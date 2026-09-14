#include "Memory.hpp"
#include <winternl.h>
#include <psapi.h>
#include <algorithm>

#pragma comment(lib, "ntdll.lib")

// ---- Static helpers ---------------------------------------------------------

// Fallback: open a fresh handle via NtOpenProcess if hijacking fails.
static HANDLE OpenGameProcess(DWORD pid) {
    auto NtOpenProcess = GetNtOpenProcessStub(); // syscall stub, not kernel32
    if (!NtOpenProcess) return nullptr;
    HANDLE hProcess = nullptr;
    OBJECT_ATTRIBUTES oa = { sizeof(OBJECT_ATTRIBUTES) };
    CLIENT_ID cid = { (HANDLE)(uintptr_t)pid, nullptr };
    NTSTATUS status = NtOpenProcess(
        &hProcess,
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, // full VM access on cs2.exe
        &oa, &cid
    );
    return NT_SUCCESS(status) ? hProcess : nullptr;
}

// Read N bytes from cs2.exe with a full-read check.
static bool ReadRemoteBuffer(HANDLE hProcess, uintptr_t address, void* buffer, SIZE_T size) {
    auto NtRead = GetNtReadVirtualMemoryStub();
    if (!NtRead) return false;
    SIZE_T bytesRead = 0;
    NTSTATUS status = NtRead(hProcess, (PVOID)address, buffer, size, &bytesRead);
    return NT_SUCCESS(status) && bytesRead == size;
}

// ---- Process discovery ------------------------------------------------------

// Get just the image name for a PID (e.g. "cs2.exe", "steam.exe").
std::wstring Memory::GetProcessNameByPid(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return L"";
    WCHAR name[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(hProc, 0, name, &size)) {
        std::wstring full(name);
        size_t pos = full.find_last_of(L'\\');
        if (pos != std::wstring::npos) full = full.substr(pos + 1); // strip directory
        CloseHandle(hProc);
        return full;
    }
    CloseHandle(hProc);
    return L"";
}

// Long-lived processes that usually hold a handle to cs2.exe.
bool Memory::IsTrustedSourceProcess(DWORD pid) {
    std::wstring name = GetProcessNameByPid(pid);
    if (name.empty()) return false;
    std::transform(name.begin(), name.end(), name.begin(), ::towlower); // lower for compare
    static const wchar_t* trusted[] = {
        OBFUSCATE_W(L"steam.exe"),
        OBFUSCATE_W(L"steamservice.exe"),
        OBFUSCATE_W(L"explorer.exe"),
        OBFUSCATE_W(L"dwm.exe"),
        OBFUSCATE_W(L"csrss.exe"),
        OBFUSCATE_W(L"svchost.exe"),
        OBFUSCATE_W(L"nvcontainer.exe"),
        OBFUSCATE_W(L"audiodg.exe")
    };
    for (const auto& t : trusted) if (name == t) return true;
    return false;
}

// Scan the global handle table for a handle to cs2.exe owned by a trusted
// process (usually Steam), then duplicate it into our own process.
HANDLE Memory::TryHijackHandle(DWORD targetPid) {
    auto NtQuerySystemInfo = GetNtQuerySystemInformationStub();
    auto NtDuplicate       = GetNtDuplicateObjectStub();
    if (!NtQuerySystemInfo || !NtDuplicate) return nullptr;

    // Enable SeDebugPrivilege so we can open any process.
    HANDLE hToken = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp = {};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValueW(nullptr, OBFUSCATE_W(L"SeDebugPrivilege"), &tp.Privileges[0].Luid))
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(hToken);
    }

    // Query SystemHandleInformation (0x10), grow buffer on STATUS_INFO_LENGTH_MISMATCH.
    ULONG bufferSize = 0x100000;
    std::vector<BYTE> buffer(bufferSize);
    ULONG returnLen = 0;
    NTSTATUS status = NtQuerySystemInfo((SYSTEM_INFORMATION_CLASS)0x10,
                                        buffer.data(), bufferSize, &returnLen);
    while (status == (NTSTATUS)0xC0000004L) {
        bufferSize = returnLen + 0x1000;
        buffer.resize(bufferSize);
        status = NtQuerySystemInfo((SYSTEM_INFORMATION_CLASS)0x10,
                                   buffer.data(), bufferSize, &returnLen);
    }
    if (!NT_SUCCESS(status)) return nullptr;

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
        USHORT UniqueProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR  ObjectTypeIndex;
        UCHAR  HandleAttributes;
        USHORT HandleValue;
        PVOID  Object;
        ULONG  GrantedAccess;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

    typedef struct _SYSTEM_HANDLE_INFORMATION {
        ULONG NumberOfHandles;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
    } SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

    auto* handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer.data();
    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        auto& entry = handleInfo->Handles[i];
        if (entry.HandleValue == 0) continue;
        DWORD sourcePid = entry.UniqueProcessId;
        if (!IsTrustedSourceProcess(sourcePid)) continue; // only from trusted owners

        HANDLE hSourceProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, sourcePid);
        if (!hSourceProc) continue;

        HANDLE hDup = nullptr;
        NTSTATUS dupStatus = NtDuplicate(
            hSourceProc, (HANDLE)(uintptr_t)entry.HandleValue,
            GetCurrentProcess(), &hDup, 0, 0, DUPLICATE_SAME_ACCESS
        );
        CloseHandle(hSourceProc);
        if (!NT_SUCCESS(dupStatus) || !hDup) continue;

        // Confirm the duplicated handle really points at cs2.exe.
        auto NtQueryInfo = GetNtQueryInformationProcessStub();
        if (NtQueryInfo) {
            PROCESS_BASIC_INFORMATION pbi = {};
            ULONG ret = 0;
            if (NT_SUCCESS(NtQueryInfo(hDup, ProcessBasicInformation, &pbi, sizeof(pbi), &ret))
                && (DWORD)pbi.UniqueProcessId == targetPid) {
                HANDLE hFinal = nullptr;
                NTSTATUS finalStatus = NtDuplicate(
                    GetCurrentProcess(), hDup, GetCurrentProcess(), &hFinal,
                    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                    0, 0
                );
                CloseHandle(hDup);
                if (NT_SUCCESS(finalStatus) && hFinal) return hFinal; // usable handle
            }
        }
        CloseHandle(hDup);
    }
    return nullptr;
}

// Walk SystemProcessInformation to find cs2.exe's PID.
uint32_t Memory::GetProcessId(const wchar_t* processName) const {
    auto NtQuerySystemInfo = GetNtQuerySystemInformationStub();
    if (!NtQuerySystemInfo) return 0;
    ULONG bufferSize = 0x10000;
    std::vector<BYTE> buffer(bufferSize);
    NTSTATUS status;
    while ((status = NtQuerySystemInfo(SystemProcessInformation, buffer.data(),
                                       bufferSize, &bufferSize))
           == (NTSTATUS)0xC0000004L) {
        buffer.resize(bufferSize);
    }
    if (!NT_SUCCESS(status)) return 0;

    typedef struct _MY_SYSTEM_PROCESS_INFORMATION {
        ULONG          NextEntryOffset;
        ULONG          NumberOfThreads;
        LARGE_INTEGER  SpareLi1, SpareLi2, SpareLi3;
        LARGE_INTEGER  CreateTime, UserTime, KernelTime;
        UNICODE_STRING ImageName;
        ULONG          BasePriority;
        HANDLE         UniqueProcessId;
        HANDLE         InheritedFromUniqueProcessId;
        ULONG          HandleCount;
        ULONG          SessionId;
        ULONG_PTR      UniqueProcessKey;
        SIZE_T         PeakVirtualSize, VirtualSize;
        ULONG          PageFaultCount;
        SIZE_T         PeakWorkingSetSize, WorkingSetSize;
        SIZE_T         QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage;
        SIZE_T         QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage;
        SIZE_T         PagefileUsage, PeakPagefileUsage, PrivatePageCount;
        LARGE_INTEGER  ReadOperationCount, WriteOperationCount, OtherOperationCount;
        LARGE_INTEGER  ReadTransferCount, WriteTransferCount, OtherTransferCount;
    } MY_SYSTEM_PROCESS_INFORMATION, * PMY_SYSTEM_PROCESS_INFORMATION;

    auto* entry = (MY_SYSTEM_PROCESS_INFORMATION*)buffer.data();
    for (;;) {
        if (entry->ImageName.Buffer &&
            _wcsicmp(entry->ImageName.Buffer, processName) == 0) {
            return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(entry->UniqueProcessId));
        }
        if (!entry->NextEntryOffset) break;
        entry = (MY_SYSTEM_PROCESS_INFORMATION*)((BYTE*)entry + entry->NextEntryOffset);
    }
    return 0;
}

// ---- Module resolution (PEB walk) -------------------------------------------

typedef struct _LDR_DATA_TABLE_ENTRY_FULL {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY_FULL, * PLDR_DATA_TABLE_ENTRY_FULL;

// Resolve a module base by reading cs2.exe's PEB Ldr list.
uintptr_t Memory::GetModuleBase(const wchar_t* moduleName) const {
    if (!handle) return 0;
    auto NtQueryInfo = GetNtQueryInformationProcessStub();
    if (!NtQueryInfo) return 0;

    // PEB -> Ldr -> InMemoryOrderModuleList.
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returnLength = 0;
    if (!NT_SUCCESS(NtQueryInfo(handle, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength))
        || !pbi.PebBaseAddress) return 0;

    PEB peb{};
    if (!ReadRemoteBuffer(handle, (uintptr_t)pbi.PebBaseAddress, &peb, sizeof(peb))) return 0;
    if (!peb.Ldr) return 0;

    PEB_LDR_DATA ldr{};
    if (!ReadRemoteBuffer(handle, (uintptr_t)peb.Ldr, &ldr, sizeof(ldr))) return 0;

    uintptr_t headAddr    = (uintptr_t)peb.Ldr + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);
    uintptr_t currentAddr = (uintptr_t)ldr.InMemoryOrderModuleList.Flink;

    while (currentAddr && currentAddr != headAddr) {
        uintptr_t entryBase = currentAddr - offsetof(LDR_DATA_TABLE_ENTRY_FULL, InMemoryOrderLinks);
        LDR_DATA_TABLE_ENTRY_FULL entry{};
        if (!ReadRemoteBuffer(handle, entryBase, &entry, sizeof(entry))) break;

        if (entry.BaseDllName.Buffer && entry.BaseDllName.Length > 0) {
            WCHAR nameBuffer[MAX_PATH]{};
            SIZE_T nameSize = (std::min)(
                (SIZE_T)entry.BaseDllName.Length,
                (SIZE_T)(MAX_PATH - 1) * sizeof(WCHAR));
            if (ReadRemoteBuffer(handle, (uintptr_t)entry.BaseDllName.Buffer, nameBuffer, nameSize)) {
                if (_wcsicmp(nameBuffer, moduleName) == 0)
                    return (uintptr_t)entry.DllBase; // found client.dll / engine2.dll / etc.
            }
        }
        currentAddr = (uintptr_t)entry.InMemoryOrderLinks.Flink;
    }
    return 0;
}

// ---- Public API -------------------------------------------------------------

bool Memory::ReadRaw(uintptr_t address, void* buffer, size_t size) const {
    if (!address || !buffer || !handle) return false;
    auto NtRead = GetNtReadVirtualMemoryStub();
    if (!NtRead) return false;
    SIZE_T bytesRead = 0;
    NTSTATUS status = NtRead(handle, (PVOID)address, buffer, size, &bytesRead);
    return NT_SUCCESS(status) && bytesRead == size;
}

std::string Memory::ReadString(uintptr_t address, size_t maxLen) const {
    if (!address) return {};
    char buf[256]{};
    size_t n = (std::min)(maxLen, sizeof(buf) - 1);
    if (!ReadRaw(address, buf, n)) return {};
    buf[n] = '\0';
    return std::string(buf);
}

std::wstring Memory::ReadWString(uintptr_t address, size_t maxLen) const {
    if (!address) return {};
    wchar_t buf[256]{};
    size_t n = (std::min)(maxLen, sizeof(buf) / sizeof(wchar_t) - 1);
    if (!ReadRaw(address, buf, n * sizeof(wchar_t))) return {};
    buf[n] = L'\0';
    return std::wstring(buf);
}

uintptr_t Memory::ResolvePointer(uintptr_t base, const std::vector<uintptr_t>& offsets) const {
    uintptr_t addr = base;
    for (size_t i = 0; i < offsets.size(); ++i) {
        if (i + 1 == offsets.size()) return addr + offsets[i]; // last offset is added, not dereferenced
        addr = Read<uintptr_t>(addr + offsets[i]);
        if (!addr) return 0;
    }
    return addr;
}

void Memory::Cleanup() {
    if (handle) {
        typedef NTSTATUS(NTAPI* pNtClose)(HANDLE);
        auto NtClose = (pNtClose)GetProcAddress(
            GetModuleHandleA(OBFUSCATE("ntdll.dll")), OBFUSCATE("NtClose"));
        if (NtClose) NtClose(handle); // close via NtClose, not CloseHandle
        handle = nullptr;
    }
    pid = 0; client = 0; engine = 0;
}

// Attach to cs2.exe, hijack a handle, resolve client.dll + engine2.dll.
bool Memory::Init(const wchar_t* processName) {
    pid = GetProcessId(processName);
    if (!pid) {
        MessageBoxA(NULL, "Game process not found.", "ERROR (1)", MB_OK | MB_ICONERROR);
        return false;
    }

    // Prefer hijacking Steam's handle over opening cs2.exe directly.
    handle = TryHijackHandle(pid);
    if (!handle) {
        handle = OpenGameProcess(pid); // fallback: direct NtOpenProcess
        if (!handle) {
            MessageBoxA(NULL, "Failed to open a handle to cs2.exe.", "ERROR (2)", MB_OK | MB_ICONERROR);
            return false;
        }
    }

    client = GetModuleBase(OBFUSCATE_W(L"client.dll")); // resolves to client.dll base
    engine = GetModuleBase(OBFUSCATE_W(L"engine2.dll")); // resolves to engine2.dll base

    if (!client || !engine) {
        MessageBoxA(NULL, "Failed to resolve client.dll or engine2.dll.", "ERROR (3)", MB_OK | MB_ICONERROR);
        Cleanup();
        return false;
    }
    return true;
}

Memory mem;