#pragma once
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "../Protection/Protection.h"

// External memory interface for CS2 (cs2.exe).
// Resolves client.dll + engine2.dll bases on Init.
class Memory {
public:
    uint32_t  pid    = 0;
    HANDLE    handle = nullptr;
    uintptr_t client = 0;   // base of client.dll
    uintptr_t engine = 0;   // base of engine2.dll

    // Attach to cs2.exe and resolve both module bases.
    bool Init(const wchar_t* processName = L"cs2.exe");

    void Cleanup();
    ~Memory() { Cleanup(); }

    // Typed read from cs2.exe memory (uses NtReadVirtualMemory stub).
    template <typename T>
    T Read(uintptr_t address) const {
        T buffer{};
        if (!address || !handle) return buffer;
        auto fn = GetNtReadVirtualMemoryStub(); // indirect syscall, avoids ntdll hooks
        if (!fn) return buffer;
        SIZE_T bytesRead = 0;
        fn(handle, (PVOID)address, &buffer, sizeof(T), &bytesRead);
        return buffer;
    }

    // Read arbitrary byte count (arrays, variable-size structs).
    bool ReadRaw(uintptr_t address, void* buffer, size_t size) const;

    // Typed write to cs2.exe memory; skips if the value is already equal.
    template <typename T>
    bool Write(uintptr_t address, T value) const {
        if (!address || !handle) return false;
        T currentValue = Read<T>(address);
        if (std::memcmp(&currentValue, &value, sizeof(T)) == 0) return true; // no-op if identical
        auto fn = GetNtWriteVirtualMemoryStub();
        if (!fn) return false;
        SIZE_T bytesWritten = 0;
        NTSTATUS status = fn(handle, (PVOID)address, &value, sizeof(T), &bytesWritten);
        return NT_SUCCESS(status) && bytesWritten == sizeof(T);
    }

    // Read a null-terminated ASCII / wide string from cs2.exe.
    std::string  ReadString (uintptr_t address, size_t maxLen = 64) const;
    std::wstring ReadWString(uintptr_t address, size_t maxLen = 64) const;

    // Follow a pointer chain: base -> [base+o0] -> [..+o1] -> ... + last.
    uintptr_t ResolvePointer(uintptr_t base, const std::vector<uintptr_t>& offsets) const;

    // Resolve any loaded module base (e.g. "tier0.dll", "materialsystem2.dll").
    uintptr_t GetModuleBase(const wchar_t* moduleName) const;

private:
    uint32_t     GetProcessId(const wchar_t* processName) const;
    HANDLE       TryHijackHandle(DWORD targetPid);
    bool         IsTrustedSourceProcess(DWORD pid);
    std::wstring GetProcessNameByPid(DWORD pid);
};

extern Memory mem;