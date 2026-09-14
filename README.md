# VAC Bypass CS2 — Memory Module

External memory access library for Counter-Strike 2 that avoids the detection
vectors VAC uses against traditional external cheats.

> ⚠️ **Educational purposes only.** Using this against live CS2 servers will
> result in a permanent VAC ban. Don't.

---

## What This Is

This is the memory layer only — no aimbot, no ESP, no overlay. It provides:

- `Memory::Init()` — attaches to `cs2.exe`, resolves `client.dll` + `engine2.dll`
- `Memory::Read<T>()` / `Write<T>()` — typed read/write through NT syscalls
- `Memory::ReadRaw()` / `ReadString()` / `ReadWString()`
- `Memory::ResolvePointer()` — offset chain resolver
- `Memory::GetModuleBase()` — PEB module walking

Drop it into any CS2 external project and replace your existing memory calls.

---

## How VAC Detects External Cheats

VAC’s user-mode detection relies on three primary mechanisms against external
cheats:

### 1. Handle Scanning

VAC repeatedly calls `NtQuerySystemInformation` with
`SystemHandleInformation` (class `0x10`) to enumerate every open handle in the
system[reference:0]. When it finds a handle pointing to `cs2.exe` (or `csgo.exe`),
it resolves the owning process via `NtQueryInformationProcess` with
`ProcessImageFileName` and flags the process for analysis[reference:1].

This is the **primary** detection vector for external cheats. A naive cheat
calls `OpenProcess(PROCESS_VM_READ, FALSE, cs2_pid)`, which creates an entry in
the system handle table visible to VAC[reference:2].

### 2. User-Mode API Hooking

VAC loads a module that hooks `ntdll.dll` exports, including
`NtReadVirtualMemory`, `NtWriteVirtualMemory`, `NtOpenProcess`, and
`NtQuerySystemInformation`[reference:3]. Any call to these functions from a
process VAC is monitoring can be intercepted, inspected, and the caller’s
return address checked.

### 3. Module List Inspection

VAC can query a process’s loaded modules via `EnumProcessModules` or by reading
its PEB `Ldr` list. If your cheat `.exe` or `.dll` is loaded into a monitored
process, or if your process’s module list contains known-bad entries, it’s
flagged.

---

## How This Library Bypasses Those

### 1. Handle Hijacking (vs. Handle Scanning)

Instead of calling `OpenProcess` on `cs2.exe` — which creates a detectable
handle entry — this library:

1. Enables `SeDebugPrivilege` on its own token.
2. Calls `NtQuerySystemInformation(SystemHandleInformation)` to enumerate every
   handle in the system.
3. Filters to handles owned by a short list of trusted, long-lived processes:
   `steam.exe`, `explorer.exe`, `svchost.exe`, `dwm.exe`, `csrss.exe`,
   `nvcontainer.exe`, `audiodg.exe`, `steamservice.exe`.
4. Duplicates each candidate with `NtDuplicateObject(DUPLICATE_SAME_ACCESS)`.
5. Confirms the duplicated handle points at `cs2.exe` via
   `NtQueryInformationProcess(ProcessBasicInformation)`.
6. Keeps the first match and uses it for all subsequent reads/writes.

**What this changes:** the handle in the system handle table now belongs to
`steam.exe`, not to your cheat process. When VAC scans handles, it sees Steam’s
legitimate handle to the game — not yours. Handle hijacking is a known,
documented bypass for anti-cheats that rely on user-mode handle enumeration[reference:4].

**Caveat:** VAC can still detect that a handle was duplicated into your process
if it correlates `NtDuplicateObject` calls. As of CS2, this is reported as
“detected but not bannable” — the handle exists, but VAC does not act on it
alone[reference:5].

### 2. Indirect NT Syscalls (vs. API Hooking)

All memory operations go through indirect syscall stubs resolved from
`ntdll.dll`, not through the exported `NtReadVirtualMemory` /
`NtWriteVirtualMemory` wrappers directly.

**How it works:**

1. `Protection.cpp` locates the syscall stub inside `ntdll.dll` by scanning
   `ntdll`’s export table for the pattern `4C 8B D1 B8` (the standard x64
   syscall prologue: `mov r10, rcx; mov eax, <SSN>`).
2. It saves the address of that instruction sequence.
3. When `Memory::Read<T>()` runs, it calls the stub address directly — the
   `syscall` instruction executes from **inside** `ntdll.dll`’s address space,
   not from injected or allocated memory.

**Why this matters:** VAC hooks the first bytes of `NtReadVirtualMemory` in
`ntdll.dll` to intercept calls[reference:6]. If your cheat calls the exported
function, the hook fires. By resolving the syscall stub **after** the hook (or
by scanning for the `syscall` instruction directly), you bypass the hook
entirely. Indirect syscalls are specifically designed to defeat user-land
`ntdll` hooks[reference:7].

**Secondary benefit:** RIP spoofing. The return address of the `syscall`
instruction resides inside `ntdll.dll`’s legitimate code region. Even if VAC
uses kernel-level ETW or callbacks to inspect the return address, it sees a
valid `ntdll` address — not your cheat’s `.text` section[reference:8].

### 3. PEB Module Walking (vs. Module List Inspection)

`Memory::GetModuleBase()` does **not** call `EnumProcessModules`,
`GetModuleHandle`, or `GetModuleInformation`. Instead it:

1. Reads the target’s PEB via `NtQueryInformationProcess(ProcessBasicInformation)`.
2. Reads `PEB->Ldr` (`PEB_LDR_DATA`).
3. Walks the `InMemoryOrderModuleList` doubly-linked list.
4. Reads each entry’s `BaseDllName` (`UNICODE_STRING`) and `DllBase`.
5. Compares the name against `client.dll` / `engine2.dll` case-insensitively.

**Why this matters:** `EnumProcessModules` on the target process requires a
handle and generates a detectable API call. PEB walking reads the same data
through memory reads only — no API call, no handle, no ETW event. This is a
standard evasion technique used by malware and red-teams to avoid
`GetModuleHandle` / `GetProcAddress` detection[reference:9].

### 4. String Obfuscation

Every string literal that VAC signatures might match on is XOR-obfuscated with
`0xAA` at compile time and decrypted at runtime:

- `cs2.exe` → obfuscated
- `client.dll` → obfuscated
- `engine2.dll` → obfuscated
- `ntdll.dll` → obfuscated
- `NtReadVirtualMemory`, `NtWriteVirtualMemory`, etc. → resolved from stubs,
  never string-referenced
- `SeDebugPrivilege` → obfuscated
- Trusted process names (`steam.exe`, `explorer.exe`, etc.) → obfuscated

A static scan of the cheat binary will not find these strings. Only in-memory
decryption exposes them, and the decrypted strings exist only for the duration
of the call.

### 5. No Direct OpenProcess

The only path that calls `NtOpenProcess` on `cs2.exe` is the **fallback**
branch in `Memory::Init()`. If handle hijacking succeeds (the common case), the
process never opens a new handle to the game. No `OpenProcess` = no new handle
in the system handle table = nothing for VAC’s handle scanner to flag on **your
process**.

---

## What This Library Does **Not** Do

| Limitation | Why |
|------------|-----|
| No kernel-mode driver | Ring-3 only. VAC kernel components can still inspect ring-0 state. |
| No DMA hardware | PCIe DMA cards bypass OS entirely; this library does not. |
| No manual mapping | The cheat `.exe` itself is a normal process, not injected. |
| No VAC module unhooking | If VAC already hooked `ntdll` before `Init()`, indirect syscalls still work, but the *cheat’s own process* is still visible. |
| No protection against behavioral analysis | VAC’s server-side (VACnet) analyzes gameplay patterns regardless of memory access. |
| No protection against VAC Live | CS2’s live detection can flag suspicious mid-match behavior independent of memory technique. |

---

## Detection Status (Community Reports)

As of CS2 (2023–2025):

- **Handle hijacking** is detected by VAC’s handle scanner but **does not
  result in a ban** on its own. VAC sees the duplicated handle, resolves the
  owning process, but does not act on it[reference:10].
- **Indirect syscalls** bypass user-mode `ntdll` hooks. VAC has no known
  user-mode counter for indirect syscall execution that stays within `ntdll`’s
  address space.
- **PEB walking** is not detected by VAC’s module scanner because no
  `EnumProcessModules` call is made.
- **String obfuscation** defeats static signature scanning of the cheat binary.

The combination — hijack + indirect syscalls + PEB walk — removes the three
most common detection vectors for external cheats: handle creation, API call
interception, and module enumeration.

---

## Usage

```cpp
#include "Memory/Memory.hpp"

// Attach
if (!mem.Init()) return 1;  // defaults to L"cs2.exe"

// Read
uintptr_t localPawn = mem.Read<uintptr_t>(
    mem.client + offsets::client_dll::dwLocalPlayerPawn
);
int health = mem.Read<int>(localPawn + offsets::C_BaseEntity::m_iHealth);

// Write
mem.Write<int>(localPawn + offsets::C_BaseEntity::m_iHealth, 100);

// Offset chain
uintptr_t entity = mem.ResolvePointer(mem.client, { 0x2577BE0, 0x10, 0x8 });

// Extra modules
uintptr_t tier0 = mem.GetModuleBase(L"tier0.dll");

// Cleanup
mem.Cleanup();  // also runs in destructor
