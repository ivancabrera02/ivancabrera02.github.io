---
title: "Using ETW for Offensive Security"
categories:
  - Blog
tags:
  - Windows
  - Red Team
---

## Table of Contents

1. [Introduction](#introduction)
2. [ETW Architecture and Internals](#etw-architecture-and-internals)
   - [The Three Pillars: Providers, Controllers, Consumers](#the-three-pillars-providers-controllers-consumers)
   - [How Events Flow Through the Kernel](#how-events-flow-through-the-kernel)
   - [Manifest-Based vs. TraceLogging Providers](#manifest-based-vs-tracelogging-providers)
   - [ETW Buffers and Sessions](#etw-buffers-and-sessions)
   - [The NT Kernel Logger and Circular Kernel Context Logger](#the-nt-kernel-logger-and-circular-kernel-context-logger)
3. [Enumerating and Working with Providers](#enumerating-and-working-with-providers)
   - [Listing Providers on a Live System](#listing-providers-on-a-live-system)
   - [Decoding Provider Schemas](#decoding-provider-schemas)
   - [Subscribing to a Provider Programmatically](#subscribing-to-a-provider-programmatically)
4. [Offensive Uses of ETW](#offensive-uses-of-etw)
   - [SMB Provider: Capturing NTLMv2 Hashes](#smb-provider-capturing-ntlmv2-hashes)
   - [PowerShell ETW: Script Block Logging Internals](#powershell-etw-script-block-logging-internals)
   - [WMI Provider: Persistence and Lateral Movement Awareness](#wmi-provider-persistence-and-lateral-movement-awareness)
   - [Process and Thread Providers: Injection Detection and Evasion](#process-and-thread-providers-injection-detection-and-evasion)
   - [.NET CLR Provider: Detecting Managed Code Execution](#net-clr-provider-detecting-managed-code-execution)
   - [Security Auditing Provider: Real-Time Log Monitoring](#security-auditing-provider-real-time-log-monitoring)
5. [ETW Bypass Timeline: A History of Evasion](#etw-bypass-timeline-a-history-of-evasion)
   - [User-Mode Bypasses](#user-mode-bypasses)
   - [Kernel-Mode Bypasses](#kernel-mode-bypasses)
6. [Detecting ETW Tampering](#detecting-etw-tampering)
7. [Defensive Recommendations](#defensive-recommendations)
8. [Conclusion](#conclusion)

---

## Introduction

Event Tracing for Windows (ETW) is one of the most powerful and least understood subsystems in the entire Windows operating system. Originally designed as a high-performance logging and diagnostics framework, ETW has quietly become one of the primary telemetry sources that every modern EDR (Endpoint Detection and Response) product depends on. It is the backbone behind Windows Defender, Microsoft Defender for Endpoint, Sysmon's kernel callbacks, and countless third-party security tools.

For a red teamer or penetration tester, ETW is a double-edged sword. On one hand, it is the mechanism that will get your implant detected, your lateral movement flagged, and your persistence mechanisms burned. On the other hand, understanding ETW deeply allows you to consume its telemetry offensively capturing credential material, mapping network activity, and understanding exactly what defenders can and cannot see.

This post covers ETW from the ground up: how it works internally at both the user and kernel level, which providers are interesting from an offensive standpoint, how to consume events programmatically, and a detailed timeline of every significant ETW bypass technique that has been publicly disclosed from patching `EtwEventWrite` in user space to manipulating kernel data structures directly.

---

## ETW Architecture and Internals

### The Three Pillars: Providers, Controllers, Consumers

ETW is built around three distinct roles that interact with the tracing infrastructure:

**Providers** are software components: DLLs, executables, drivers that instrument their code to emit events. A provider registers itself with the ETW subsystem through `EtwRegister` (user mode) or `EtwRegisterProvider` equivalents in kernel mode, and is assigned a globally unique identifier (GUID) at registration time. Every provider publishes events using one of two primary mechanisms: classic (MOF-based) providers or modern manifest-based providers.

**Controllers** are responsible for creating and managing *trace sessions*. A trace session is essentially an in-memory ring buffer that collects events from one or more providers. The controller uses the `StartTrace`, `EnableTrace`, `ControlTrace`, and `StopTrace` APIs (all wrapping `NtTraceControl` in ntdll.dll) to manage sessions. When a controller enables a provider for a session, it specifies a *level* (verbosity from 1-Critical to 5-Verbose) and a *keyword mask*, which acts as a bitmask filter allowing the controller to subscribe to only certain categories of events from that provider.

**Consumers** are processes that read the event data. They can either read from a live session in real time using `OpenTrace` and `ProcessTrace`, or read from a log file (`.etl`) after the fact. The consumer registers an `EVENT_RECORD_CALLBACK` function that is invoked for each matching event.

![etw](/assets/images/etwarchitecture.png)

### How Events Flow Through the Kernel

Understanding the event flow path is critical to understanding both why ETW is trusted by security tools and where it can be tampered with.

When a provider calls `EtwEventWrite` in user mode, execution flows as follows:

1. **`EtwEventWrite` (ntdll.dll)** — The call enters ntdll's ETW implementation. Here the event is assembled into an `EVENT_DESCRIPTOR` structure that carries the event ID, level, channel, opcode, task, and keyword fields.

2. **Registration handle check** — The registration handle (obtained at `EtwRegister` time) is checked. This handle encodes whether the provider is currently *enabled* for any active session. If no session is listening, the function returns immediately — this is the fast path and has negligible overhead.

3. **`EtwpEventWriteFull` / `NtTraceEvent` syscall** — If at least one session has enabled this provider, the event data is prepared and a syscall is issued to the kernel via `NtTraceEvent`.

4. **Kernel-side: `EtwpWriteUserEvent` (ntoskrnl.exe)** — The kernel receives the event, validates the caller, and writes the event data into the in-kernel buffer associated with the trace session.

5. **Buffer flushing** — Kernel buffers are flushed either on a timer (configurable) or when full, and the data is made available to the consumer. For real-time sessions, this involves writing into a shared memory region that the consuming process can read.

The key insight here is that **the actual event commit happens in kernel space**. User-mode providers cannot unilaterally suppress events once the kernel has decided to log them — unless they prevent the syscall from ever being issued. This is the fundamental tension that drives all user-mode ETW bypass techniques: they must intercept the call *before* it reaches the kernel.

### Manifest-Based vs. TraceLogging Providers

Modern Windows ETW providers come in two flavors:

**Manifest-based providers** register an XML manifest with the system (installed via `wevtutil im` or `logman`). The manifest describes every event the provider can emit, including field names and types, enabling consumers and tools to decode events into human-readable form. The schema is stored in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}`. These are the providers you enumerate with `logman query providers` or the `TdhEnumerateProviders` API.

**TraceLogging providers** are newer and use a self-describing format, each event carries its own schema inline. This means no manifest registration is required. TraceLogging is heavily used by Windows components and first-party Microsoft software (Edge, the Xbox Gaming Services, telemetry components). These providers often appear in enumeration without human-readable names, showing only their GUID.

**WPP (Windows Software Trace Preprocessor)** providers are a legacy format, predating manifest-based providers, heavily used in kernel drivers. WPP events require a separate PDB or TMF file to decode, making them more opaque to analysts but still capturable.

### ETW Buffers and Sessions

ETW sessions have a well-defined structure in kernel memory. The primary kernel object is `_ETW_LOGGER_CONTEXT`, which contains:

- **Buffer array** — A pool of `_ETW_BUFFER` structures, each typically 64 KB by default (configurable up to 1 MB).
- **Buffer list** — A doubly-linked list distinguishing full buffers (ready to flush), free buffers, and the current buffer being written to.
- **Session GUID and name** — Used to identify the session. The "NT Kernel Logger" session has a fixed GUID of `{9E814AAD-3204-11D2-9A82-006008A86939}`.
- **Enable flags and keywords** — Bitmask fields that control which providers and event categories feed into this session.

The maximum number of simultaneous ETW sessions on a standard system is **64 for standard (non-private) sessions** (`MAXLOGGERS`), though this was raised to 128 in newer Windows versions. Private sessions (used by process-local logging) have separate limits.

From a red team perspective, the session limit has historically been exploited: if all session slots are exhausted, new sessions cannot be created, effectively preventing EDR tools from establishing their ETW feeds at startup. This was a short-lived but real denial-of-service vector against ETW-based detection.

### The NT Kernel Logger and Circular Kernel Context Logger

Two sessions deserve special mention:

The **NT Kernel Logger** (`{9E814AAD-3204-11D2-9A82-006008A86939}`) is the primary kernel tracing session, capturing events from `Microsoft-Windows-Kernel-Process`, `Microsoft-Windows-Kernel-File`, `Microsoft-Windows-Kernel-Network`, and related providers. It is the source of process creation, image load, file I/O, and network events, the bread and butter of EDR telemetry.

The **Circular Kernel Context Logger (CKCL)** is a special session that runs in kernel mode, with its buffers stored in non-paged pool. It is used internally by Windows and also feeds the ETW consumer architecture. Importantly, the CKCL is used by `WdBoot.sys` (Windows Defender's boot driver) to receive early boot telemetry before the full ETW stack is running.

---

## Enumerating and Working with Providers

### Listing Providers on a Live System

The quickest way to enumerate registered ETW providers on a live system is `logman`:

```cmd
logman query providers
```

![logman](/assets/images/logman.png)

This queries `TdhEnumerateProviders` under the hood and lists every provider that has a registered manifest. For a more complete view including unregistered/TraceLogging providers currently active in running processes, you can use:

```powershell
# List all providers registered in the registry
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers" |
    ForEach-Object {
        [PSCustomObject]@{
            Name = $_.GetValue("(default)")
            GUID = $_.PSChildName
        }
    }
```

For a more powerful approach, the `EtwExplorer` tool by Pavel Yosifovich provides a GUI that lets you browse provider manifests, view event schemas, and subscribe to live event streams. Similarly, `PerfView` from Microsoft exposes the full ETW consumer interface with a user-friendly front end.

Using the Windows Performance Toolkit:

```cmd
# Start a trace capturing specific providers
xperf -start MySession -on Microsoft-Windows-SMBClient:0xff:5 -f c:\trace.etl

# Stop the trace
xperf -stop MySession

# Merge and symbolize
xperf -merge c:\trace.etl c:\merged.etl
```

### Decoding Provider Schemas

Once you have a provider GUID, you can query its full event schema using the Trace Data Helper (TDH) APIs. In PowerShell, the `Microsoft.Diagnostics.Tracing.TraceEvent` NuGet package (part of `PerfView`) makes this straightforward:

```powershell
Add-Type -Path "Microsoft.Diagnostics.Tracing.TraceEvent.dll"
$session = New-Object Microsoft.Diagnostics.Tracing.Session.TraceEventSession("SchemaQuery")
$parser = New-Object Microsoft.Diagnostics.Tracing.Parsers.RegisteredTraceEventParser($session.Source)
# Enumerate events for a specific GUID...
```

For low-level C access, `TdhGetEventInformation` takes an `EVENT_RECORD` pointer and populates a `TRACE_EVENT_INFO` structure describing every field in the event.

### Subscribing to a Provider Programmatically

The following C example demonstrates the minimal code to subscribe to a provider and receive its events in real time:

```c
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")

#define SESSION_NAME L"MyOffensiveSession"

// The provider GUID - here using Microsoft-Windows-SMBClient
static const GUID SMBClientGuid = 
    { 0x988C59C5, 0x0A1C, 0x45B6, { 0xA5, 0x55, 0xF2, 0xCA, 0x89, 0x27, 0x3C, 0x41 } };

VOID WINAPI EventRecordCallback(PEVENT_RECORD pEventRecord) {
    // Process event here
    wprintf(L"Event ID: %d, Provider: \n", pEventRecord->EventHeader.EventDescriptor.Id);
}

int main() {
    TRACEHANDLE hSession = INVALID_PROCESSTRACE_HANDLE;
    
    // Allocate EVENT_TRACE_PROPERTIES
    ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(SESSION_NAME) * sizeof(WCHAR);
    PEVENT_TRACE_PROPERTIES pProps = (PEVENT_TRACE_PROPERTIES)malloc(bufSize);
    ZeroMemory(pProps, bufSize);
    
    pProps->Wnode.BufferSize   = bufSize;
    pProps->Wnode.Flags        = WNODE_FLAG_TRACED_GUID;
    pProps->LogFileMode        = EVENT_TRACE_REAL_TIME_MODE;
    pProps->LoggerNameOffset   = sizeof(EVENT_TRACE_PROPERTIES);
    
    // Start the trace session
    ULONG status = StartTraceW(&hSession, SESSION_NAME, pProps);
    
    // Enable the SMB client provider at verbose level
    ENABLE_TRACE_PARAMETERS params = { 0 };
    params.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    EnableTraceEx2(hSession, &SMBClientGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                   TRACE_LEVEL_VERBOSE, 0xFFFFFFFFFFFFFFFF, 0, 0, &params);
    
    // Open the session for real-time consumption
    EVENT_TRACE_LOGFILE logfile = { 0 };
    logfile.LoggerName          = (LPWSTR)SESSION_NAME;
    logfile.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.EventRecordCallback = EventRecordCallback;
    
    TRACEHANDLE hTrace = OpenTraceW(&logfile);
    ProcessTrace(&hTrace, 1, NULL, NULL);  // Blocking call
    
    return 0;
}
```

This pattern start a session, enable a provider, open and process the trace — is the foundation for every offensive ETW consumer tool.

---

## Offensive Uses of ETW

Now for the interesting part. ETW is not just a defensive telemetry mechanism  it is a rich source of structured, low-latency operational data that an attacker on a compromised host can consume to dramatically improve situational awareness, capture credential material, and map the environment.

The following sections detail the most interesting provider from an offensive standpoint, including the specific event IDs to target and practical attack scenarios.

### SMB Provider: Capturing NTLMv2 Hashes

> 📷 *[Insert screenshot: ETW consumer showing NTLMv2 hash material from SMB authentication events]*

**Provider:** `Microsoft-Windows-SMBClient` (`{988C59C5-0A1C-45B6-A555-F2CA89273C41}`)  
**Also relevant:** `Microsoft-Windows-SMBServer` (`{D48CE617-33A2-4BC3-A5C7-11AA8D29FFFE}`)

The SMB client provider emits detailed events covering connection setup, authentication negotiation, and file operations. From an offensive perspective, the most valuable events are those surrounding NTLM authentication — specifically, events that expose the NTLM challenge-response material transiting through an SMB connection.

When a Windows client authenticates to an SMB server using NTLM (whether real or an attacker-controlled responder), the ETW SMBClient provider fires events containing:

- The target server name and IP
- The username and domain being authenticated
- The NTLM authentication flags
- In some Windows versions, fragments of the authentication blob that include the NTLMv2 response itself

The attack scenario is compelling: on a compromised host, run an ETW consumer subscribed to the SMB client provider. Then trigger NTLM authentications — either wait for organic ones from the user (e.g., they access a network share) or force them via common techniques like SCF files, UNC path injection in Office documents, or `net use`. The ETW events will surface the authentication activity with enough metadata to correlate with and complement standard responder captures.

At a higher privilege level, subscribing to `Microsoft-Windows-SMBServer` on a host that acts as a file server can reveal every authentication attempt against it, including failed ones with partial hash material.

Key event IDs to monitor in `Microsoft-Windows-SMBClient`:

| Event ID | Description |
|----------|-------------|
| 30800 | Session setup (authentication initiation) |
| 30803 | Logon success with authentication details |
| 30804 | Logon failure (exposes username, target) |
| 40001 | Connection initiated |
| 40002 | Connection disconnected |

```powershell
# Quick PowerShell one-liner to subscribe and dump SMBClient auth events
# Requires admin rights and the ETW session privileges
$session = New-Object Microsoft.Diagnostics.Tracing.Session.TraceEventSession("SMBHarvest")
$session.EnableProvider("Microsoft-Windows-SMBClient", 
    [Microsoft.Diagnostics.Tracing.Session.TraceEventLevel]::Verbose, 
    [ulong]::MaxValue)

$source = $session.Source
$source.Dynamic.All += { param($event)
    if ($event.ID -in @(30800, 30803, 30804)) {
        Write-Host "[SMB Auth] $($event.TimeStamp) User=$($event['UserName']) Target=$($event['ServerName'])"
    }
}
$source.Process()
```

![hash](/assets/images/etw4.png)

This is a stealthy complement to traditional responder-style attacks: no new network traffic, no injected packets, just passive observation of the existing authentication stream.

**For red teamers, two implications:**

First, SBL events travel the same ETW pathway as every other event — they are subject to the same bypass techniques described in the bypass timeline section. Patching the provider-sid

### Process and Thread Providers: Injection Detection and Evasion

**Provider:** `Microsoft-Windows-Kernel-Process` (`{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}`)

The kernel process provider is enabled by nearly every EDR through the NT Kernel Logger session. It fires events for:

- Process creation and termination (EventID 1, 2)
- Thread creation and termination (EventID 3, 4) — this is critical for detecting `CreateRemoteThread`-based injection
- Image loads (EventID 5) — fires when any DLL or executable is mapped into a process
- Virtual memory allocation (EventID 14, 15) — some EDRs enable this to detect `VirtualAllocEx` cross-process allocations

From an offensive standpoint, monitoring this provider on a host tells you exactly which EDR callbacks are active. If you see image load events being fired for `CrowdStrikeFalcon.sys`, you know the kernel component is present. If thread creation events are firing for `MsMpEng.exe` spin-up routines, Defender is active and scanning.

More practically: subscribing to the process provider gives you a live process tree of the host. Combined with image load events, you can reconstruct exactly what defensive tools are loaded in what processes without making a single `OpenProcess` call — a much lower-noise reconnaissance method.

### .NET CLR Provider: Detecting Managed Code Execution

**Provider:** `Microsoft-Windows-DotNETRuntime` (`{E13C0D23-CCBC-4E12-931B-D9CC2EEE27E4}`)

The .NET CLR runtime emits detailed ETW events covering:

- Method JIT compilation (EventID 141, 143) — fires when a .NET method is compiled to native code for the first time
- Assembly loads (EventID 154, 155)
- Exception events (EventID 250)
- GC activity

For offensive security, this provider reveals **in-memory .NET assembly execution**. Techniques like `Assembly.Load(byte[])` used by tools like `execute-assembly` in Cobalt Strike will fire CLR assembly load events (EventID 154) even when the assembly is loaded entirely from memory and never touches disk. This is precisely why EDRs subscribe to this provider — it catches reflective .NET loading.

Understanding this: if you're using in-memory .NET execution, the CLR provider will fire assembly load events with the `AssemblyName` and `FullyQualifiedAssemblyName` fields. Unsigned assemblies or assemblies with suspicious names (especially those matching known offensive tools) create detection opportunities.

Defensive tools can cross-reference CLR assembly load events against their allowlist of expected .NET assemblies on a given host. A `SharpHound` assembly loading in a `powershell.exe` process is anomalous; the same event in `SharePoint.exe` is expected.

### Security Auditing Provider: Real-Time Log Monitoring

**Provider:** `Microsoft-Windows-Security-Auditing` (`{54849625-5478-4994-A5BA-3E3B0328C30D}`)

This provider is the direct source for Windows Security event log entries — every `4624` (logon), `4625` (failed logon), `4688` (process creation with audit enabled), `4698` (scheduled task creation), and so on originates here as an ETW event before being written to the Security event log.

The crucial point: **ETW events arrive before the event log is written**. An attacker with an ETW consumer subscribed to this provider receives authentication events, process creation events, and privilege use events in real time with lower latency than reading from the event log itself.

This is useful for:

- **Credential harvesting timing:** Detect when a high-value user authenticates to the machine (4624 with their username) and time a credential dump to that window.
- **Operator awareness:** Detect when incident responders log on (new logon events for unknown users) or when new scheduled tasks are created (4698) — potentially indicating defensive automation being deployed against you.
- **Kerberos ticket events:** Events 4769 (Kerberoastable service ticket requests) and 4771 (Kerberos pre-auth failures) appear here in real time, giving you visibility into whether your Kerberoasting activity is generating noise.

---

## ETW Bypass Timeline: A History of Evasion

One of the most fascinating aspects of ETW's security history is the arms race between researchers finding bypass techniques and Microsoft hardening the infrastructure. What follows is a comprehensive timeline of publicly disclosed ETW bypass methods, categorized by whether they operate in user mode or kernel mode.

---

### User-Mode Bypasses

#### 2013–2014 — The GUID Deregistration Era

The earliest ETW bypass techniques were conceptually simple: if a provider deregisters itself before writing events, no events will be emitted. The deregistration API (`EtwUnregister`) is callable from user space by any code running in the provider's process.

**Technique:** Enumerate the ETW registration handles for target providers using undocumented structures in the `ntdll.dll` private heap, call `EtwUnregister` on them to destroy the registration, then re-register with a no-op stub. Subsequent calls to `EtwEventWrite` using the original handle return `ERROR_INVALID_HANDLE`.

**Impact:** Affected all user-mode providers including PowerShell's script block logging provider.  
**Detection:** Correlation between process behavior and absence of expected ETW events.

---

#### 2015 — `EtwEventWrite` Function Patching

Matt Graeber's research (later widely reproduced) demonstrated the simplest and most direct technique: patch the `EtwEventWrite` function in `ntdll.dll` to return immediately (replace the function prologue with a `ret` instruction — `0xC3` on x64).

```powershell
# Classic EtwEventWrite patch in PowerShell
$EtwEventWrite = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (& { 
        $Kernel32 = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            [IntPtr](& { [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory() })
        )
    }),
    [type]
)
# Practical: Find EtwEventWrite in ntdll, change first byte to 0xC3 (ret)
```

More practically, using P/Invoke:

```csharp
[DllImport("kernel32")] static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
    uint flNewProtect, out uint lpflOldProtect);

// Get address of EtwEventWrite in ntdll
IntPtr etwAddr = GetProcAddress(GetModuleHandle("ntdll.dll"), "EtwEventWrite");

// Make page writable
VirtualProtect(etwAddr, (UIntPtr)1, 0x40, out uint oldProtect);

// Patch with ret (0xC3)
Marshal.WriteByte(etwAddr, 0xC3);

// Restore protection
VirtualProtect(etwAddr, (UIntPtr)1, oldProtect, out _);
```

**Impact:** Completely silences all ETW events from the patched process. Killed PowerShell script block logging when applied before script execution.  
**Detection:** Memory integrity checks on ntdll (comparing loaded image bytes to disk) this is now detected by Windows Defender's IUMFI (Image File Integrity) checks and most EDRs.

---

#### 2016–2017 — Registration Handle NULL-ing

Research by Adam Chester and others identified a cleaner approach: rather than patching the function itself, zero out the registration handle stored in the provider's registration structure. The `EtwEventWrite` fast path checks the registration handle early a null or invalid handle causes an immediate return with `STATUS_INVALID_HANDLE` before any kernel call.

Each provider's registration handle is stored in a provider registration structure maintained by ntdll. The structure chain for user-mode providers is:

```
ntdll!_ETW_USER_REG_ENTRY (per-provider)
    ├── RegHandle (REGHANDLE) 
    ├── Callback pointer
    ├── Provider GUID
    └── Linked list pointers
```

By walking this linked list and zeroing the `RegHandle` field for target providers, events are suppressed without touching executable code pages a key advantage for evading memory integrity checks.

**Impact:** More stealthy than function patching, avoids modification of `.text` section pages.  
**Detection:** Behavioral presence of code walking ntdll internal structures scanning for zeroed handles in provider registration linked lists.

---

#### 2018 — Provider Keyword/Level Manipulation

Rather than disabling providers outright, researchers demonstrated that the keyword and level fields of the provider registration structure can be manipulated to cause `EtwEventWrite` to skip the kernel transition entirely (due to the fast-path check against enabled keywords/levels).

If the registration reflects that no session is listening with matching keyword/level filters, the event write call returns immediately. By clearing the `MatchAny` and `MatchAll` keyword fields in the registration structure, all events appear to fail the filter check.

**Impact:** Even more surgical can target specific event categories while leaving others operational, making the silence harder to notice against a baseline.  
**Detection:** Comparing live registration structure fields against expected values registered in the manifest.

---

#### 2019 — `EtwpCreateEtwThread` Stack Spoofing

As ETW hardening increased, researchers looked for bypass surfaces further down the call chain. An interesting technique involved manipulating thread-local state that `EtwEventWrite` consults:

When `EtwEventWrite` is called from a thread that has a certain `ThreadLocalStorage` (TLS) flag set indicating it is currently inside ETW infrastructure code, events are suppressed to prevent recursion. By setting this TLS flag from attacker-controlled code, all `EtwEventWrite` calls on that thread are silenced.

**Impact:** Affects only the current thread effective for single-threaded tools, no code page modifications.  
**Detection:** Unusual TLS flag values in non-ETW threads.

---

#### 2020 — `EtwEventRegister` Callback Hook for Script Block Logging

Specific to defeating PowerShell's Script Block Logging, researchers (including work published by FireEye's Red Team) identified that hooking or replacing the provider callback registered by the PowerShell ETW provider causes the callback to be skipped. Since the SBL mechanism calls `EtwEventWrite` via the registered provider's instrumented callback chain, inserting a no-op at this layer avoids the need to patch ntdll at all.

**Impact:** Targeted and stealthy for PowerShell specifically.  
**Detection:** Monitoring provider callback pointer integrity.

---

#### 2021 — `ClrEtwAll` Flag Manipulation (.NET)

For suppressing .NET CLR ETW events specifically, Topher Timzen and others documented that the CLR runtime checks an internal flag called `g_pConfig->IsETWEnabled()` before calling `EtwEventWrite`. By patching this flag in `clr.dll` / `coreclr.dll`, .NET runtime events are silenced at the CLR level before even reaching ntdll.

```csharp
// Locate and patch the CLR ETW enabled flag
// In .NET Framework: clr.dll
// In .NET Core/5+: coreclr.dll
// Field: g_CLRTraceControl or equivalent internal config bool

// Result: Assembly load events, JIT events, and exception events no longer fire
```

**Impact:** Specifically targets EDR detection of in-memory .NET loading (execute-assembly style attacks).  
**Detection:** Memory scanning for the patched CLR internal configuration behavioral analysis showing .NET execution without CLR telemetry.

---

### Kernel-Mode Bypasses

Kernel-mode bypasses are substantially more powerful and more dangerous. They require the attacker to have kernel code execution (typically via a vulnerable driver, a BYOD technique, or an existing kernel-mode implant). However, they are correspondingly harder to detect, as they operate below the level where user-mode security tools can observe them.

---

#### 2015–2016 — `_ETW_LOGGER_CONTEXT` Buffer Manipulation

Early kernel ETW bypasses focused on corrupting the logger context structure to prevent events from being logged. By finding the `_ETW_LOGGER_CONTEXT` for the session of interest (e.g., the NT Kernel Logger) and zeroing or randomizing the buffer array pointers, events have nowhere to be written and are silently dropped.

```c
// Conceptual kernel-mode bypass
// Walk the ETW logger context list (EtwpLoggerContext array in ntoskrnl)
// Find target session by name/GUID
// Zero the BufferQueue or set LogFileHandle to INVALID
```

**Impact:** Can target specific sessions, leaving others operational.  
**Detection:** Kernel integrity monitors checking session buffer state, PatchGuard (KPP) on some structures.

---

#### 2017 — Provider Enable Mask Clearing (Kernel Level)

In kernel mode, the provider registration structures (`_ETW_REG_ENTRY` for kernel providers) are accessible directly. Clearing the `IsEnabled` bitmask in kernel provider registration entries suppresses events at the provider level, before any buffer interaction.

This technique was used in advanced implants to suppress `Microsoft-Windows-Kernel-Process` events (process creation, image loads) that feed EDR telemetry.

**Impact:** Suppresses kernel provider events such as process creation, image loads the primary EDR telemetry sources.  
**Detection:** Kernel scanning for zeroed provider enable masks in known provider registration entries. PatchGuard does not protect these fields on most Windows versions.

---

#### 2018–2019 — `EtwThreatIntProvRegHandle` NULL-ing

Windows 10 introduced the `Microsoft-Windows-Threat-Intelligence` provider (ETWTI), a specially protected ETW provider designed to supply high-fidelity security events (process injection, memory allocation patterns, driver loads) to security tools with PPL (Protected Process Light) or higher privileges. The ETWTI provider was designed to be tamper-resistant.

Researchers (notably documented by Alex Ionescu and later Sektor7) found that even ETWTI's registration handle, stored in the kernel variable `EtwThreatIntProvRegHandle`, can be NULL-ed in kernel mode. Once this handle is null, ETWTI events silently fail to emit.

```c
// Kernel code to NULL the ETWTI registration handle
// EtwThreatIntProvRegHandle is an exported symbol in ntoskrnl.exe
PHANDLE pEtwThreatIntProvRegHandle = (PHANDLE)
    GetKernelSymbolAddress(L"EtwThreatIntProvRegHandle");
    
// Zero the handle - ETWTI events will now fail silently
*pEtwThreatIntProvRegHandle = NULL;
```

**Impact:** Disables the most privileged ETW security telemetry channel, blinding even PPL-protected security processes.  
**Detection:** Checking `EtwThreatIntProvRegHandle` value at runtime; integrity checking of kernel symbol values. PatchGuard was NOT protecting this symbol at time of disclosure.

---

#### 2020 — PatchGuard and ETW: Understanding the Boundary

An important clarification in the bypass timeline: PatchGuard (Kernel Patch Protection, KPP) does NOT comprehensively protect ETW structures. KPP protects a specific set of kernel data structures (SSDT, IDT, GDT, kernel code sections), but the ETW provider registration structures, logger context structures, and most ETW-related global variables are not in KPP's protection set as of most Windows 10/11 versions.

This means that kernel ETW manipulation is possible without triggering a KPP-induced BSOD, which is why kernel-mode ETW bypasses remained viable long after PatchGuard was introduced.

**Kernel Data Protection (KDP)**, introduced in Windows 10 2004, does begin to protect some ETW structures by making them non-writable after initialization. The CKCL's logger context and the ETWTI registration handle gained KDP protection progressively across Windows versions, making the above bypasses non-functional on patched modern systems.

---

#### 2022–2023 — Hypervisor-Protected Code Integrity (HVCI) Era

With the enforcement of HVCI (also called Memory Integrity or Core Isolation) on modern Windows 11 devices, kernel-mode bypasses became dramatically harder. HVCI prevents unsigned kernel code from executing and uses the hypervisor to enforce page permission policies — write-execute exclusivity applies even to kernel pages.

Under HVCI, many of the older kernel ETW bypass techniques require either:
- A signed vulnerable driver (BYOVD — Bring Your Own Vulnerable Driver) that can be weaponized to perform the memory writes.
- A zero-day kernel vulnerability that bypasses HVCI itself.

The BYOVD technique became the dominant approach for kernel ETW bypasses in this era. Notable examples include ransomware groups and APTs using signed but vulnerable drivers (e.g., `gdrv.sys`, `RTCore64.sys`) to perform arbitrary kernel writes that zero ETW handles or manipulate session structures.

**Detection:** Vulnerable driver blocklists (WDAC/Driver Blocklist) monitoring for known-vulnerable driver loads via `Microsoft-Windows-Kernel-Process` image load events (ironically, the very telemetry these bypasses aim to suppress, so the window of visibility is narrow).

---

#### 2023–2024 — ETW Bypass via Kernel Callback Removal

Some modern kernel-mode implants bypass ETW indirectly by removing the kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `PsSetLoadImageNotifyRoutine`) that certain ETW-based providers depend on. Disabling these callbacks prevents the callbacks from firing, which prevents the ETW provider from having data to emit — effectively a step removed from ETW itself.

This is a notable evolution: rather than attacking ETW infrastructure directly (which draws more scrutiny), attack the data sources that feed ETW providers.

**Detection:** Kernel callback integrity monitoring (verifying the expected set of registered callbacks matches a known-good baseline); this is a detection area that Microsoft continues to improve with each Windows release.

---

## Detecting ETW Tampering

Understanding how to detect ETW bypass attempts is essential both for defenders hardening their environments and for red teamers understanding their detection surface. Detection approaches fall into several categories:

### Memory Integrity Checks on ETW-Related Functions

**What to check:** The bytes at the start of `EtwEventWrite`, `EtwEventWriteFull`, `EtwEventWriteEx`, and `NtTraceEvent` in `ntdll.dll` in every running process. Compare the live bytes to the bytes on disk (using a clean copy of ntdll loaded as a data file, not as an executable).

**Implementation approach:**
```csharp
// For each running process:
// 1. Open ntdll.dll from disk as a data file
// 2. Open the process's memory and read the ntdll mapping
// 3. Compare the .text section bytes at relevant function offsets
// 4. Alert on any deviation from the on-disk copy

// Tools implementing this: Get-InjectedThread, PE-sieve, Moneta
```

**Coverage:** Catches all patching-based bypasses (0xC3 patches, NOPs, etc.).  
**Gaps:** Does not catch handle/structure manipulation techniques that don't touch code pages.

### Provider Registration Structure Validation

**What to check:** For each registered ETW provider (enumerable via `TdhEnumerateProviders`), validate that the provider's registration handle in memory is non-null and matches a valid registration.

**Advanced approach:** Scan the provider registration linked list in ntdll's internal structures and cross-reference against expected provider registrations. Alert on providers that are registered in the manifest but have null/invalid registration handles at runtime.

**Coverage:** Catches handle NULL-ing techniques.  
**Gaps:** Requires access to ntdll internal structures (undocumented; version-dependent offsets).

### ETW Session Baseline Monitoring

**Concept:** Establish a baseline of expected ETW sessions on a system (name, GUID, provider subscriptions, buffer count). Periodically re-enumerate sessions via `EnumerateTraceGuids` or the `NtQuerySystemInformation` `SystemTraceInformation` class and alert on deviations.

**Specific checks:**
- NT Kernel Logger session should always be running with expected providers enabled
- CKCL should be active with expected configuration
- Security-sensitive sessions (Microsoft Defender's sessions, EDR product sessions) should show expected providers with expected keyword masks

**Coverage:** Catches session-level manipulation and DoS-style attacks (filling session slots).  
**Gaps:** Does not catch provider-level bypasses that leave sessions intact.

### Kernel-Mode: Canary Values and Hash Checks

For kernel-mode bypass detection, Microsoft's own security mechanisms include:

**PatchGuard** periodically hashes protected structures and BSODs if they've changed. As noted, ETW structures are partially (but not comprehensively) protected.

**KDP (Kernel Data Protection)** makes critical ETW structures non-writable by marking their pages as read-only at the hypervisor level. Once a structure is KDP-protected, even kernel code cannot write to it without triggering a hypervisor exception.

**ETWTI (Threat Intelligence Provider) self-monitoring:** Some EDR products subscribe to ETWTI and also implement their own kernel callbacks as redundant telemetry sources. If ETWTI events stop flowing but the redundant callbacks are still firing, the discrepancy reveals tampering.

**Canary approach:** A dedicated kernel driver can write a unique canary value to a non-critical memory region and register an ETW provider that emits events referencing that canary. If the events stop flowing or arrive with incorrect canary values, the driver can detect the suppression and alert through an out-of-band channel.

### Behavioral Detections

Some of the most robust detections are behavioral rather than structural:

**Expected-event absence:** If a system is running PowerShell and no Script Block Logging events (4104) appear for an extended period, that absence is suspicious. Baselining expected event rates and alerting on unexpectedly low rates is a powerful complementary detection.

**Cross-correlation:** Many actions that trigger ETW events also trigger other telemetry (file system events, registry changes, network connections). An implant that successfully suppresses ETW but cannot suppress all side channels creates a detectable inconsistency — for example, network connections to a C2 IP appearing in firewall logs but with no corresponding process creation or image load events in ETW.

**AMSI + ETW correlation:** AMSI and ETW are separate telemetry mechanisms. A bypass that suppresses ETW events but leaves AMSI scanning intact produces a signature: AMSI scan requests appear but the corresponding ETW events don't.

### Specific IOCs for Common Bypasses

| Bypass Technique | Primary IOC | Detection Method |
|------------------|-------------|------------------|
| `EtwEventWrite` 0xC3 patch | ntdll .text modification | Memory integrity scan |
| Provider handle NULL | NULL `RegHandle` in registration struct | In-process structure scan |
| Keyword mask zeroing | Zero MatchAny/MatchAll in reg entry | In-process structure scan |
| TLS recursion flag abuse | Unexpected TLS ETW flag set | Thread TLS inspection |
| ETWTI handle NULL (kernel) | NULL `EtwThreatIntProvRegHandle` | Kernel driver check |
| CKCL manipulation | Modified `GetCpuClock` pointer | KDP/kernel integrity |
| Callback removal | Missing expected notify callbacks | Callback list enumeration |
| Session exhaustion | All 64/128 session slots in use | Session count monitoring |

---

## Defensive Recommendations

For blue teams and defenders building ETW-based detection capabilities:

**1. Enable HVCI (Memory Integrity) and Secure Boot.** This is the single most impactful configuration change to harden against kernel-mode ETW bypasses. HVCI prevents unsigned kernel code execution and enables KDP, which progressively protects more ETW structures across Windows versions.

**2. Maintain an up-to-date vulnerable driver blocklist.** BYOVD attacks are the primary remaining vector for kernel ETW manipulation on HVCI-enabled systems. Microsoft's recommended driver blocklist (configurable via WDAC) should be applied and kept current.

**3. Use redundant telemetry sources.** No single telemetry source should be the sole input for critical detections. Combine ETW with AMSI, WFP (Windows Filtering Platform) for network events, Sysmon kernel callbacks, and cloud-delivered telemetry. An attacker who suppresses one source creates a detectable absence against the others.

**4. Deploy PPL-protected EDR processes.** The ETWTI provider is only accessible to processes running at Protected Process Light level or higher. Ensuring your EDR's kernel component is PPL-protected means its ETWTI subscription survives most user-mode interference.

**5. Alert on ntdll memory modifications in any process.** Process memory integrity scanning (comparing loaded ntdll to on-disk copy) should be a standard EDR capability. This catches the oldest and most common family of ETW bypasses.

**6. Monitor for known-vulnerable driver loads.** Image load events for drivers in the BYOVD blocklist should trigger immediate alert escalation. The window between driver load and kernel manipulation is narrow but detectable.

**7. Baseline expected ETW event rates.** Implement event volume anomaly detection. A machine running PowerShell scripts with zero 4104 (Script Block Logging) events is suspicious. Establish per-machine, per-process baselines and alert on significant deviations.

---

## Conclusion

ETW is a microcosm of the broader Windows security landscape: deeply powerful, architecturally elegant, and the subject of a decade-long arms race between attackers seeking to blind it and defenders seeking to protect it. For offensive security practitioners, ETW represents both the primary risk surface (it will detect you) and a rich operational resource (you can consume its data for your own purposes).

The key takeaways from this deep dive:

- **ETW is not a monolith.** It spans user space and kernel space, with different bypass techniques operating at each level. Suppressing user-mode `EtwEventWrite` leaves kernel providers intact. Disabling the NT Kernel Logger session leaves process-local providers intact.

- **ETW providers are intelligence.** The SMB, DNS, LDAP, WMI, and process providers contain extraordinarily rich operational data. An attacker with an ETW consumer on a compromised host can perform passive reconnaissance that generates no new network traffic and leaves minimal forensic artifacts.

- **The bypass landscape has matured.** Early bypasses (0xC3 patches) are now reliably detected by modern EDRs. Kernel bypasses remain effective but require elevated privileges and are increasingly constrained by HVCI/KDP. The current frontier is BYOVD-enabled kernel manipulation on systems without HVCI.

- **Detection is achievable but layered.** No single detection catches all bypass techniques. The most robust defensive posture combines memory integrity checking, behavioral anomaly detection on event volumes, kernel structure integrity monitoring, and redundant telemetry sources.

As Microsoft continues to extend KDP coverage to more ETW structures and HVCI adoption grows, the kernel bypass surface will continue to shrink. Understanding the historical attack surface and its evolution is essential for both accurately assessing your current detection capabilities and anticipating where the next generation of bypasses will emerge.

---

### Further Reading and References

- **Alex Ionescu** — "Kernel Exploitation via Windows Group Policy" and ETW internals presentations (SyScan, REcon)
- **Matt Graeber** — Original PowerShell ETW bypass documentation
- **Adam Chester (XPN)** — "Hiding Your .NET – ETW" blog series
- **Sektor7 Institute** — Malware development courses covering ETW bypass
- **FireEye/Mandiant Red Team** — "Bring Your Own Land" and ETW avoidance techniques
- **Pavel Yosifovich** — "Windows Kernel Programming" (ETW kernel internals chapter)
- **Joe Desimone / Elastic Security** — "Detecting ETW Bypass" research
- **Windows Internals 7th Edition** — Part 1, Chapter 9 (Management Mechanisms, ETW section)
- **Microsoft Documentation** — `docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing`
- **SilkETW / SilkService** — Mandiant's open-source ETW consumer framework for defensive use
- **PerfView** — Microsoft's ETW analysis tool (GitHub: microsoft/perfview)
- **EtwExplorer** — Provider browser by Pavel Yosifovich

---

*© Your Blog Name — All content for educational and authorized security testing purposes only.*
