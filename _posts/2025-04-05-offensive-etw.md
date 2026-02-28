---
title: "Using ETW for Offensive Security"
categories:
  - Blog
tags:
  - Windows
  - Red Team
---

## What is ETW?

**Event Tracing for Windows (ETW)** is a high-performance, kernel-level tracing mechanism built into Windows that allows both user-mode and kernel-mode components to log structured events. Introduced with Windows 2000 and massively expanded in later releases, ETW is today the backbone of Windows diagnostics, performance analysis, and — crucially for us — security monitoring.

Unlike traditional logging systems, ETW is designed for **minimal overhead**. Events are written to in-memory circular per-CPU buffers and only flushed to disk or delivered to consumers when necessary. Microsoft itself uses ETW internally for the Windows Performance Recorder (WPR), Windows Performance Analyzer (WPA), Process Monitor, and many components of Windows Defender / Microsoft Defender for Endpoint (MDE).

From a security standpoint, ETW is a double-edged sword: for defenders it is a rich telemetry goldmine; for attackers it is a surveillance system that must be understood, blinded, or bypassed to stay under the radar.

> ETW currently ships with **1,000+ built-in providers** in Windows 10/11, covering everything from network activity and process creation to AMSI scan results, CLR events, and kernel object access.
