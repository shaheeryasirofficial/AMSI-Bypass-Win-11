# AMSI Bypass Tool (Rust Implementation)

[![Rust](https://img.shields.io/badge/Rust-1.75+-informational)](https://www.rust-lang.org/) [![Windows](https://img.shields.io/badge/Windows-10%2B-blue)](https://www.microsoft.com/windows) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

This is a simple, educational Rust-based tool that implements an in-memory binary patch for bypassing the **Antimalware Scan Interface (AMSI)** on Windows. Specifically, it targets the `AmsiScanBuffer` function in `amsi.dll` by modifying a conditional jump instruction (`je` → `jne`) to skip the failure return path (HRESULT `E_INVALIDARG`).

**Purpose**: Demonstrates low-level Windows API usage (e.g., `LoadLibraryA`, `GetProcAddress`, `VirtualProtect`) for security research, red teaming, or understanding AMSI internals. **Not for malicious use.**

- **Tested On**: Windows 11 (builds up to 24H2 as of November 2025). May require adjustments for future updates due to potential Microsoft mitigations.
- **Volatility**: Patch applies only to the current process/session; reverts on reboot or DLL reload.

> **⚠️ WARNING**: This modifies protected system memory. Requires **Administrator privileges**. Use in a virtual machine (VM) only. Misuse may violate laws (e.g., CFAA in the US). For authorized pentesting/research exclusively.

## Features

- Loads `amsi.dll` dynamically via `LoadLibraryA`.
- Locates `AmsiScanBuffer` export with `GetProcAddress`.
- Scans for a signature pattern (`ret` + `int3` + `int3` = `[0xC3, 0xCC, 0xCC]`) to find the target jump site.
- Validates the `je` (0x74) instruction leads to `mov eax, 0x80070057` (failure code).
- Patches the opcode to `jne` (0x75) using `VirtualProtect` for write access.
- Restores original memory protection.

## Requirements

- **Rust**: Stable toolchain (1.75+ recommended). Install via [rustup.rs](https://rustup.rs/).
- **Windows**: 10/11 (x86_64). AMSI.dll must be present (standard on modern installs).
- **Admin Rights**: For `VirtualProtect` to succeed.
- **Dependencies**: Handled via Cargo (see `Cargo.toml`).

- No output or errors indicate failure (e.g., pattern not found—check Windows version).

3. Verify:
- Use a disassembler (e.g., x64dbg, Ghidra) on a live process (like `explorer.exe`) to inspect `amsi.dll!AmsiScanBuffer`—the jump should now be `0x75`.
- Test with PowerShell scripts (see below).

## Testing the Bypass

Post-patch, test in an elevated PowerShell session. AMSI should no longer block "suspicious" dynamic content.

### Basic Test
```powershell
# Save as test.ps1 and run: powershell.exe -ExecutionPolicy Bypass -File test.ps1
$b = [Text.Encoding]::UTF8.GetBytes('malicious payload simulation');
[Runtime.InteropServices.Marshal]::AllocHGlobal($b.Length) | Out-Null;  # P/Invoke trigger
Write-Output "Basic test: No AMSI block!";
