# Halo's Hall

Halo’s Hall is the twin sister of Halo’s Gate — sharing the same core concept of stealthy syscall invocation, but taking a different path.
Instead of direct syscalls, Halo’s Hall implements indirect syscalls, making it more resilient against modern EDR/AV userland hooks and inline patching.

# Key Features
- Indirect Syscall Execution — avoids direct syscall stubs to bypass naive detection mechanisms.

- Halo’s Gate Logic Retained — inherits the enumeration and syscall number retrieval mechanism from Halo’s Gate.

- Improved OPSEC — reduces risk of static signature detection by avoiding common syscall prologues.

- Minimal API Usage — limits interaction with WinAPI functions to lower detection surface.

# Why Indirect Syscalls?
While direct syscalls are fast and effective, they often rely on a predictable stub pattern in ntdll.dll that security products monitor.
Indirect syscalls introduce a layer of abstraction: execution flow jumps indirectly into the syscall instruction, making it harder for EDRs to hook or trace.
