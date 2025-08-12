# Halo's Hall

Halo’s Hall is the twin sister of Halo’s Gate — sharing the same core concept of stealthy syscall invocation, but taking a different path.
Instead of direct syscalls, Halo’s Hall implements indirect syscalls, making it more resilient against modern EDR/AV userland hooks and inline patching.

# Key Features
- Indirect Syscall Execution — avoids direct syscall stubs to bypass naive detection mechanisms.

- Halo’s Gate Logic Retained — inherits the enumeration and syscall number retrieval mechanism from Halo’s Gate.

- Improved OPSEC — reduces risk of static signature detection by avoiding common syscall prologues.

- Minimal API Usage — limits interaction with WinAPI functions to lower detection surface.

# Credits

Reenz0h from @SEKTOR7net (Creator of the HalosGate technique)

Inspired by Halo’s Gate (original idea for SSN discovery/enumeration).
