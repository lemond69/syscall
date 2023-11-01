# Syscall extraction from ntdll
Based on [this blog post by crummie5](https://web.archive.org/web/20200621161516/https://www.crummie5.club/freshycalls/), but implemented from scratch in C. Uses manual syscalls to call ntdll.

Modified to make use of ROP gadget by `jmp` to a syscall-ret set (`0f 05 c3`) in ntdll. This code only uses the first ROP gadget found within ntdll, but a more strategic choice of ROP can be easily selected for a more effective return address spoofing.

Compiled with x64 mingw, `x86_64-w64-mingw32-gcc demo.c rop.S -masm=intel` for demo program, `x86_64-w64-mingw32-gcc scanner.c` for scanner program. Note this code is EXCLUSIVELY for x64 only, because it's quite pointless to implement one for x86 due to how few real x86 machines are left, and the fact that you CANNOT syscall from WOW64.

I tried to ensure minimal disruption from using this code, and usage remains very similar to just calling standard undocumented NTAPIs. Demo available in `demo.c`.

It is not very likely for breaking changes to be made in Windows in the near future, but if derived syscall counts are offset by like 1-2 compared to actual syscalls, compile and run `scanner.c` to scan for changes. Right now only unusual API needed to account for is `NtGetTickCount`.
