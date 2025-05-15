
# 📘 System Call Tracer (strace-like) for xv6

## 🔍 Project Overview
This project implements a system call tracer on the xv6 operating system, mimicking the behavior of the Linux `strace` tool. The tracer logs all system calls made by a process, including syscall names, arguments, and return values. It also supports advanced features like selective tracing, logging to a file, and system-wide tracing.

---

## 🚀 How It Works
- A process enables tracing by calling a new system call: `trace()`.
- Once enabled, every system call the process makes is logged to the kernel console or a file.
- The output includes:
  - syscall name, arguments, and return values.
  - Additional features allow fine control over what is traced and where output is written

---

## 📁 Modified Files and Descriptions

🧩 `proc.h`
Location: Kernel data structures

Modifications:

```c
int tracing;                   // Per-process flag to enable syscall tracing
int trace_mask[25];            // Tracks which syscalls are being traced
int logfd;                     // File descriptor for trace output
```

🧩 `proc.c`
Location: Process lifecycle code (e.g., fork, exec)

Modifications in fork():

```c
np->tracing = curproc->tracing;
memcpy(np->trace_mask, curproc->trace_mask, sizeof(curproc->trace_mask));
np->logfd = -1;
```
Purpose: Inherit tracing behavior from parent process.


🧩 `sysproc.c`
Location: Kernel system call implementations

Modifications:

Added 5 new system calls:

```c
int sys_trace(void);           // Enables tracing
int sys_traceoff(void);        // Disables tracing
int sys_settracemask(void);    // Enables/disables specific syscall tracing
int sys_setlogfd(void);        // Sets log output file descriptor
int sys_tracepid(void);        // Enables tracing for another process by PID
```
Purpose: Implements system calls for controlling tracing.


🧩 `defs.h`
Location: Global kernel declarations

Modifications:

```c
int sys_trace(void);
int sys_traceoff(void);
int sys_settracemask(void);
int sys_setlogfd(void);
int sys_tracepid(void);
```
Purpose: Declares new syscall handler prototypes.


🧩 `syscall.h`
Location: System call number definitions

Modifications:

```c
#define SYS_trace         22
#define SYS_settracemask  23
#define SYS_traceoff      24
#define SYS_setlogfd      25
#define SYS_tracepid      26
```
Purpose: Assigns syscall numbers for the new tracing system calls.


🧩 `syscall.c`
Location: Central syscall dispatcher

Modifications:

Registered new syscalls:

```c
extern int sys_trace(void);
extern int sys_traceoff(void);
extern int sys_settracemask(void);
extern int sys_setlogfd(void);
extern int sys_tracepid(void);
...
[SYS_trace]        sys_trace,
[SYS_settracemask] sys_settracemask,
[SYS_traceoff]     sys_traceoff,
[SYS_setlogfd]     sys_setlogfd,
[SYS_tracepid]     sys_tracepid,
```
Hooked syscall dispatcher to log syscalls:

```c
if (proc->tracing && proc->trace_mask[num]) {
  // print syscall name and args
}
```
Logs to console or file based on logfd.


🧩 `usys.S`
Location: Assembly stubs for user-space syscalls

Modifications:

```asm
SYSCALL(trace)
SYSCALL(traceoff)
SYSCALL(settracemask)
SYSCALL(setlogfd)
SYSCALL(tracepid)
```
Purpose: Allows user programs to invoke the new system calls.

🧩 `user.h`
Location: User-space syscall declarations

Modifications:

```c
int trace(void);
int traceoff(void);
int settracemask(int syscall_num, int enable);
int setlogfd(int fd);
int tracepid(int pid);
```
Purpose: Makes new syscalls accessible to user-space programs.


🧩 trace_test.c (new)
Location: User program for testing

Modifications:

- Created a demo program to:
  - Enable tracing
  - Set a syscall mask
  - Redirect logs to file
  - Invoke system calls (e.g., write, sleep, exit)


🧩 Makefile
Location: Build system

Modifications:

make
UPROGS=\
  ...
  _trace_test\
Purpose: Builds the test program as part of xv6.

---

## 🧪 How to Run
1. Compile and run xv6:
```bash
make clean
make qemu
```
2. Run the test:
```sh
$ trace_test
```

## 💡 Example Output in the kernel console or redirected log file
```perl
pid 3: syscall write(1, 632848, 14)
pid 3: -> return 14
pid 3: syscall getpid()
pid 3: -> return 3
pid 3: syscall fork()
pid 3: -> return 4
pid 4: syscall write(1, 632900, 20)
pid 4: -> return 20
pid 4: syscall getpid()
pid 4: -> return 4
pid 4: syscall exit()
pid 4: -> return 0
pid 3: syscall wait()
pid 3: -> return 4
pid 3: syscall traceoff()
pid 3: -> return 0
```

---

## 🔧 Features

### -----------------------  Adham w Mazen ----------------------- ###

## 1. ✅ tracing Flag in `proc` Struct

📄 File: `proc.h`

```c
int tracing; // 0 = off, 1 = on
```

## 2. ✅ Add a New System Call: `trace()`

📄 File: `sysproc.c`

```c
int sys_trace(void) {
  struct proc *p = myproc();
  p->tracing = 1;
  return 0;
}
```

## 3. ✅ Modify Syscall Dispatcher for Logging (Print Traces)

📄 File: `syscall.c`

```c
if (syscalls[num]) {
  int retval;

  if (proc->tracing) {
    cprintf("pid %d: syscall %s(", proc->pid, syscall_names[num]);

    int arg0;
    if (argint(0, &arg0) >= 0)
      cprintf("%d", arg0);
    cprintf(")
");
  }

  retval = syscalls[num]();

  if (proc->tracing)
    cprintf("pid %d: -> return %d
", proc->pid, retval);

  proc->tf->eax = retval;
}
```

### -----------------------  Salah w Zeyad ----------------------- ###

## 4. ✅ Trace All Arguments of System Calls 

📄 File: `syscall.c`

Replace current tracing block with:

```c
if (proc->tracing) {
  cprintf("pid %d: syscall %s(", proc->pid, syscall_names[num]);

  int i, arg_val;
  for (i = 0; i < 5; i++) {
    if (argint(i, &arg_val) >= 0) {
      cprintf("%d", arg_val);
      if (i < 4) cprintf(", ");
    } else {
      break;
    }
  }

  cprintf(")\n");
}
```

## 5. ✅ Selective System Call Tracing `trace_mask[]`
Use:
```c
settracemask(SYS_write, 1); // Enable
settracemask(SYS_write, 0); // Disable
```

📄 File: `proc.h`

```c
int trace_mask[SYS_call_count]; // where SYS_call_count = total number of syscalls
🔹 Add new syscall settracemask(int syscall_num, int enable)
```

📄 File: `sysproc.c`

```c
int
sys_settracemask(void)
{
  int num, enable;
  if (argint(0, &num) < 0 || argint(1, &enable) < 0)
    return -1;
  if (num < 0 || num >= SYS_call_count)
    return -1;

  struct proc *p = myproc();
  p->trace_mask[num] = enable;
  return 0;
}
```

📄 File: defs.h

```c
int sys_settracemask(void);
```

📄 File: `syscall.h`

```c
#define SYS_settracemask 23
```

📄 File: `syscall.c`

```c
extern int sys_settracemask(void);
...
[SYS_settracemask] sys_settracemask,
```

📄 File: `user.h`

```c
int settracemask(int syscall_num, int enable);
```

📄 File: ` usys.S`

```asm
SYSCALL(settracemask)
```

📄 File: `syscall()` handler

Replace:
```c
if (proc->tracing)
```
With:

```c
if (proc->tracing && proc->trace_mask[num])
```

## 6. ✅ Add a New System Call: `traceoff()`

```c
Call `traceoff()` to stop tracing during execution.

``` 
📄File: Add new syscall `sysproc.c`

```c
int sys_traceoff(void)
{
  myproc()->tracing = 0;
  return 0;
}
```

📄 File: `defs.h`

```c
int sys_traceoff(void);
```
📄 File: `syscall.h`

```c
#define SYS_traceoff 24
```

📄 File: `syscall.c`

```c
extern int sys_traceoff(void);
...
[SYS_traceoff] sys_traceoff,
```

📄 File: `user.h`

```c
int traceoff(void);
```

📄 File: `usys.S`

```asm
SYSCALL(traceoff)

```
### -----------------------  Samaa ----------------------- ###

## 7. ✅ Trace Child Processes on `fork()` (Inheritance)
Children inherit `tracing`, `trace_mask[]` via `fork()`.

📄 File: `proc.c, inside fork()` , tracing flags:

```c
np->tracing = curproc->tracing;
for (int i = 0; i < SYS_call_count; i++) {
  np->trace_mask[i] = curproc->trace_mask[i];
}
```

## 8. ✅ Log Output to File (logfd)
📄 File: `proc.h`

```c
Call `setlogfd(fd)` to redirect logs to a file opened in user-space.

You can log to a file instead of the console.

int logfd; // initialized to -1 by default
```
🔹 Add syscall to set output log file

📄 File: `sysproc.c`

```c
int sys_setlogfd(void) {
  int fd;
  if (argint(0, &fd) < 0) return -1;
  myproc()->logfd = fd;
  return 0;
}
```
📄 File: `defs.h, syscall.h, syscall.c, user.h, usys.S`: Add sys_setlogfd just like above examples.

📄 File: Modify logging line in `syscall.c`
Replace:
```c
cprintf(...)
```
With:

```c
if (proc->logfd >= 0) {
  char buffer[128];
  int len = snprintf(buffer, sizeof(buffer), "pid %d: syscall %s(...)\n", ...);
  write(proc->logfd, buffer, len);
} else {
  cprintf(...);
}
```

## 9. ✅ System-Wide Tracing 'tracepid(pid)'
```c
Call `tracepid(pid)` to trace another process from kernel space.
```
📄 File: `sysproc.c`

```c
int sys_tracepid(void) {
  int pid;
  if (argint(0, &pid) < 0) return -1;
  for (struct proc *p = ptable.proc; p < &ptable.proc[NPROC]; p++) {
    if (p->pid == pid) {
      p->tracing = 1;
      return 0;
    }
  }
  return -1;
}
```

📄 File: `(syscall.h, defs.h, user.h, usys.S, syscall.c)`, Add syscall entries

```c
#define SYS_tracepid 25
...
int tracepid(int pid);
SYSCALL(tracepid)
```

## 🧪 Example Program
```c
#include "types.h"
#include "user.h"

int main() {
  int fd = open("trace.log", O_CREATE | O_WRONLY);
  setlogfd(fd);                     // ✅ Feature 8: Redirect log output
  trace();                          // ✅ Feature 1: Enable tracing
  settracemask(SYS_write, 1);      // ✅ Feature 5: Selective tracing
  settracemask(SYS_getpid, 1);     // ✅ Feature 5

  printf(1, "Start tracing\\n");
  int pid = fork();                // ✅ Feature 7: Trace inheritance

  if (pid == 0) {
    // Child process
    printf(1, "Child here: %d\\n", getpid());  // Traced due to inheritance
    exit();
  } else {
    wait();                         // Traced due to trace mask
    traceoff();                     // ✅ Feature 6: Stop tracing
    printf(1, "Tracing off\\n");
    close(fd);
    exit();
  }
}
```