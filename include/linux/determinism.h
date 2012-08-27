
#ifndef _LINUX_DETERMINISM_H
#define _LINUX_DETERMINISM_H

#include <linux/sched.h>

/* The low two bytes specify general operations. The high two bytes
   specify flags for a specific flag. */

#define DETERMINE_START             0x0001
#define DETERMINE_REGS              0x0002
//#define DETERMINE_VM_COPY           0x0004
//#define DETERMINE_ZERO_FILL         0x0008
//#define DETERMINE_SNAP              0x0010
//#define DETERMINE_MERGE             0x0010
#define DETERMINE_BECOME_MASTER     0x0020
//#define DETERMINE_COPY_CHILD        0x0040
//#define DETERMINE_CLEAR_CHILD       0x0040
//#define DETERMINE_CHILD_STATUS      0x0080
#define DETERMINE_DEBUG             0x8000

/* Change or get a process's state. */
#define DETERMINE_KILL              (0x0001 << 16)

/* These constants can be returned by the three syscalls. */

/* Process is alive and in a state ready to begin execution but is not
   on the scheduler queue. */
#define DETERMINE_S_READY           1
/* Process was put onto the scheduluer (may or may not actually be running). */
#define DETERMINE_S_RUNNING         2
/* Process was killed due to illegal behavior (illegal opcode,
   memory violation, permission violation). */
#define DETERMINE_S_EXCEPT          3
/* Process exited normally. */
#define DETERMINE_S_DEAD            4

//int copy_mm(unsigned long clone_flags, struct task_struct * tsk);
//void copy_regs(struct task_struct *from, struct task_struct *into);

/* When a deterministic process exits, we need to notify the parent so wake it
   up. */
extern void deterministic_notify_parent(struct task_struct *tsk);

extern long do_dfork(unsigned long, unsigned long, struct pt_regs *,
		unsigned long, int __user *, int __user *, struct task_struct **);

#define DET_DETERMINISTIC 0x0001
#define DET_MASTER        0x0002

#endif

