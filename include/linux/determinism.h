
#ifndef _LINUX_DETERMINISM_H
#define _LINUX_DETERMINISM_H

#include <linux/sched.h>

/* When a deterministic process exits, we need to notify the parent so wake it
 * up. */
static inline void deterministic_notify_parent(struct task_struct *tsk)
{
    wake_up_process(tsk);
}

static inline void forget_det_child(struct task_struct *child)
{
	child->d_pid = -1;
}

/* Marks a deterministic process and its children as poisoned. All marked
 * child processes are killed immediately, and the marked parent task is
 * stopped from ever running again. This process is kept around until its
 * parent notices its death with a dput()/dget().
 */
extern void mark_deterministic_poisoned(struct task_struct *tsk);
extern void zap_det_process(struct task_struct *tsk, int exit_code);
extern long do_dfork(unsigned long, unsigned long, struct pt_regs *,
		unsigned long, int __user *, int __user *, struct task_struct **);
extern long deterministic_put_regs(struct task_struct *dst,
		const void __user *regs, unsigned int setno);
extern long deterministic_get_regs(struct task_struct *dst,
		void __user *regs, unsigned int setno);

/* For (struct task_struct*)->d_flags. */
#define DET_DETERMINISTIC     0x0001
#define DET_MASTER            0x0002
#define DET_POISON            0x0004
#define DET_CUSTOM_SIGNALS    0x0008

/* Operations for dput/dget flags argument. */
#define DET_REGS                 1
#define DET_BECOME_MASTER        2
#define DET_GET_STATUS           3
#define DET_KILL                 4
#define DET_ALLOW_SIGNALS        5
#define DET_VM_ZERO              6
#define DET_VM_COPY              7
#define DET_SNAP                 8
#define DET_MERGE                9
#define DET_MAX_OPERATION        10

static inline int is_valid_det_op(unsigned long op)
{
	return 0 <= op && op < DET_MAX_OPERATION;
}

#define DET_START                (0x0001L << 16)
#define DET_DEBUG                (0x8000L << 16)

/* Operation specific flags. */
/* for: DET_GET_STATUS */
#define DET_DONT_WAIT            (0x1L << 8)
/* for: DET_KILL */
#define DET_KILL_POISON          (0x1L << 8)

#define is_deterministic_or_master(tsk) ((DET_DETERMINISTIC | DET_MASTER) & (tsk)->d_flags)
#define is_deterministic(tsk) (DET_DETERMINISTIC & (tsk)->d_flags)
#define is_master(tsk) (DET_MASTER & (tsk)->d_flags)
#define is_deterministic_poison(tsk) (DET_POISON & (tsk)->d_flags)
#define master_allow_signals(tsk) (DET_CUSTOM_SIGNALS & (tsk)->d_flags)

/* Return values for dput(), dget(), and dret() conform to the following.
 * dret() always returns 0 except when the caller is not deterministic or a
 * master process.
 * A return value less than zero indicates an error. Otherwise, a successful
 * return value is encoded with two types of information. The least significant
 * 4 bits indicate the run status of the child (eg. runnable or faulted). The
 * following 28 bits indicate information regarding the specific operation(s)
 * performed.
 */
#define DET_S_READY   1 /* Alive and runnable (not in run queue). */
#define DET_S_RUNNING 2 /* Alive and in run queue. */
#define DET_S_EXCEPT  3 /* Process killed due to illegal behavior. */
#define DET_S_EXIT_NORMAL    4 /* Process exited normally. */
#define DET_S_EXCEPT_DEAD    5 /* When an excepted task was killed explicitly by the parent. */

#endif

