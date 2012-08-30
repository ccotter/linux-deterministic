/*
 *  determinism/determinism.c
 *
 *  Kernel deterministic system calls (dput, dget and dret).
 *
 *  See "Efficient System-Enforced Deterministic Parallelism."
 *  (http://dedis.cs.yale.edu/2010/det/papers/osdi10.pdf)
 *
 */

#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/determinism.h>

#define DET_RQ_STOPPED 0
#define DET_RQ_RUNNING_NORMAL 1
#define DET_RQ_FIRST_TIME 2 /* Has never been started yet. */

/*
 *
 * We need the 6th argument to be pt_regs so that we can properly perform
 * do_dfork. Typical syscalls (eg. exit) don't save an entire stack frame.
 *
 */
SYSCALL_DEFINE6(dput, pid_t, child_dpid, long, flags, unsigned long, start,
		size_t, size, unsigned long, dst, struct pt_regs *, regs)
{
	long ret;
	struct list_head *list;
	struct task_struct *child;

	/* Validate arguments first. TODO */

	if (DET_BECOME_MASTER & flags) {
		if (is_deterministic_or_master(current))
			return -EPERM;
		current->d_flags = DET_MASTER;
		return 0;
	}

	if (!is_deterministic_or_master(current)) {
		return -EPERM;
	}

	ret = 0;
	child = NULL;
	/* See if child even exists - O(N) runtime, very slow. TODO make faster */
	list_for_each(list, &current->children) {
		struct task_struct *tsk = list_entry(list, struct task_struct, sibling);
		if (child_dpid == tsk->d_pid && current == tsk->parent) {
			child = tsk;
			break;
		}
	}

	if (NULL == child) {
		ret = do_dfork(0, regs->sp, regs, 0, NULL, NULL, &child);
		if (unlikely(ret < 0)) {
			/* TODO fault. */
			return -ENOMEM;
		}
		child->d_pid = child_dpid;
		child->d_flags = DET_DETERMINISTIC;
		sema_init(&child->d_sem, 1);
		atomic_set(&child->d_status, DET_RQ_FIRST_TIME);
		init_waitqueue_head(&child->d_wq_head);
	} else {
		/* Wait for child to sync up. */
		DEFINE_WAIT(wait);
		for (;;) {
			prepare_to_wait(&child->d_wq_head, &wait, TASK_INTERRUPTIBLE);
			if (DET_RQ_RUNNING_NORMAL != atomic_read(&child->d_status))
				break;
            /* BUG need to check for pending signals! Otherwise we will get
             * stuck here forever waiting to be killed!
			 *
			 * The reason is that do_signal() only runs when returning into user
			 * mode. When we are woken up and returned here (in this dput
			 * syscall), do_signal() won't run and thus a SIGKILL won't do its
			 * job. Instead, we will have to check if we have a pending SIGKILL
			 * and do it ourselves (probably just return to user space). */
            schedule();
		}
		finish_wait(&child->d_wq_head, &wait);
		/* At this point, the child is not running and will not run until we
		 * tell it to. */
	}

	if (DET_COPY_REGS & flags) {
		struct pt_regs *dst = task_pt_regs(child);
		*dst = *regs;
		/* TODO specific to x86 */
		dst->ax = 0;
	}

	if (DET_START & flags) {
		if (DET_RQ_FIRST_TIME == atomic_read(&child->d_status)) {
			atomic_set(&child->d_status, DET_RQ_RUNNING_NORMAL);
			wake_up_process(child);
		} else {
			atomic_set(&child->d_status, DET_RQ_RUNNING_NORMAL);
			wake_up_interruptible(&child->d_wq_head);
		}
	}

	return ret;
}

SYSCALL_DEFINE6(dget, pid_t, child_dpid, long, flags, unsigned long, start,
		size_t, size, unsigned long, dst, struct pt_regs *, regs)
{
	printk("IN DGET\n");
	return -1;
}

SYSCALL_DEFINE0(dret)
{
	struct task_struct *parent;
	DEFINE_WAIT(wait);

	if (!is_deterministic(current))
		return -EPERM;

	parent = current->real_parent;
	atomic_set(&current->d_status, DET_RQ_STOPPED);
	prepare_to_wait(&current->d_wq_head, &wait, TASK_INTERRUPTIBLE);
	wake_up_interruptible(&current->d_wq_head);
	schedule();
	finish_wait(&current->d_wq_head, &wait);

	return 0;
}

