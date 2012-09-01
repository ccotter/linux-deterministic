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

#include <asm/syscall.h>

#define DET_RQ_STOPPED 0
#define DET_RQ_RUNNING_NORMAL 1
#define DET_RQ_FIRST_TIME 2 /* Has never been started yet. */

/* Wait for a deterministic child to do a dret() or fault.
 * This function returns 0 if the child process was stopped with a normal
 * dret(). If a fatal SIGKILL arrives to current, this function returns -EINTR
 * immediately.
 */
static int wait_for_child(struct task_struct *child)
{
	int ret = 0;
	DEFINE_WAIT(wait);
	for (;;) {
		prepare_to_wait(&child->d_wq_head, &wait, TASK_INTERRUPTIBLE);
		if (DET_RQ_RUNNING_NORMAL != atomic_read(&child->d_status))
			break;
		if (unlikely(fatal_signal_pending(current))) {
			ret = -EINTR;
			break;
		}
		schedule();
	}
	finish_wait(&child->d_wq_head, &wait);
	return ret;
}

/*
 *
 * We need the 6th argument to be pt_regs so that we can properly perform
 * do_dfork. Typical syscalls (eg. exit) don't save an entire stack frame.
 *
 * Returns:
 *   When current is non-deterministic:
 *     * On success, the least significant 32-bits of the return value are
 *       important. Various bits are set (see determinism.h) indicating child
 *       status.
 *     * -EINTR when the caller is interrupted by a signal while waiting for a
 *       child to perform a dret().
 *     * On other errors (no memory, etc) the appropriate negative error number
 *       is set.
 *   When current is deterministic:
 *     * On success, the least significant 32-bits of the return value are
 *       important. Various bits are set (see determinism.h) indicating child
 *       status.
 *     * On any failure that is deterministically reproducible (eg. invalid
 *       arguments), an appropriate negative error number is returned.
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
		int waitrc = wait_for_child(child);
		if (-EINTR == waitrc) {
			/* Might as well exit immediately. */
			do_exit(0);
			/* NOTREACHED */
		}
		/* At this point, the child is not running and will not run until we
		 * tell it to. */
	}

	if (is_deterministic_poison(child)) {
		return DET_S_EXCEPT;
	}

	if (DET_COPY_REGS & flags) {
		struct pt_regs *dst = task_pt_regs(child);
		*dst = *regs;
		syscall_set_return_value(child, dst, 0, 0);
	}

	if (DET_START & flags) {
		if (DET_RQ_FIRST_TIME == atomic_read(&child->d_status)) {
			atomic_set(&child->d_status, DET_RQ_RUNNING_NORMAL);
			wake_up_process(child);
		} else {
			atomic_set(&child->d_status, DET_RQ_RUNNING_NORMAL);
			wake_up_interruptible(&child->d_wq_head);
		}
		ret = DET_S_RUNNING;
	} else {
		ret = DET_S_READY;
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
	DEFINE_WAIT(wait);

	if (!is_deterministic(current))
		return -EPERM;

	atomic_set(&current->d_status, DET_RQ_STOPPED);
	wake_up_interruptible(&current->d_wq_head);
	for (;;) {
		prepare_to_wait(&current->d_wq_head, &wait, TASK_INTERRUPTIBLE);
		if (DET_RQ_RUNNING_NORMAL == atomic_read(&child->d_status) ||
				fatal_signal_pending(current)) {
			break;
		}
		schedule();
	}
	finish_wait(&current->d_wq_head, &wait);

	return 0;
}

