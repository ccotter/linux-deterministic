/*
 *  determinism/determinism.c
 *
 *  Kernel deterministic system calls (dput, dget and dret).
 *
 *  See "Efficient System-Enforced Deterministic Parallelism."
 *  (http://dedis.cs.yale.edu/2010/det/papers/osdi10.pdf)
 *
 */

#include <linux/determinism.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/regset.h>

#include <asm/syscall.h>

static inline int get_child_status(struct task_struct *child)
{
	return atomic_read(&child->d_status);
}

static struct task_struct *
find_deterministic_child(struct task_struct *tsk, pid_t dpid)
{
	struct task_struct *p;
	/* O(N) runtime, very slow. TODO make faster */
	list_for_each_entry(p, &current->children, sibling) {
		if (dpid == p->d_pid && tsk == p->parent) {
			return p;
		}
	}
	return NULL;
}

static inline int sigsets_overlap(const sigset_t *one, const sigset_t *two)
{
	size_t i, n = sizeof(one->sig);
	for (i = 0; i < n; ++i) {
		if (one->sig[i] & two->sig[i])
			return 1;
	}
	return 0;
}

/* Wait for a deterministic child to do a dret() or fault.
 * This function returns a DET_S_* status code if the child process was stopped
 * with a normal dret(). If a fatal SIGKILL arrives to current, or the master
 * process receives any non-blocked signal, this function returns -EINTR
 * immediately.
 */
static int wait_for_child(struct task_struct *child)
{
	int ret;
	int is_master = is_master(current);
	long state = TASK_STOPPED;
	sigset_t oldset;

	if (is_master && master_allow_signals(current)) {
		state = TASK_INTERRUPTIBLE; /* Only set if current wants to allow custom
									   signal set. */
		sigprocmask(SIG_SETMASK, &current->d_blocked, &oldset);
	}
	for (;;) {
		set_current_state(state);
		ret = get_child_status(child);
		if (DET_S_RUNNING != ret) {
			break;
		}
		if (unlikely(fatal_signal_pending(current))) {
			ret = -EINTR;
			break;
		}
		if (signal_pending(current) && is_master(current)) {
			ret = -ERESTARTNOINTR;
			break;
		}
		schedule();
	}
	set_current_state(TASK_RUNNING);
	if (TASK_INTERRUPTIBLE == state) {
		sigprocmask(SIG_SETMASK, &oldset, NULL);
	}
	return ret;
}

static void __mark_deterministic_poisoned(struct task_struct *tsk, int kill) {
	struct task_struct *p;

	tsk->d_flags |= DET_POISON;
	/* Marking DET_S_EXCEPT tells the kernel to not remove the task_struct yet - this
	 * parent will want to know about this. TODO don't make recursive. */
	atomic_set(&tsk->d_status, DET_S_EXCEPT);
	list_for_each_entry(p, &tsk->children, sibling) {
		__mark_deterministic_poisoned(p, 0);
	}
	if (kill)
		zap_det_process(tsk, 0);
}

void mark_deterministic_poisoned(struct task_struct *tsk)
{
	__mark_deterministic_poisoned(tsk, 1);
}

static long set_blocked_signals(struct task_struct *tsk, unsigned long addr, size_t setsize)
{
	sigset_t __user *blocked = (sigset_t __user*)addr;
	sigset_t tmp;
	if (sizeof(sigset_t) != setsize)
		return -EINVAL;
	if (copy_from_user(&tmp, blocked, sizeof(sigset_t)))
		return -EFAULT;

	sigdelsetmask(&tmp, sigmask(SIGKILL)|sigmask(SIGSTOP));
	if (sigisemptyset(&tmp)) {
		tsk->d_flags &= ~DET_ALLOW_SIGNALS;
	} else {
		memcpy(&tsk->d_blocked, &tmp, sizeof(sigset_t));
		tsk->d_flags |= DET_CUSTOM_SIGNALS;
	}
	return 0;
}

/* Children who have died because of an exception (SIGSEGV, SIGILL, etc)
 * must be reaped by their parent explicitly. Similar to when a parent must
 * do a wait4() to actually release the associated task_struct object. */
static int wait_for_det_zombie(struct task_struct *tsk)
{
	/* Just use sys_wait4! Easy! */
	tsk->exit_signal = SIGCHLD;
	printk("RET IS %d\n", sys_wait4(tsk->pid, NULL, 0, NULL));
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
 *     * On errors (no memory, etc) the appropriate negative error number
 *       is set.
 *   When current is deterministic:
 *     * On success, the least significant 32-bits of the return value are
 *       important. Various bits are set (see determinism.h) indicating child
 *       status.
 *     * On any failure that is deterministically reproducible (eg. invalid
 *       arguments), an appropriate negative error number is returned.
 *
 *  Flags are a little complicated (just a little). The lowest order 8 bits are
 *  reserved to indicate what operation to perform. All remaining bits (24) are
 *  used to indicate various flags associated with the particular operation. The
 *  lowest 8 bits are reserved for operation specific flags, and the remaining
 *  16 bits (upper half) are used for global flags. See determinism.h for
 *  example flag macros.
 *
 */
SYSCALL_DEFINE6(dput, pid_t, child_dpid, unsigned long, flags, unsigned long, addr,
		size_t, size, unsigned long, dst, struct pt_regs *, regs)
{
	long ret;
	struct task_struct *child;
	int child_status;
	unsigned int operation;
	unsigned long opflags;
	
	operation = 0xff & flags;
	opflags = 0xff00 & flags;
	flags &= ~0xffffL;

	if (!operation)
		return -EINVAL;

	if (DET_BECOME_MASTER == operation) {
		if (is_deterministic_or_master(current))
			return -EPERM;
		current->d_flags = DET_MASTER;
		return 0;
	}

	if (!is_deterministic_or_master(current)) {
		return -EPERM;
	}

	if (DET_ALLOW_SIGNALS == operation) {
		if (!is_master(current))
			return -EPERM;
		return set_blocked_signals(current, addr, size);
	}

	child = find_deterministic_child(current, child_dpid);

	if (!child) {
		/* We don't want a SIGCHLD signal when the child dies. */
		ret = do_dfork(0, regs->sp, regs, 0, NULL, NULL, &child);
		if (unlikely(ret < 0)) {
			/* TODO fault. */
			return -ENOMEM;
		}
		child->d_parent = current;
		child->d_pid = child_dpid;
		child->d_flags = DET_DETERMINISTIC;
		atomic_set(&child->d_status, DET_S_READY);
		sema_init(&child->d_sem, 1);
		spin_lock_init(&child->d_spinlock);
		child_status = DET_S_READY;
	} else {
		child_status = wait_for_child(child);
		if (-EINTR == child_status) {
			/* Return now to handle the signal. */
			return -EINTR;
		} else if (-ERESTARTNOINTR == child_status) {
			return restart_syscall();
		}
	}

	if (DET_S_READY != child_status) {
		/* This is the only way to kill an excepted child. */
		if (DET_KILL == operation && (opflags & DET_KILL_POISON) &&
				DET_S_EXCEPT == child_status) {
			wait_for_det_zombie(child);
			printk("DID WAIT ZOMIB\n");
			return DET_S_EXCEPT_DEAD;
		}

		/* Can't work with a non-runnable child. Must have faulted or already exited
		 * cleanly. */
		return child_status;
	}

	ret = 0;
	switch (operation) {
		case DET_REGS:
			ret = deterministic_put_regs(child, (const void __user*)addr, opflags >> 8);
			if (ret)
				return ret;
			break;
		case DET_KILL:
			if (DET_START & flags)
				return -EINVAL;
			atomic_set(&child->d_status, DET_S_EXIT_NORMAL);
			child_status = DET_S_EXIT_NORMAL;
			zap_det_process(child, 0);
			break;
		case DET_GET_STATUS:
			break;
	}

	spin_lock(&child->d_spinlock);
	if (DET_START & flags) {
		atomic_set(&child->d_status, DET_S_RUNNING);
		wake_up_process(child);
		ret |= DET_S_RUNNING;
	} else {
		ret |= child_status;
	}
	spin_unlock(&child->d_spinlock);

	return ret;
}

SYSCALL_DEFINE6(dget, pid_t, child_dpid, unsigned long, flags, unsigned long, addr,
		size_t, size, unsigned long, dst, struct pt_regs *, regs)
{
	long ret;
	struct task_struct *child;
	int child_status;
	unsigned int operation;
	unsigned long opflags;
	
	operation = 0xff & flags;
	opflags = 0xff00 & flags;
	flags &= ~0xffffL;

	if (!operation)
		return -EINVAL;

	if (!is_deterministic_or_master(current)) {
		return -EPERM;
	}

	child = find_deterministic_child(current, child_dpid);

	if (!child) {
		return -ESRCH;
	}

	if (DET_GET_STATUS == operation && DET_DONT_WAIT & opflags) {
		if (!is_master(current))
			return -EPERM;
		return get_child_status(child);
	}

	child_status = wait_for_child(child);
	if (-EINTR == child_status) {
		/* Return now to handle the signal. */
		return -EINTR;
	} else if (-ERESTARTNOINTR == child_status) {
		return restart_syscall();
	}

	if (!(DET_S_READY == child_status)) {
		/* Can't work with a non-runnable child. Must have faulted or already exited
		 * cleanly. */
		return child_status;
	}

	ret = 0;
	switch (operation) {
		case DET_REGS:
			ret = deterministic_get_regs(child, (void __user*)addr, opflags >> 8);
			if (ret)
				return ret;
			break;
		case DET_GET_STATUS:
			break;
	}

	if (DET_START & flags) {
		atomic_set(&child->d_status, DET_S_RUNNING);
		wake_up_process(child);
		ret |= DET_S_RUNNING;
	} else {
		ret |= child_status;
	}

	return ret;
}

SYSCALL_DEFINE1(dret, struct pt_regs *, regs)
{
	DEFINE_WAIT(wait);

	if (!is_deterministic(current))
		return -EPERM;

	atomic_set(&current->d_status, DET_S_READY);
	wake_up_process(current->real_parent);
	for (;;) {
		set_current_state(TASK_STOPPED);
		if (DET_S_RUNNING == atomic_read(&current->d_status) ||
				fatal_signal_pending(current)) {
			break;
		}
		schedule();
	}
	set_current_state(TASK_RUNNING);

	return 0;
}

void zap_det_process(struct task_struct *tsk, int exit_code)
{
    tsk->signal->flags = SIGNAL_GROUP_EXIT;
    tsk->signal->group_exit_code = exit_code;
    tsk->signal->group_stop_count = 0;
    sigaddset(&tsk->pending.signal, SIGKILL);
    signal_wake_up(tsk, 1);
}

