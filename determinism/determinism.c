/*
 *  linux/determinism/determinism.c
 *
 *  Kernel deterministic system calls (dput, dget and dret).

 *  See "Efficient System-Enforced Deterministic Parallelism."
 *  (http://dedis.cs.yale.edu/2010/det/papers/osdi10.pdf)
 *
 */

#include <linux/syscalls.h>

#include <linux/determinism.h>

SYSCALL_DEFINE5(dput, pid_t, child_dpid, long, flags, unsigned long, start,
		size_t, size, unsigned long, dst)
{
	long ret;
	struct list_head *list;
	struct task_struct *child;

	ret = 0;
	child = NULL;
	/* See if child even exists - O(N) runtime, very slow. TODO make faster */
	list_for_each(list, &current->children)
	{
		struct task_struct *tsk = list_entry(list, struct task_struct, sibling);
		if (child_dpid == tsk->d_pid && current == tsk->parent)
		{
			child = tsk;
			break;
		}
	}

	if (NULL == child)
	{
		/* TODO clearly assuming x86 pt_regs. */
		struct pt_regs *regs = task_pt_regs(current);
		ret = do_dfork(0, regs->sp, regs, 0, NULL, NULL, &child);
		if (unlikely(ret < 0))
		{
			child = NULL;
			ret = -1;
			goto ret;
		}
		printk("FORK just created %d %d\n",child->pid, current->pid);
		//child->snapshot_mm = NULL;
		child->d_pid = child_dpid;
		child->d_flags = DET_DETERMINISTIC;
		init_rwsem(&child->det_sem);
		atomic_set(&child->d_running, 2); /* TODO don't use 1, 2 ... */
		init_waitqueue_head(&child->det_rq);
	}
	else
	{
		printk("Child exists...\n");
	}

	if (DETERMINE_START & flags)
	{
		if (2 == atomic_read(&child->d_running))
		{
			atomic_set(&child->d_running, 1);
			wake_up_process(child);
		}
		else
		{
			atomic_set(&child->d_running, 1);
			wake_up_interruptible_nr(&child->det_rq, 1);
		}
	}


ret:
	return ret;
}

SYSCALL_DEFINE5(dget, pid_t, child_dpid, long, flags, unsigned long, start,
		size_t, size, unsigned long, dst)
{
	printk("IN DGET\n");
	return -1;
}

SYSCALL_DEFINE0(dret)
{
	printk("IN DRET\n");
	return -1;
}

