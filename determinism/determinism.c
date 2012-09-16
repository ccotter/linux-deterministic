/*
 *  determinism/determinism.c
 *
 *  Kernel deterministic system calls (dput, dget and dret).
 *
 *  See "Efficient System-Enforced Deterministic Parallelism."
 *  (http://dedis.cs.yale.edu/2010/det/papers/osdi10.pdf)
 *
 * Author: Chris Cotter <ccotter@utexas.edu>
 *
 * See determinisim/LIMITATIONS for a list of limitations of this
 * implementation.
 *
 */

#include <linux/determinism.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/regset.h>
#include <linux/mman.h>
#include <asm/tlb.h>
#include <linux/highmem.h>
#include <linux/rmap.h>

#include <asm/syscall.h>

#define DET_MAP_FLAGS (MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS)
#define LOWER_PAGE(addr) PAGE_ALIGN((addr) + 1 - PAGE_SIZE)

/* Returns whether or not a process can become a master of a deterministic
 * process group. */
static int can_become_master(struct task_struct *tsk)
{
	struct mm_struct *mm = tsk->mm;
	struct vm_area_struct *vma;
	int ret = 0;

	/* Scan memory mappings to ensure none can be mergeable for KSM.
	 * Also check for HUGETLB mappings. */
	down_read(&mm->mmap_sem);
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		if (vma->vm_flags & (VM_HUGETLB | VM_MERGEABLE))
			goto ret;
	}
	ret = 1;

ret:
	up_read(&mm->mmap_sem);
	return ret;
}

static inline int get_child_status(struct task_struct *child)
{
	return atomic_read(&child->d_status);
}
static struct task_struct *
find_deterministic_child(struct task_struct *tsk, pid_t dpid)
{
	struct task_struct *p, *found = NULL;
	read_lock(&tasklist_lock);
	/* O(N) runtime, very slow. TODO make faster */
	list_for_each_entry(p, &tsk->children, sibling) {
		if (dpid == p->d_pid && tsk == p->parent) {
			found = p;
			goto ret;
		}
	}
ret:
	read_unlock(&tasklist_lock);
	return found;
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
	memcpy(&tsk->d_blocked, &tmp, sizeof(sigset_t));
	tsk->d_flags |= DET_CUSTOM_SIGNALS;
	return 0;
}

/* Children who have died because of an exception (SIGSEGV, SIGILL, etc)
 * must be reaped by their parent explicitly. Similar to when a parent must
 * do a wait4() to actually release the associated task_struct object. */
static int wait_for_det_zombie(struct task_struct *tsk)
{
	/* Just use sys_wait4! Easy! */
	tsk->exit_signal = SIGCHLD;
	return sys_wait4(tsk->pid, NULL, 0, NULL);
}

/* Caller must kunmap_atomic() the mapped address. */
static inline void *pin_one_page_atomic(struct mm_struct *mm,
		unsigned long addr, int write, struct page **apage)
{
	struct page *page;
	int ret = get_user_pages(NULL, mm, addr, 1 /* npages=1 */, write,
			write /* force */, &page, NULL);
	if (apage)
		*apage = page;
	if (ret > 0) {
		return kmap_atomic(page);
	} else {
		return NULL;
	}
}

static inline struct page *pin_one_page_atomic_(struct mm_struct *mm,
		unsigned long addr, int write)
{
	struct page *page;
	int ret = get_user_pages(NULL, mm, addr, 1 /* nrpages=1*/, write,
			write /* force */, &page, NULL);
	return ret > 0 ? page : NULL;
}

/* Assumes [addr, addr+len) is a subset of a single page.
 * Returns 0 on success, otherwise a negative error code. This function will map a page if a mapping doesn't
 * already exist. */
static inline int manually_zero(struct task_struct *tsk, unsigned long addr,
		unsigned long len, unsigned long prot)
{
	unsigned long aligned;
	void *vaddr;
	struct mm_struct *mm = tsk->mm;
	struct page *page;
	struct vm_area_struct *vma;

	vma = find_vma(mm, addr);
	aligned = LOWER_PAGE(addr);
	if (!vma || vma->vm_start > addr) {
		/* Map the region ourselves. */
		unsigned long rc = do_mmap_pgoff_tsk(tsk, NULL, aligned, PAGE_SIZE, prot,
				DET_MAP_FLAGS, 0);
		if (rc != aligned)
			return -ENOMEM; /* ??? */
		else
			return 0;
	}

	page = pin_one_page_atomic_(mm, aligned, 1);
	if (!page)
		return -ENOMEM;

	preempt_disable();
	vaddr = kmap_atomic(page);
	vaddr += addr - aligned;
	memset(vaddr, 0, len);
	preempt_enable();

	put_page(page);
	return 0;
}

/* Supports arbitrary start and end addresses.
 *
 * This function will zero out non page aligned regions of space using memset.
 * The page aligned sub region will be mmap()ed. This has the effect of
 * 1) unmapping any existing old regions and 2) telling the kernel to assign
 * zero page frames via demand paging. Thus, this function only clears old
 * page tables, and does not allocate pages until demanded by the process.
 *
 * Returns 0 on success, otherwise a negative integer indicating the error. */
static int do_vm_zero(struct task_struct *tsk, unsigned long addr,
		unsigned long len, unsigned long prot)
{
	unsigned long start_page, end_page, end;
	int ret = 0;

	end = addr + len;
	start_page = PAGE_ALIGN(addr);
	end_page = LOWER_PAGE(end);

	down_write(&tsk->mm->mmap_sem);

	if (start_page > end_page) {
		ret = manually_zero(tsk, addr, len, prot);
		goto unlock;
	}

	if (addr < start_page) {
		/* Zero out pre page aligned region. */
		if (unlikely((ret = manually_zero(tsk, addr, start_page - addr, prot))))
			goto unlock;
	}

	if (end_page < end) {
		/* Zero out post page aligned region. */
		if (unlikely((ret = manually_zero(tsk, end_page, end - end_page, prot))))
			goto unlock;
	}

	if (start_page == end_page)
		goto unlock;

	/* Now remap the region. */
	addr = do_mmap_pgoff_tsk(tsk, NULL, start_page, end_page - start_page, prot,
			DET_MAP_FLAGS, 0);
	if (addr != start_page)
		ret = -ENOMEM; /* ??? */

unlock:
	up_write(&tsk->mm->mmap_sem);
	return ret;
}

/* Will map the region in destination if it is not already mapped.
 * Assumes a proper subset region strictly within a page. One of the boundaries
 * of the region is assumed to be page aligned.
 * Returns 0 iff success. */
static inline int manually_copy(struct task_struct *dst, struct task_struct *src,
		struct mm_struct *dmm, struct mm_struct *smm,
		unsigned long dst_addr, unsigned long addr, unsigned long len)
{
	struct vm_area_struct *vma;
	unsigned long prot;
	unsigned long aligned = LOWER_PAGE(addr);
	unsigned long dst_aligned = LOWER_PAGE(dst_addr);
	int ret = -ENOMEM, off;
	struct page *dpage, *spage;
	void *daddr, *saddr;

	/* Ensure source mapped. */
	vma = find_vma(smm, addr);
	if (!vma || vma->vm_start > addr)
		return 0;

	/* Do we need to map destination? */
	prot = vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC);
	vma = find_vma(dmm, dst_addr);
	if (!vma || vma->vm_start > dst_addr) {
		unsigned long ret = do_mmap_pgoff_tsk(dst, NULL, dst_aligned, PAGE_SIZE,
				prot, DET_MAP_FLAGS, 0);
		if (dst_aligned != ret)
			return -ENOMEM; /* ??? */
	}

	spage = pin_one_page_atomic_(smm, aligned, 0);
	if (!spage)
		return -ENOMEM; /* ??? */
	dpage = pin_one_page_atomic_(dmm, dst_aligned, 1);
	if (!dpage)
		goto put;

	/* TODO are we guaranteed the pages won't be swapped out from
	 * under us? I'm guessing so since we have a _count>0 on the
	 * page, but who knows for *sure*... */

	/* Now that we have the pages, become atomic and map the pages.
	 * Atomic mappings always succeed. */
	preempt_disable();
	saddr = kmap_atomic(spage);
	daddr = kmap_atomic(dpage);
	off = addr - aligned;
	memcpy(daddr + off, saddr + off, len);
	kunmap_atomic(daddr);
	kunmap_atomic(saddr);
	preempt_enable();

	/* TODO how do we do this correctly? */
	set_page_dirty_lock(dpage);
	put_page(dpage);
	ret = 0;

put:
	put_page(spage);
	return ret;
}

#define printK no_printk

void print_vmas(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		printK ("%lx %lx %lx\n", vma->vm_start, vma->vm_end, vma->vm_flags);
	}
}

int dup_one_vma(struct mm_struct *mm, struct mm_struct *oldmm,
		struct vm_area_struct *mpnt, unsigned long dst_off,
		struct vm_area_struct **prev, struct vm_area_struct ***pprev,
		struct rb_node ***rb_link, struct rb_node **rb_parent);

static inline int _split_vma(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long addr, int new_below)
{
	if (vma->vm_end != addr)
		return split_vma(mm, vma, addr, new_below);
	return 0;
}

/* Supports arbitrary start and end addresses.
 * Copies only regions mapped in source. Unmapped regions in the source
 * descriptor will be silently ignored.
 *
 * This function considers three subests of [addr, addr+len) that partition
 * [addr, addr+len). The first is the region starting from addr to the next
 * page aligned address (which might be addr itself). The second is the page
 * aligned region from the first page aligned address to the last page aligned
 * address within [addr, add+len). The third is the region starting from the
 * last page aligned address to addr+len-1. Any of the regions may be empty,
 * but at least one will be non empty assuming len>0.
 *
 * Region two will be first unmapped in the destination, then all mapped regions
 * in the source will be mapped identically in the destination via copy-on-write
 * with the same memory access permissions as the source.
 *
 * The first and third regions will be mapped only if they were previously not
 * mapped in the destination. If the regions were already mapped, then the
 * memory access permissions of those regions will be unchanged, but the memory
 * copied into the destination. Otherwise, the region will be mapped identically
 * into the destination, and the data copied via memcpy (not copy-on-write).
 * If we used COW, then we would actually copy more than the process asked.
 *
 * Returns 0 on success, otherwise a negative integer indicating the error. */
static int do_vm_copy(struct task_struct *dst, struct task_struct *src,
		unsigned long dst_addr, unsigned long addr, unsigned long len)
{
	int ret = -ENOMEM;
	struct mm_struct *dmm = dst->mm;
	struct mm_struct *smm = src->mm;
	unsigned long start_page, end_page, lowest, highest, dst_start_page, dst_end_page;
	unsigned long end = addr + len;
	unsigned long dst_end = dst_addr + len;
	struct vm_area_struct *vma, *prev;
	unsigned long dst_off = dst_addr - addr;

	if ((dst_addr - addr) & ~PAGE_MASK)
		return -EINVAL;

	/* Investigate likelyhood of deadlock TODO. Doubt it, since we have know one of
	 * dmm or smm is stopped. */
	down_write(&dmm->mmap_sem);
	down_write_nested(&smm->mmap_sem, SINGLE_DEPTH_NESTING);

	start_page = PAGE_ALIGN(addr);
	end_page = LOWER_PAGE(end);
	printK ("First ones are %lx %lx\n", start_page, end_page);

	/* Set start and end addresses to match the nearest matching vm_area_structs. */
	vma = find_vma(smm, addr);
	if (vma) {
		if (vma->vm_start > start_page) {
			unsigned long a1=start_page;
			unsigned long a2=dst_addr;
			dst_addr += vma->vm_start - addr;
			start_page = addr = vma->vm_start;
			printK ("%d: start_page=%lx (%lx) dst_addr=%lx (%lx)\n", __LINE__,
					start_page, a1, dst_addr, a2);
		}
	} else {
		printK ("%d: Completely missed\n",__LINE__);
		ret = 0;
		goto unlock;
	}
	prev = NULL;
	while (vma) {
		if (vma->vm_start >= end) {
			if (!prev) {
				printK ("%d: NO prev %lx %lx\n", __LINE__, vma->vm_start, end_page);
				ret = 0;
				goto unlock;
			}
			if (prev->vm_end < end_page) {
				unsigned long a1=end_page;
				unsigned long a2=dst_end;
				dst_end += prev->vm_end - end;
				end_page = end = prev->vm_end;
				printK ("%d: end_page=%lx (%lx) dst_end=%lx (%lx)\n", __LINE__,
						end_page, a1, dst_end, a2);
			}
			break;
		}
		prev = vma;
		vma = vma->vm_next;
	}

	lowest = LOWER_PAGE(addr);
	highest = PAGE_ALIGN(end);
	dst_start_page = PAGE_ALIGN(dst_addr);
	dst_end_page = LOWER_PAGE(dst_end);

	int didwe=0;
	printK ("OG\n");
	print_vmas(smm);
	/* Do we need to split the source VMAs? */
	vma = find_vma(smm, lowest);
	if (vma && vma->vm_start < lowest) {
		didwe=1;
		printK ("%d: split_vma %lx %lx %lx\n", __LINE__, vma->vm_start, lowest, vma->vm_end);
		if (_split_vma(smm, vma, lowest, 1))
			goto unlock;
	}
	vma = find_vma(smm, addr);
	if (vma && vma->vm_start < start_page) {
		didwe=1;
		printK ("%d: split_vma %lx %lx %lx\n", __LINE__, vma->vm_start, start_page, vma->vm_end);
		if (_split_vma(smm, vma, start_page, 1))
			goto unlock;
	}
	vma = find_vma(smm, end);
	if (vma && vma->vm_start < end_page) {
		didwe=1;
		printK ("%d: split_vma %lx %lx %lx\n", __LINE__, vma->vm_start, end_page, vma->vm_end);
		if (_split_vma(smm, vma, end_page, 1))
			goto unlock;
	}
	vma = find_vma(smm, highest);
	if (vma && vma->vm_start < highest) {
		didwe=1;
		printK ("%d: split_vma %lx %lx %lx\n", __LINE__, vma->vm_start, highest, vma->vm_end);
		if (_split_vma(smm, vma, highest, 1))
			goto unlock;
	}
	if (didwe) {
		printK ("After\n");
		print_vmas(smm);
	}

	/* First, unmap destination. Only unmap page aligned subregion.
	 * Then map VMAs to match those of the source. */
	if (dst_end_page != dst_start_page) {
		if (unlikely(do_munmap(dmm, dst_start_page, dst_end_page - dst_start_page)))
			goto unlock;
	}

	printK ("args(%lx,%lx,%lx,%lx)\n", addr,start_page,end_page,end);
	if (start_page > end_page) {
		ret = manually_copy(dst, src, dmm, smm, dst_addr, addr, len);
		goto unlock;
	}

	if (addr < start_page) {
		if (unlikely(ret = manually_copy(dst, src, dmm, smm,
						dst_addr, addr, start_page - addr)))
			goto unlock;
	}

	if (end_page < end) {
		if (unlikely(ret = manually_copy(dst, src, dmm, smm,
						dst_end_page, end_page, end - end_page)))
			goto unlock;
	}

	if (start_page == end_page)
		goto unlock;

	/* Now, copy page aligned region copy-on-write style. */
	addr = start_page;
	end = end_page;
	dst_addr = dst_start_page;
	dst_end = dst_end_page;
	ret = -ENOMEM;

	flush_cache_mm(smm); /* TODO */
	flush_cache_mm(dmm);

	vma = find_vma(smm, addr);
	while (vma && (vma->vm_start < end)) {
		struct vm_area_struct *dvma, *prev;
		unsigned long prot = vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC);
		unsigned long local_end = end < vma->vm_end ? end : vma->vm_end;
		unsigned long local_len = local_end - addr;
		struct rb_node **rb_link, *rb_parent;

		if (dup_one_vma(dmm, smm, vma, dst_off, NULL, NULL, NULL, NULL))
			goto flush;

		dst_addr += local_len;
		addr += local_len;
		vma = vma->vm_next;
	}
	ret = 0;

flush:
	flush_tlb_all(); /* TODO */
unlock:
	up_write(&smm->mmap_sem);
	up_write(&dmm->mmap_sem);

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

	if (!is_valid_det_op(operation))
		return -EINVAL;

	if (DET_BECOME_MASTER == operation) {
		if (is_deterministic_or_master(current))
			return -EPERM;
		/* TODO Check for invalid process attributes. Ex: hugetlb mappings. */
		if (!can_become_master(current)) {
			return -EPERM;
		}
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
		if (child_dpid < 0)
			return -EINVAL;

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
			/* Return now to handle the fatal signal. */
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
			forget_det_child(child);
			break;
		case DET_GET_STATUS:
			break;
		case DET_VM_ZERO:
			ret = do_vm_zero(child, addr, size, opflags >> 8);
			if (ret)
				return ret;
			break;
		case DET_VM_COPY:
			ret = do_vm_copy(child, current, dst, addr, size);
			if (ret)
				return ret;
			break;
	}

	BUG_ON(ret < 0 || (ret & 0xff));
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

	if (!is_valid_det_op(operation))
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
		/* Return now to handle the fatal signal. */
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

	BUG_ON(ret < 0 || (ret & 0xff));
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

