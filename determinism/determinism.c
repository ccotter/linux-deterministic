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
#include <asm/mmu_context.h>

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

/* Caller must put_page() the returned struct page. */
static inline struct page *
pin_one_page(struct mm_struct *mm, unsigned long addr, int write)
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

	page = pin_one_page(mm, aligned, 1);
	if (!page)
		return -ENOMEM;

	preempt_disable();
	vaddr = kmap_atomic(page);
	vaddr += addr - aligned;
	memset(vaddr, 0, len);
	kunmap_atomic(vaddr);
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

	spage = pin_one_page(smm, aligned, 0);
	if (!spage)
		return -ENOMEM; /* ??? */
	dpage = pin_one_page(dmm, dst_aligned, 1);
	if (!dpage)
		goto put;

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

void print_vmas(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		printk("%lx %lx %lx\n", vma->vm_start, vma->vm_end, vma->vm_flags);
	}
}

static inline int __need_split(struct vm_area_struct *v1, struct vm_area_struct *v2)
{
	return
		(v1->vm_start < v2->vm_start && v2->vm_start < v1->vm_end) ||
		(v1->vm_start < v2->vm_end   && v2->vm_end   < v1->vm_end) ||
		(v2->vm_start < v1->vm_start && v1->vm_start < v2->vm_end);
}

/* Returns 0 if nothing was split, positive on a successful split,
 * and negative on error. */
static inline int _split_vma(struct mm_struct *mm, struct vm_area_struct *vma,
		unsigned long addr, int new_below)
{
	if (vma->vm_start < addr && addr < vma->vm_end) {
		int r = split_vma(mm, vma, addr, new_below);
		return r ? r : 1;
	}
	return 0;
	
}

static inline int can_do_vm_copy(struct task_struct *tsk,
		unsigned long addr, unsigned long end)
{
	struct mm_struct *mm = tsk->mm;
	struct vm_area_struct *vma;

	if (!is_master(tsk))
		return 1; /* Assumption is that purely deterministic processes will never
					 have "illegal" maps (e.g. VM_SHARED). */

	vma = find_vma(mm, addr);
	while (vma && vma->vm_start < end) {
		if (vma->vm_flags & VM_SHARED)
			return 0;
		vma = vma->vm_next;
	}
	return 1;

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

	/* Investigate likelyhood of deadlock TODO. Doubt it, since we have one of
	 * dmm or smm is stopped. */
	down_write(&dmm->mmap_sem);
	down_write_nested(&smm->mmap_sem, 1);

	if (!can_do_vm_copy(src, addr, end)) {
		ret = -EPERM;
		goto unlock;
	}

	start_page = PAGE_ALIGN(addr);
	end_page = LOWER_PAGE(end);

	/* Set start and end addresses to match the nearest matching vm_area_structs. */
	vma = find_vma(smm, addr);
	if (vma) {
		if (vma->vm_start > start_page) {
			dst_addr += vma->vm_start - addr;
			start_page = addr = vma->vm_start;
		}
	} else {
		ret = 0;
		goto unlock;
	}
	prev = NULL;
	while (vma) {
		if (vma->vm_start >= end) {
			if (!prev) {
				ret = 0;
				goto unlock;
			}
			if (prev->vm_end < end_page) {
				dst_end += prev->vm_end - end;
				end_page = end = prev->vm_end;
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

	/* Do we need to split the source VMAs? */
	vma = find_vma(smm, lowest);
	if (vma && vma->vm_start < lowest) {
		if (_split_vma(smm, vma, lowest, 1) < 0)
			goto unlock;
	}
	vma = find_vma(smm, addr);
	if (vma && vma->vm_start < start_page) {
		if (_split_vma(smm, vma, start_page, 1) < 0)
			goto unlock;
	}
	vma = find_vma(smm, end);
	if (vma && vma->vm_start < end_page) {
		if (_split_vma(smm, vma, end_page, 1) < 0)
			goto unlock;
	}
	vma = find_vma(smm, highest);
	if (vma && vma->vm_start < highest) {
		if (_split_vma(smm, vma, highest, 1) < 0)
			goto unlock;
	}

	/* First, unmap destination. Only unmap page aligned subregion.
	 * Then map VMAs to match those of the source. */
	if (dst_end_page != dst_start_page) {
		if (unlikely(do_munmap(dmm, dst_start_page, dst_end_page - dst_start_page)))
			goto unlock;
	}

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
		unsigned long len = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

		if (!may_expand_vm(dst, dmm, len))
			goto flush;

		/* dup_one_vma does VM accounting and increases map_count.
		 * TODO what about security_vm_enough_memory() */
		if (dup_one_vma(dmm, smm, vma, dst_off, NULL, NULL, NULL, NULL))
			goto flush;

		dmm->total_vm += len;
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

/* See exec_mmap. */
static inline int drop_mm(struct task_struct *tsk, struct mm_struct *mm, struct mm_struct *refmm)
{
	struct mm_struct *oldmm, *active_mm, *oldref = NULL;

	oldmm = tsk->mm;
	sync_mm_rss(tsk, oldmm); /* TODO what is this? */
	mm_release(tsk, oldmm);

	if (oldmm) {
		down_read(&oldmm->mmap_sem);
		if (unlikely(oldmm->core_state)) {
			up_read(&oldmm->mmap_sem);
			mmput(mm);
			mmput(refmm);
			return -EINTR;
		}
	}
	task_lock(tsk);
	if (tsk->mm != tsk->active_mm) {
		/* Why not??? */
		task_unlock(tsk);
		mmput(mm);
		mmput(refmm);
		WARN(1, "mm != active_mm pid=%d\n", tsk->pid);
		return -EAGAIN;
	}
	active_mm = tsk->active_mm;
	tsk->mm = tsk->active_mm = mm;
	oldref = tsk->snapshot_mm;
	tsk->snapshot_mm = refmm;
	/* TODO oom_disable_count */
	task_unlock(tsk);

	if (oldref)
		mmput(oldref); /* TODO will this work? */
	arch_pick_mmap_layout(mm);

	if (oldmm) {
		up_read(&oldmm->mmap_sem);
		BUG_ON(active_mm != oldmm);
		mm_update_next_owner(oldmm);
		mmput(oldmm);
		return 0;
	}
	mmdrop(active_mm);
	return 0;
}

/* See s390_enable_sie. */
static int do_snapshot(struct task_struct *tsk)
{
	struct mm_struct *mm, *ref;

	mm = dup_mm(tsk);
	if (!mm)
		return -ENOMEM;
	ref = dup_mm(tsk);
	if (!ref) {
		mmput(mm);
		return -ENOMEM;
	}

	if (atomic_read(&tsk->mm->mm_users) > 1) {
		/* This should NOT happen, since we don't allow multi-threading. Notify
		 * with a message and return. */
		task_unlock(tsk);
		mmput(ref);
		mmput(mm);
		WARN(1, "Cannot do SNAPSHOT! mm_users=%d>1\n", atomic_read(&tsk->mm->mm_users));
		return -EAGAIN;
	}
	return drop_mm(tsk, mm, ref);
	return 0;
}

/* Ensure VMAs match up at boundaries. Returns 0 iff success, -ENOMEM otherwise.
 * Enter with both mmap_sem writes held. */
static int prepare_merge(struct mm_struct *dmm, struct mm_struct *smm,
unsigned long addr, unsigned long end)
{
	struct vm_area_struct *svma, *dvma;

	svma = find_vma(smm, addr);
	dvma = find_vma(dmm, addr);
	while (svma && dvma && svma->vm_start < end) {
		int rc, next = 1;
		while (dvma && dvma->vm_end <= svma->vm_start)
			dvma = dvma->vm_next;
		if (!dvma)
			return 0;
		if ((rc = _split_vma(smm, svma, dvma->vm_start, 1))) {
			if (rc > 0)
				next = 0;
			else
				return rc;
		}
		if ((rc = _split_vma(dmm, dvma, svma->vm_start, 1)) < 0)
			return rc;
		if ((rc = _split_vma(smm, svma, dvma->vm_end, 1))) {
			if (rc > 0)
				next = 0;
			else
				return rc;
		}
		if ((rc = _split_vma(dmm, dvma, svma->vm_end, 1)) < 0)
			return rc;
		if (next)
			svma = svma->vm_next;
	}
	return 0;
}

static int
manually_merge(struct task_struct *dst,
		struct mm_struct *dmm, struct mm_struct *smm,
		struct mm_struct *rmm, unsigned long addr, unsigned long len)
{
	struct vm_area_struct *vma;
	unsigned long prot, aligned;
	struct page *dpage, *spage, *rpage;
	unsigned char *daddr, *saddr, *raddr;
	int ret = -ENOMEM;

	aligned = LOWER_PAGE(addr);
	/* Ensure source mapped. */
	vma = find_vma(smm, addr);
	if (!vma || vma->vm_start > addr)
		return 0;

	/* Do we need to map destination? */
	prot = vma->vm_flags & (VM_READ|VM_WRITE|VM_EXEC);
	vma = find_vma(dmm, addr);
	if (!vma || vma->vm_start > addr) {
		unsigned long rc = do_mmap_pgoff_tsk(dst, NULL, aligned, PAGE_SIZE,
				prot, DET_MAP_FLAGS, 0);
		if (aligned != rc)
			return -ENOMEM; /* ??? */
	}

	spage = pin_one_page(smm, aligned, 0);
	if (!spage)
		return -ENOMEM; /* ??? */
	dpage = pin_one_page(dmm, aligned, 1);
	if (!dpage)
		goto put;
	rpage = pin_one_page(rmm, aligned, 0);
	if (!rpage) {
		rpage = ZERO_PAGE(0);
		get_page(rpage);
	}

	/* Now that we have the pages, become atomic and map the pages.
	 * Atomic mappings always succeed. */
	preempt_disable();
	daddr = kmap_atomic(dpage);
	saddr = kmap_atomic(spage);
	raddr = kmap_atomic(rpage);
	ret = merge_mapped_range(daddr, saddr, raddr, addr - aligned, len);
	kunmap_atomic(raddr);
	kunmap_atomic(saddr);
	kunmap_atomic(daddr);
	preempt_enable();

	put_page(rpage);

	/* TODO how do we do this correctly? */
	if (1 == ret) {
		set_page_dirty_lock(dpage);
		ret = 0;
	}
	put_page(dpage);

put:
	put_page(spage);
	return ret;
}

static int do_merge(struct task_struct *dst, struct task_struct *src,
		unsigned long addr, unsigned long len)
{
	int ret = -ENOMEM;
	struct mm_struct *dmm = dst->mm;
	struct mm_struct *smm = src->mm;
	struct mm_struct *rmm = src->snapshot_mm;
	unsigned long end = addr + len;
	unsigned long start_page, end_page;
	struct vm_area_struct *svma, *dvma;

	if (!rmm) {
		return -EPERM;
	}

	/* Investigate likelyhood of deadlock TODO. Doubt it, since we have one of
	 * dmm or smm is stopped. */
	down_write(&dmm->mmap_sem);
	down_write_nested(&smm->mmap_sem, 1);
	/* No need to lock rmm->mmap_sem, but we do anyway for the sake of
	 * being consistent with other code paths who might in the future, for some
	 * unknown reason, operate on the mm. Currently, NO other piece of code
	 * possible works on snapshot_mm. */
	down_write_nested(&rmm->mmap_sem, 2);

	if (unlikely(prepare_merge(dmm, smm, addr, end)))
		goto unlock;

	start_page = PAGE_ALIGN(addr);
	end_page = LOWER_PAGE(end);

	if (start_page > end_page) {
		ret = manually_merge(dst, dmm, smm, rmm, addr, len);
		goto unlock;
	}

	if (addr < start_page) {
		ret = manually_merge(dst, dmm, smm, rmm, addr, start_page - addr);
		if (ret)
			goto unlock;
	}

	if (end_page < end) {
		ret = manually_merge(dst, dmm, smm, rmm, end_page, end - end_page);
		if (ret)
			goto unlock;
	}

	/* Ready to merge by examining page tables. */
	addr = start_page;
	end = end_page;
	ret = -ENOMEM;

	flush_cache_mm(smm); /* TODO */
	flush_cache_mm(dmm);

	svma = find_vma(smm, addr);
	dvma = find_vma(dmm, addr);
	while (svma && (svma->vm_start < end)) {
		unsigned long local_start, local_end;

		WARN(__need_split(dvma, svma),
				"do_merge(): Overlapping VMAs [%lx %lx] [%lx %lx]",
				dvma->vm_start, dvma->vm_end, svma->vm_start, svma->vm_end);

		if (dvma->vm_start != svma->vm_start) {
			if (!may_expand_vm(dst, dmm, len))
				goto flush;

			/* dup_one_vma does VM accounting and increases map_count.
			 * TODO what about security_vm_enough_memory() */
			if (unlikely(dup_one_vma(dmm, smm, svma, 0, NULL, NULL, NULL, NULL)))
				goto flush;

			dmm->total_vm += len;
			dvma = dvma->vm_next;
			continue;
		}

		if (svma->vm_start != dvma->vm_start || svma->vm_end != dvma->vm_end) {
			printk("  %d: VMAs not aligned! [%lx, %lx] [%lx, %lx]\n", __LINE__,
					dvma->vm_start, dvma->vm_end, svma->vm_start, svma->vm_end);
			ret = -EINVAL;
			goto flush;
		}

		/* TODO I don't think I need to anon_vma_prepare(dvma), but my old code had
		 * this. AFAIK, merge_page_range will, at most, copy PTEs into the
		 * destination, but won't allocate new pages. Only the allocation of new
		 * pages needs dvma's anon_vma structures. */

		local_start = svma->vm_start < addr ? addr : svma->vm_start;
		local_end = svma->vm_end > end ? end : svma->vm_end;
		/* Ok, we have aligned VMAs, so walk the page tables. */
		if (unlikely(ret = merge_page_range(dst, src, dvma, svma, rmm,
						local_start, local_end)))
			goto flush;
		svma = svma->vm_next;
		dvma = dvma->vm_next;
	}
	ret = 0;

flush:
	flush_tlb_all(); /* TODO */
unlock:
	up_write(&rmm->mmap_sem);
	up_write(&smm->mmap_sem);
	up_write(&dmm->mmap_sem);
	return ret;
}

/*
 *
 * We need the 6th argument to be pt_regs so that we can properly perform
 * do_dfork. Typical syscalls (eg. write) don't save an entire stack frame.
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
 *  Flags are a little complicated (just a little). The lowest order 16 bits are
 *  reserved to indicate what operations to perform. All remaining bits (16) are
 *  used to indicate various flags associated with the particular operation. The
 *  lowest 8 bits are reserved for operation specific flags, and the remaining
 *  8 bits (upper half) are used for global flags. See determinism.h for
 *  example flag macros.
 *
 */
SYSCALL_DEFINE6(dput, pid_t, child_dpid, unsigned long, flags, unsigned long, addr,
		size_t, size, unsigned long, child_addr, struct pt_regs *, regs)
{
	long ret;
	struct task_struct *child;
	int child_status;
	unsigned int operation;
	unsigned long opflags;

	operation = 0xffff & flags;
	opflags = 0xff0000 & flags;
	flags &= ~0xffffL;

	if (!is_valid_det_op(operation))
		return -EINVAL;

	if (DET_BECOME_MASTER == operation) {
		if (is_deterministic(current))
			return -EACCES;
		else if (is_master(current))
			return 0;
		else if (!can_become_master(current))
			return -EPERM;

		current->d_flags = DET_MASTER;
		return 0;
	}

	if (!is_deterministic_or_master(current)) {
		return -EPERM;
	}

	if (DET_ALLOW_SIGNALS == operation) {
		if (!is_master(current))
			return -EACCES;
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
		child->snapshot_mm = NULL;
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
	if (operation & DET_KILL) {
		if (DET_START & flags)
			return -EINVAL;
		atomic_set(&child->d_status, DET_S_EXIT_NORMAL);
		child_status = DET_S_EXIT_NORMAL;
		zap_det_process(child, 0);
		forget_det_child(child);
	} else {
		unsigned int is_memory_op = (DET_SNAP | DET_VM_ZERO | DET_VM_COPY) & operation;
		if (is_memory_op != (is_memory_op & -is_memory_op)) {
			return -EINVAL;
		}
		if (DET_SNAP & operation) {
			ret = do_snapshot(child);
			if (ret)
				return ret;
		} else if (DET_VM_COPY & operation) {
			ret = do_vm_copy(child, current, child_addr, addr, size);
			if (ret)
				return ret;
		} else if (DET_VM_ZERO & operation) {
			ret = do_vm_zero(child, addr, size, opflags >> 16);
			if (ret)
				return ret;
		}
		if (DET_REGS & operation) {
			ret = deterministic_put_regs(child, (const void __user*)addr, opflags >> 16);
			if (ret)
				return ret;
		}
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
		size_t, size, unsigned long, child_addr, struct pt_regs *, regs)
{
	long ret;
	struct task_struct *child;
	int child_status;
	unsigned int operation;
	unsigned long opflags;

	operation = 0xffff & flags;
	opflags = 0xff0000 & flags;
	flags &= ~0xffL;

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
	unsigned int is_memory_op = (DET_VM_COPY | DET_MERGE) & operation;
	if (is_memory_op != (is_memory_op & -is_memory_op)) {
		return -EINVAL;
	}
	if (DET_VM_COPY & operation) {
		ret = do_vm_copy(current, child, addr, child_addr, size);
		if (ret)
			return ret;
	} else if (DET_MERGE & operation) {
		ret = do_merge(current, child, addr, size);
		if (ret)
			return ret;
	}
	if (DET_REGS & operation) {
		ret = deterministic_get_regs(child, (void __user*)addr, opflags >> 16);
		if (ret)
			return ret;
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
	if (tsk->exit_state)
		return;
	tsk->signal->flags = SIGNAL_GROUP_EXIT;
	tsk->signal->group_exit_code = exit_code;
	tsk->signal->group_stop_count = 0;
	sigaddset(&tsk->pending.signal, SIGKILL);
	signal_wake_up(tsk, 1);
}

