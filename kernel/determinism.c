/*
 *  linux/kernel/determinism.c
 *
 *  Kernel deterministic system calls (dput, dget and dret).

 *  See "Efficient System-Enforced Deterministic Parallelism."
 *  (http://dedis.cs.yale.edu/2010/det/papers/osdi10.pdf)
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 */

#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <asm/io.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <asm/pgtable_types.h>
#include <linux/mman.h>
#include <linux/module.h>

#include <linux/determinism.h>

#define is_put_memory_op(flags) ((DETERMINE_ZERO_FILL | DETERMINE_VM_COPY) & \
        flags)
#define is_get_memory_op(flags) ((DETERMINE_MERGE | DETERMINE_ZERO_FILL | \
            DETERMINE_VM_COPY) & flags)
/* Aligns an address to the start address of the page in which the address
   occurs. */
#define LOWER_PAGE(addr) (PAGE_ALIGN((addr) - PAGE_SIZE + 1))

/* Debugging is easier if the compiler doesn't inline anything. */
#define _STATIC_F_
#define _WANT_INLINE_
#define PRINT_OFTEN(x)

/* TODO goes in header */

int do_brk_gen_mm(struct task_struct *, struct mm_struct *, unsigned long,
        unsigned long, unsigned long);

/* Forward declare various helper functions. */
_STATIC_F_ int clear_mmap(struct mm_struct *mm);
_STATIC_F_ int copy_entire(struct task_struct *dst_tsk,
        struct task_struct *src_tsk, struct mm_struct *mm);
_STATIC_F_ int copy_memory(struct task_struct *dst_tsk,
        struct task_struct *src_tsk, unsigned long dst_addr,
        unsigned long addr, size_t size, unsigned long prot_flags);
_STATIC_F_ int zero_fill_vm(struct task_struct *tsk,
        unsigned long addr, unsigned long end, unsigned long prot_flags);
_STATIC_F_ int merge(struct task_struct *dst_tsk, struct task_struct *src_tsk,
        struct mm_struct *ref_mm, unsigned long start, unsigned long end);
_STATIC_F_ int kill_task(struct task_struct *tsk);
_STATIC_F_ int wake_task(struct task_struct *tsk);
_STATIC_F_ unsigned long simple_map(struct mm_struct *mm, unsigned long addr,
        unsigned long len, unsigned long prot_flags);
_STATIC_F_ int make_anon(struct task_struct *tsk);

/* Declare debug functions. */
_STATIC_F_ void printtlb(struct mm_struct *mm, unsigned long addr,
        unsigned long end);
_STATIC_F_ void printvmas(struct mm_struct *mm);

/**
  Description of "deterministic put:"
  This function interacts with a child space of the parent (the calling task).
  The flags syscall argument determines what the kernel should do to the child.

  DETERMINE_START - The child space is put into the scheduler.

  DETERMINE_REGS - Copies the register state from the parent space into the
    child.

  DETERMINE_VM_COPY - Copies a range of virtual memory from the calling parent
    into the child.

  DETERMINE_SNAP - Specify a range of memory to send the child a snapshot.

  DETERMINE_BECOME_MASTER - The calling process becomes a "master" space.
    Master spaces has all the normal nondeterministic privileges as a "normal"
    linux process. Any children it creates via dput become deterministic.
    The children must have all their virtual memory mapped anonymously.

  DETERMINE_CLEAR_CHILD - Clears a child's entire memory map.

  DETERMINE_CHILD_STATUS - Sets a child's status (running, stopped, killed).

  The return value is defined as follows:
    1) On any failure, >0 is returned.
        1a) If the error is due to something non deterministic (out of memory,
            other timing dependencies), return TODO (something other than -1)
            -1. TODO We should actually fault the user program.
        1b) If the error is deterministic (the user gave incorrect parameters),
            then return a specific error code.
    2) On success, 1 is returned into the calling process (the parent).
    3) If the DETERMINE_REGS flag is set, then 1 will still be returned in the
        calling process (the parent). However, since registers are copied into
        the child, architecture specific techniques will alter register state
        to return 0 when the child returns.
  
  This return behavior emulates (in a determinstic fashion) fork return
    semantics.

  */
SYSCALL_DEFINE5(dput, pid_t, child_dpid,
        int, flags, unsigned long, start, size_t, size, unsigned long, dststart)
{
    struct task_struct *child;
    struct list_head *list;
    long ret = 0;
    PRINT_OFTEN(printk("Entering DPUT (%d) %08lx %08lx %08lx %08lx %08lx\n",
                current->pid,child_dpid,flags,start,size,dststart);)

    /* Validate arguments first. */
    if (
            (is_put_memory_op(flags) && (
                                     (start + size < start) ||
                                     (0 != ((PAGE_SIZE-1) &
                                            PAGE_ALIGN(dststart - start))))) ||
            ((DETERMINE_BECOME_MASTER & flags) &&
             (DETERMINE_BECOME_MASTER != flags))
       )
    {
        printk(" is-memory %d size violation? %d\n", is_put_memory_op(flags),
                start + size < start);
        printk("FAilre on dput %d   %08lx %08lx %08lx\n",
                0 != (PAGE_SIZE & (PAGE_ALIGN(dststart - start))),
                PAGE_ALIGN(dststart - start),
                PAGE_SIZE,
                dststart-start);
        return -EINVAL;
    }

    if (DETERMINE_BECOME_MASTER & flags)
    {
        if (current->is_deterministic || current->is_master_space)
            return -EINVAL;
        /* TODO certain processes (ptraced, etc) can not become master either */
        current->flags &= ~PF_RANDOMIZE;
        current->personality |= ADDR_NO_RANDOMIZE;
        current->is_master_space = 1;
        init_rwsem(&current->det_sem);
        init_waitqueue_entry(&current->det_wait, current);
        INIT_LIST_HEAD(&current->det_wait.task_list);
        return 0;
    }

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

    /* Little flag to to some useful debugging on behalf of the user process
       during kernel development. */
    if (DETERMINE_DEBUG & flags)
    {
        if (1 == start)
            printvmas(current->mm);
        else if (2 == start && NULL != child)
            printvmas(child->mm);
        else if ((flags & 0x7000)== 0x5000)
            printtlb(current->mm, start, start+size);
        else if (child && ((flags&0x7000)== 0x6000))
            printtlb(child->mm, start, start+size);
        else if (((flags & 0x7000) == 0x7000) && (start==3))
        {
            list_for_each(list, &current->children)
            {
                struct task_struct *tsk = list_entry(list, struct task_struct,
                        sibling);
                printk("Child (%d) is %d (%08lx)\n", current->pid, tsk->pid,
                        tsk->state);
            }
        }
        else if (child && ((flags & 0x7000) == 0x7000) && (start==4))
        {
            list_for_each(list, &child->children)
            {
                struct task_struct *tsk = list_entry(list, struct task_struct,
                        sibling);
                printk("Child (%d) is %d (%08lx)\n", child->pid, tsk->pid,
                        tsk->state);
            }
        }
        printk("Returning from debug\n");
        return 0;
    }

    if (unlikely(!current->is_master_space && !current->is_deterministic))
    {
        printk("Must be master space or deterministic to use dput/dget/dret\n");
        return -1;
    }

    /* Create child if it doesn't exist. If it does exist, then make sure to
       synchronize with child calling dret. */
    if (NULL == child)
    {
        /* For now, we rely on do_fork essentially. */
        struct pt_regs *regs = task_pt_regs(current);
        ret = do_dfork(SIGCHLD, regs->sp, regs, 0, NULL, NULL, &child);
        if (unlikely(ret < 0))
        {
            child = NULL;
            ret = -1;
            goto ret;
        }
        PRINT_OFTEN(
                printk("FORK just created %d %d\n",child->pid, current->pid);)
        child->snapshot_mm = NULL;
        child->d_pid = child_dpid;
        child->is_deterministic = 1;
        init_rwsem(&child->det_sem);
        atomic_set(&child->d_running, 2);
        init_waitqueue_head(&child->det_rq);
        init_waitqueue_entry(&child->det_wait, child);
        INIT_LIST_HEAD(&child->det_wait.task_list);
        ret = 0;
        /* The child is initially waiting to run, so put it in its wait
           queue. */
        //add_wait_queue(&child->det_rq, &child->det_wait);
    }
    else
    {
        /*DEFINE_WAIT(wait);
        prepare_to_wait_exclusive(&child->det_rq, &wait, TASK_INTERRUPTIBLE);
        PRINT_OFTEN(printk("DPUT(%d) waiting on child ?=%d\n", current->pid,
                atomic_read(&child->d_running));)
        if (1 == atomic_read(&child->d_running))
        {
            printk("%d %d %d DPUT waiting\n", child_dpid, child->pid,
                    current->pid);
            schedule();
        }
        finish_wait(&child->det_rq, &wait);
        printk("%d %d %d DPUT finished waiting\n", child_dpid, child->pid,
                current->pid);
                */
        wait_event_interruptible(child->det_rq, 1 !=
                atomic_read(&child->d_running));
    }

    /* Can't work on dead children. */
    if (unlikely(0 != child->exit_state))
    {
        ret = DETERMINE_S_DEAD; /* distinguish between faults/normal exits */
        printk("DPUT Child %d-%d is already dead!(%08lx %08lx %08lx %08lx)\n",
                current->pid, child->pid, flags,start,size,dststart);
        goto ret;
    }

    /* What did the client ask us to do? */

    /* Copy register state. */
    if (DETERMINE_REGS & flags)
    {
        struct pt_regs *regs = task_pt_regs(current);
        struct pt_regs *cregs = task_pt_regs(child);
        *cregs = *regs;
        cregs->ax = 0; /* Child returns 0. TODO make architecture specific */
    }

    if (DETERMINE_CHILD_STATUS & flags)
    {
        if (DETERMINE_KILL & flags)
        {
            child->d_pid = -1;
            kill_task(child);
            ret = DETERMINE_S_DEAD;
            goto ret;
        }
    }

    if (DETERMINE_CLEAR_CHILD & flags)
    {
        struct mm_struct *mm = get_task_mm(child);
        down_write(&mm->mmap_sem);
        if (unlikely(clear_mmap(mm)))
        {
            printk("DPUT clear_mmap failed\n");
            ret = -1;
            up_write(&mm->mmap_sem);
            mmput(mm);
            goto ret;
        }
        up_write(&mm->mmap_sem);
        mmput(mm);
    }

    /* Copy memory from parent (current active space) into into child. */
    if (DETERMINE_VM_COPY & flags)
    {
        if (unlikely(copy_memory(child, current, dststart, start, size,
                        VM_DATA_DEFAULT_FLAGS)))
        {
            printk("DPUT copy_memory failed %08lx %08lx %08lx\n",
                    dststart,start,start+size);
            ret = -1;
            goto ret;
        }
    }

    /* Zero fill child's VM. */
    if (DETERMINE_ZERO_FILL & flags)
    {
        if (unlikely(zero_fill_vm(child, dststart, dststart + size,
                        VM_DATA_DEFAULT_FLAGS)))
        {
            ret = -1;
            goto ret;
        }
    }

    /* Begin snapshot. */
    if (DETERMINE_SNAP & flags)
    {
        int memRet;
        /* We need to basically clone the mm_struct into the child process,
           similar to dup_mmap. TODO locking, see copy_process */
        mmput(child->mm);

        /* This duplication will be for the child->snapshot_mm field. */
        memRet = copy_mm(SIGCHLD, child);
        if (memRet)
        {
            ret = -1;
            printk("copy_mm failed first %d\n", memRet);
            goto ret;
        }
        child->snapshot_mm = child->mm;

        /* This duplication is actually for the child's memory map. */
        memRet = copy_mm(SIGCHLD, child);
        if (memRet)
        {
            printk("copy_mm failed twice %d\n", memRet);
            ret = -1;
            goto ret;
        }
    }
    //printk("Child status is %08lx\n", child->state);

ret:
    if (0 == ret)
    {
        int started = 0;
        /* Start the process at the end of our logic so that all changes have
           taken place already (copying VM, etc). */
        if (DETERMINE_START & flags)
        {
            PRINT_OFTEN(printk("DPUT making run(%d-%d) %08lx %08lx %08lx "
                        "%08lx\n", current->pid,child->pid,flags,
                        start, dststart, size);)
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
            /* When the child is in a runnable state, the semaphore is held to
               until until the child calls dret(). */
            started = 1;
        }

        if (started)
            ret = DETERMINE_S_RUNNING;
        else
            ret = DETERMINE_S_READY;
    }
    PRINT_OFTEN(printk("Returning from DPUT(%d) ret= %d\n", current->pid, ret);)
    return ret;
}

/* Arguments:
   (1) child space (process) id.
   (2) allowable flags are DETERMINE_VM_COPY, DETERMINE_ZERO_FILL,
    DETERMINE_MERGE.
   (3) start is the first byte to copy.
   (4) size of virtual memory upon which to act.
   (5) destination address for DETERMINE_VM_COPY.

  DETERMINE_COPY_CHILD - This is sort of a special version of VM_COPY for the
    entire memory image of a process. We copy the entire memory mapping of
    a child into a process.

  DETERMINE_CHILD_STATUS - This gets the status of a child (is it runnning,
    stopped?). If this flag is specified, this can be the only flag since this
    option should immediately return the status of the child and not perform any
    operations that would otherwise block the caller.

   Return value follows these rules:
     1) If the child does not exist or the arguments are invalid, -EINVAL is
        returned.
     2) If the child has been killed (exception, or it exited), control flow
        immediately returns the status of the child.
     3) Control flow proceeds to perform the clients request
        (copy, merge, etc). On
        any error, -1 is returned. (TODO perhaps we should fault?).
     4) On success, the parent returns the status (>0) of the child.
    For child task status return codes, see linux/determinism.h

 */
SYSCALL_DEFINE5(dget, pid_t, child_dpid, int, flags, unsigned long, start,
        size_t, size, unsigned long, dststart)
{
    struct task_struct *child, *tsk;
    struct list_head *list;
    int ret = 1;
    int is_mem = is_get_memory_op(flags);
    //DEFINE_WAIT(wait);

    PRINT_OFTEN(printk("Entering DGET (%d) %08lx %08lx %08lx %08lx %08lx\n",
                current->pid,child_dpid,flags,start,size,dststart);)
    /* Disallow certain flags: */
    if (
            (is_mem && (start + size <= start ||
                                     (0 != ((PAGE_SIZE-1) &
                                            PAGE_ALIGN(dststart - start))))) ||
            (DETERMINE_REGS & flags))
    {
        return -EINVAL;
    }
    /* Disallow specific combination. */
    if ((DETERMINE_MERGE | DETERMINE_VM_COPY) == 
            ((DETERMINE_MERGE | DETERMINE_VM_COPY) & flags) ||
            ((DETERMINE_CHILD_STATUS & flags) && is_mem))
    {
        return -EINVAL; /* At most one of the above flags can be specified. */
    }

    child = NULL;
    /* See if child even exists - O(N) runtime, very slow. */
    list_for_each(list, &current->children)
    {
        tsk = list_entry(list, struct task_struct, sibling);
        if (child_dpid == tsk->d_pid)
        {
            child = tsk;
            break;
        }
    }
    if (NULL == child)
    {
        printk("Child %d does not exist.\n", child_dpid);
        ret = -EINVAL;
        goto ret;
    }

    /*
    prepare_to_wait_exclusive(&child->det_rq, &wait, TASK_INTERRUPTIBLE);
    while (1 == atomic_read(&child->d_running))
    {
        printk("%d %d %d DGET waiting\n", child_dpid, child->pid, current->pid);
        schedule();
    }
    finish_wait(&child->det_rq, &wait);
    printk("%d %d %d DGET finished waiting\n", child_dpid, child->pid,
            current->pid);
    */
    wait_event_interruptible(child->det_rq,
            1 != atomic_read(&child->d_running));

    if (DETERMINE_CHILD_STATUS & flags)
    {
        if (child->exit_state)
            ret = DETERMINE_S_DEAD;
        else if (TASK_RUNNING == child->state)
            ret = DETERMINE_S_RUNNING;
        else
            ret = DETERMINE_S_READY;
        goto ret;
    }

    /* See if the child is in a valid state. If not, go to the end
       immediately. */
    if (child->exit_state)
    {
        /* For now, we don't distinguish between a child that faulted and one
           that exited gracefully. TODO We haven't devised a strategy for
           dealing with faults, though it shouldn't be too difficult or
           complex to do so. */
        ret = DETERMINE_S_DEAD;
        printk("DGET Child %d-%d is already dead!(%08lx %08lx %08lx %08lx)\n",
                current->pid, child->pid, flags,start,size,dststart);
        goto ret;
    }

    if (DETERMINE_COPY_CHILD & flags)
    {
        if (unlikely(copy_entire(current, child, current->mm)))
        {
            printk("copy_entire failed\n");
            ret = -1;
            goto ret;
        }
    }

    if (DETERMINE_MERGE & flags)
    {
        struct mm_struct *ref_mm;
        int rc;

        /* We get a pointer to child->snapshot_mm and increment the user count.
           This is accomlpished by replicatoing get_task_mm. */
        ref_mm = child->snapshot_mm;

        rc = merge(current, child, ref_mm, start, start + size);
        /* By assumption, if ref_mm is not null, when we decrement the mm_users
           count, there is no possibility it will be zero afterwards. */
        if (rc > 0)
        {
            printk("Merge failed %d\n", rc);
            ret = -1;
            goto ret;
        }
        else if (rc < 0)
        {
            /* Out of memory or something of the like. */
            ret = -1;
            goto ret;
        }
    }

    /* Copy virtual memory area from child into parent. */
    if (DETERMINE_VM_COPY & flags)
    {
        if (copy_memory(current, child, dststart, start, size,
                    VM_DATA_DEFAULT_FLAGS))
        {
            //printk("copy_memory failed DGET %08lx %08lx %08lx\n",dststart,
                    //start,start+size);
            ret = -1;
            goto ret;
        }
    }

    /* Zero fill a region in the current process. */
    if (DETERMINE_ZERO_FILL & flags)
    {
        if (zero_fill_vm(current, dststart, dststart + size,
                    VM_DATA_DEFAULT_FLAGS))
        {
            ret = -1;
            goto ret;
        }
    }

ret:

    if (1 == ret)
    {
        ret = DETERMINE_S_READY;
        if (DETERMINE_START & flags)
        {
            /* This should be the last action taken. */
            PRINT_OFTEN(printk("DGET making run(%d-%d) %08lx %08lx %08lx "
                        "%08lx\n", current->pid,child->pid,flags, start,
                        dststart, size);)
            atomic_set(&child->d_running, 1);
            wake_up_interruptible_nr(&child->det_rq, 1);
            ret = DETERMINE_S_RUNNING;
        }
    }
    PRINT_OFTEN(printk("Returned FROM DGET(%d) %d\n",current->pid,ret);)
    return ret;
}

/* Child calls this to sync with its parent. */
SYSCALL_DEFINE0(dret)
{
    struct task_struct *parent;
    int parent_waiting;
    DEFINE_WAIT(wait);
    PRINT_OFTEN(printk("Entering DRET\n");)

    if (!current->is_deterministic)
    {
        printk("current DRET bad %d\n", current->pid);
        return -EPERM;
    }

    parent = current->real_parent;
    /*get_task_struct(parent);
    if (!(parent->is_deterministic || parent->is_master_space) ||
            parent->exit_state)
    {
        / * This child should be killed immediately. TODO * /
        put_task_struct(parent);
        return -1;
    }
    */
/*
    printk("%d %d %d DRET stopping\n", current->d_pid, current->pid,
            parent->pid);
    atomic_set(&current->d_running, 0);
    parent_waiting = waitqueue_active(&current->det_rq);
    PRINT_OFTEN(printk("DRET(%d) about to finish pwait=%d\n", current->pid,
                parent_waiting);)
    prepare_to_wait_exclusive(&current->det_rq, &wait, TASK_INTERRUPTIBLE);
    / * Wake up the parent before we go to sleep. * /
    if (parent_waiting)
    {
        printk("%d %d %d DRET waking parent\n", current->d_pid, current->pid,
                parent->pid);
        wake_up_interruptible_nr(&current->det_rq, 1);
    }
    schedule();
    finish_wait(&current->det_rq, &wait);
    printk("%d %d %d DRET waking\n", current->d_pid, current->pid, parent->pid);
    PRINT_OFTEN(printk("Leaving DRET\n");)
        */
    atomic_set(&current->d_running, 0);
    wake_up_interruptible_nr(&current->det_rq, 1);
    wait_event_interruptible(current->det_rq, 1 ==
            atomic_read(&current->d_running));

    return 0;
}

/* Should only be called on deterministic tasks. This will notify the parent
   when a task is being killed. Also, all children must be killed. */
extern void
deterministic_notify_parent(struct task_struct *tsk)
{
    struct list_head *list;
    struct task_struct *parent = tsk->real_parent;
    int Q;
    atomic_set(&tsk->d_running, 0);
    PRINT_OFTEN(printk("Task is dying %d-%d\n", tsk->pid, parent->pid);)
    if (tsk->is_deterministic)
        wake_up_interruptible_nr(&tsk->det_rq, 1);
    /* Now kill children. */
    list_for_each(list, &tsk->children)
    {
        struct task_struct *t = list_entry(list, struct task_struct, sibling);
        if (t->exit_state)
            continue;
        kill_task(t);
    }
}
EXPORT_SYMBOL(deterministic_notify_parent);

/* /////////////////////////////////////
 * Static helper functions.
 * ///////////////////////////////////// */

/* Call with mmap_sem held. */
_STATIC_F_ int
clear_mmap(struct mm_struct *mm)
{
    struct vm_area_struct *vma, *tmp;
    int rc = 0;

    for (vma = mm->mmap; vma; )
    {
        unsigned long A=vma->vm_start;
        unsigned long B=vma->vm_end;
        tmp = vma->vm_next;
        if (unlikely(rc = do_munmap(mm, vma->vm_start,
                        vma->vm_end - vma->vm_start)))
        {
            printk("clear_mmap failed %d %08lx %08lx\n", rc, A, B);
            break;
        }
        vma = tmp;
    }

    return rc;
}

_STATIC_F_ int
copy_entire(struct task_struct *dst_tsk, struct task_struct *src_tsk, struct
        mm_struct *mm)
{
    struct mm_struct *src_mm;
    struct vm_area_struct *vma;
    int ret = 0;

    //mm = get_task_mm(dst_tsk);
    src_mm = get_task_mm(src_tsk);
    down_write(&mm->mmap_sem);
    down_write(&src_mm->mmap_sem);

    if (unlikely(ret = clear_mmap(mm)))
        goto unlock;

    ret = -ENOMEM;
    flush_cache_mm(mm);
    for (vma = src_mm->mmap; vma; vma = vma->vm_next)
    {
        int rc = do_brk_gen_mm(dst_tsk, mm, vma->vm_start,
                vma->vm_end - vma->vm_start,
                vma->vm_flags & VM_DATA_DEFAULT_FLAGS);
        if (unlikely(vma->vm_start != rc))
        {
            printk("copy_entire failed on %08lx %08lx\n", vma->vm_start,
                    vma->vm_end);
            goto unlock;
        }
        if (unlikely(rc = copy_page_range_dst(mm, src_mm, vma,
                        vma->vm_start, vma->vm_start, vma->vm_end)))
        {
            printk("copy_entire failed twice on %08lx %08lx\n", vma->vm_start,
                    vma->vm_end);
            goto unlock;
        }
    }
    ret = 0;

unlock:
    //flush_tlb_mm(mm);
    flush_tlb_all();

    up_write(&src_mm->mmap_sem);
    up_write(&mm->mmap_sem);
    mmput(src_mm);
    //mmput(mm);
    return ret;
}

_STATIC_F_ _WANT_INLINE_ int
kill_task(struct task_struct *tsk)
{
    /* this is definitely bad - need a spinlock */
    PRINT_OFTEN(printk("kill_task %d %08lx %08lx\n", tsk->pid, tsk->blocked,
                sigismember(&tsk->blocked, SIGKILL));)
    send_sig_info(SIGKILL, SEND_SIG_FORCED, tsk);
    return 0;
}

_STATIC_F_ _WANT_INLINE_ int
wake_task(struct task_struct *tsk)
{
    wake_up_process(tsk);
    return 0;
}

/* Caller must kunmap the mapped page. */
_STATIC_F_ void *
pin_one_page(struct task_struct *tsk, struct mm_struct *mm, unsigned long addr,
        int write, struct page **page)
{
    int ret;
    ret = get_user_pages(tsk, mm, addr, 1 /* npages=1 */, write,
            write /* force */, page, NULL);
    if (ret > 0)
        return kmap(*page);
    return NULL;
}

/* Manually (via memset) sub page virtual memory regions. Assumes
   [addr, end) is contained in one page. Returns 0 on success. */
_STATIC_F_ int
manuallyZero(struct task_struct *tsk, unsigned long addr, unsigned long end,
        unsigned long prot_flags, int force_map)
{
    unsigned long aligned;
    void *vaddr;
    struct mm_struct *mm = get_task_mm(tsk);
    struct vm_area_struct *vma;
    struct page *page;
    int ret = 0;

    vma = find_vma(mm, addr);
    if (!vma || vma->vm_start > addr)
    {
        unsigned long rc;

        if (!force_map)
        {
            ret = -EINVAL; /* Region is not mapped so we can't zero it. */
            goto ret;
        }

        addr = LOWER_PAGE(addr);
        rc = do_brk_gen(tsk, addr, PAGE_SIZE, prot_flags);

        if (rc != addr)
            ret = -ENOMEM;
        else
            ret = 0;
        goto ret;
    }

    /* Region already mapped, so have the kernel copy zeros into the region. */
    aligned = LOWER_PAGE(addr);
    vaddr = pin_one_page(tsk, mm, aligned, 1, &page);
    if (!vaddr)
    {
        ret = -ENOMEM;
        goto ret;
    }
    vaddr += addr - aligned;
    memset(vaddr, 0, end - addr);
    page_cache_release(page);
    kunmap(page);
ret:
    mmput(mm);
    return ret;
}

_STATIC_F_ void
add_mm_rss(struct mm_struct *mm, int file_rss, int anon_rss)
{
    if (file_rss)
        add_mm_counter(mm, file_rss, file_rss);
    if (anon_rss)
        add_mm_counter(mm, anon_rss, anon_rss);
}

_STATIC_F_ int
zero_fill_vm(struct task_struct *tsk, unsigned long addr, unsigned long end,
        unsigned long prot_flags)
{
    unsigned long ret;
    unsigned long start_page, last_page;
    struct mm_struct *mm;
    struct vm_area_struct *vma, *next;

    mm = get_task_mm(tsk);
    if (!mm)
        return -EINVAL;
    down_write(&mm->mmap_sem);
    start_page = PAGE_ALIGN(addr);
    last_page = LOWER_PAGE(end);

    ret = 0;
    if (start_page > last_page) /* Does not cross/touch a page boundary. */
    {
        if (unlikely(manuallyZero(tsk, addr, end, prot_flags, 1)))
            ret = -ENOMEM;
        goto unlock;
    }

    /* First, zero out the non page aligned regions. */
    if (addr < start_page) 
    {
        if (unlikely(manuallyZero(tsk, addr, start_page, prot_flags, 1)))
        {
            ret = -ENOMEM;
            goto unlock;
        }
    }
    if (last_page < end)
    {
        if (unlikely(manuallyZero(tsk, last_page, end, prot_flags, 1)))
        {
            ret = -ENOMEM;
            goto unlock;
        }
    }

    /* If we only crossed/touched one page boundary, we are done. */
    if (start_page == last_page)
        goto unlock;

    /* Now, remap the page aligned region(s). This will be faster than changing
       the page tables for large regions. We also automatically map parts of
       the region that aren't already mapped. */
    addr = start_page;
    end = last_page;
    vma = find_vma(mm, addr);
    while (vma && (vma->vm_start < end))
    {
        unsigned long tmp;
        if (vma->vm_start > addr) /* Map the gap. */
        {
            ret = do_brk_gen(tsk, addr, vma->vm_start - addr, prot_flags);
            if (unlikely(ret != addr))
            {
                ret = -ENOMEM;
                goto unlock;
            }
        }
        /* Remap the old region, but keep the old protection flags. */
        tmp = vma->vm_start;
        addr = vma->vm_end;
        next = vma->vm_next;
        ret = do_brk_gen(tsk, tmp, end - tmp,
                vma->vm_flags & VM_DATA_DEFAULT_FLAGS);
        if (unlikely(ret != tmp))
        {
            ret = -ENOMEM;
            goto unlock;
        }
        vma = next;
    }
    ret = 0;
    if (addr < end)
    {
        /* Map the rest of the region. */
        ret = do_brk_gen(tsk, addr, end - addr, prot_flags);
        if (unlikely(ret != addr))
        {
            ret = -ENOMEM;
            goto unlock;
        }
    }

    ret = 0;
unlock:
    up_write(&mm->mmap_sem);
    mmput(mm);

    return ret;
}

/* This is useful for when we decide to merge memory into the destination process
   TODO do we free memory if we can't allocate all necessary page tables? */
_STATIC_F_ int
fix_page_tables(struct mm_struct *mm, pgd_t *pgd, pud_t **pud, pmd_t **pmd,
        unsigned long addr)
{
    pud_t *npud;
    pmd_t *npmd;
    pte_t *npte;
    spinlock_t *ptl;
    npud = pud_alloc(mm, pgd, addr);
    if (!npud)
        return -ENOMEM;
    npmd = pmd_alloc(mm, npud, addr);
    if (!npmd)
        return -ENOMEM;
    /* Stupidly allocate a PTE then unmap it. This causes the pdm entry to be
       filled. We will actually set this PTE later at a different time.
       TODO integrate this with merge_one_pte */
    npte = pte_alloc_map_lock(mm, npmd, addr, &ptl);
    if (NULL == npte)
    {
        printk("fix_page_tables NULL npte %08lx\n", addr);
        return -ENOMEM;
    }
    pte_unmap_unlock(npte, ptl);
    *pud = npud;
    *pmd = npmd;
    return 0;
}

_STATIC_F_ pteval_t
get_pte_value(pte_t *pte)
{
    if (pte)
    {
        /* Whether or not the page was accessed is irrelevant in determining
           how to merge. */
        return pte_val(pte_mkold(*pte));
    }
    else
    {
        return 0; /* Empty page table entry. */
    }
}

/* Merge a range of memory. All pointers are valid and mapped so that the kernel
   can write to dst/src and read from ref. in the required range. Returns 0 on
   merge success (no conflicts), otherwise returns the number of conflicting
   bytes. Conflicting bytes are set to 0 in the destination. */
_STATIC_F_ int
merge_mapped_range(void *vdst, void *vsrc, const void *vref, size_t off,
        size_t size, unsigned long addr)
{
    int i, diff;
    unsigned char *dst, *src;
    const unsigned char *ref;

    dst = (unsigned char*)vdst;
    src = (unsigned char*)vsrc;
    ref = (const unsigned char*)vref;
    dst += off; /* Offset. */
    src += off;
    ref += off;
    addr += off;

    for (i = diff = 0; i < size; ++i)
    {
        if (ref[i] == src[i])
            continue;
        if (ref[i] == dst[i])
        {
            dst[i] = src[i];
            continue;
        }
        printk("Merge conflict at %08lx: %02lx %02lx %02lx\n", addr + i,
                dst[i], src[i], ref[i]);
        dst[i] = src[i] = 0;
        ++diff;
    }
    //if (diff)
    //    printk("By the way, there was a merge conflict at VA=%08lx\n",
    //            (unsigned long)vdst);
    return diff;
}

/* Caller must kunmap_atomic the mapped page. */
_STATIC_F_ void *
pin_one_page_atomic(struct vm_area_struct *vma, pte_t *pte,
        unsigned long addr, struct page **page)
{
    /* ret = get_user_pages(tsk, mm, addr, 1 / * npages=1 * /, write
       / * write * /, write / * force * /, page, NULL);
    if (ret > 0)
        return kmap_atomic(*page); */
    struct page *pg;
    if (!vma || !pte)
        return NULL;
    pg = vm_normal_page(vma, addr, *pte);
    if (unlikely(!pg))
        return NULL;
    get_page(pg);
    *page = pg;
    return kmap_atomic(pg);

}
/* Returns 0 on no merge conflicts. Hopefully this is inlined since there
   are so many arguments. */
_STATIC_F_ _WANT_INLINE_ int
merge_one_pte(pte_t *dst_pte, pte_t *src_pte, pte_t *ref_pte,
        struct vm_area_struct *dvma, struct vm_area_struct *svma,
        struct vm_area_struct *rvma, unsigned long addr)
{
    struct page *dpage, *spage, *rpage;
    unsigned char *daddr, *saddr, *raddr;
    int ret = -ENOMEM;

    /* TODO should we bug on failure to get page mapped? or just return
       failure to process? */
    daddr = pin_one_page_atomic(dvma, dst_pte, addr, &dpage);
    if (!daddr || IS_ERR(daddr))
    {
        printk("pin failed 1\n");
        return ret;
    }
    saddr = pin_one_page_atomic(svma, src_pte, addr, &spage);
    if (!saddr || IS_ERR(saddr))
    {
        printk("pin failed 2\n");
        goto unmap_one;
    }
    raddr = pin_one_page_atomic(rvma, ref_pte, addr, &rpage);
    if (!raddr || IS_ERR(raddr))
    {
        raddr = kmap_atomic(rpage = ZERO_PAGE(0));
        if (!raddr)
            goto unmap_two;
    }

    /* MUST check individual bytes, no larger granularity. */
    ret = merge_mapped_range(daddr, saddr, raddr, 0, PAGE_SIZE, addr);

    if (ZERO_PAGE(0) != rpage)
        put_page(rpage);
        /*page_cache_release(rpage);*/
    kunmap_atomic(raddr);
unmap_two:
    /*page_cache_release(spage);*/
    put_page(spage);
    kunmap_atomic(saddr);
unmap_one:
    /*page_cache_release(dpage);*/
    put_page(dpage);
    kunmap_atomic(daddr);

    return ret;
}

_STATIC_F_ _WANT_INLINE_ void
init_rss_vec(int *rss)
{
    memset(rss, 0, sizeof(int) * NR_MM_COUNTERS);
}
_STATIC_F_ _WANT_INLINE_ void
add_mm_rss_vec(struct mm_struct *mm, int *rss)
{
    int i;
    if (current->mm == mm)
    {
        sync_mm_rss(current, mm);
        for (i = 0; i < NR_MM_COUNTERS; ++i)
            if (rss[i])
                add_mm_counter(mm, i, rss[i]);
    }
}

#define acquire_merge_locks()                                           \
do {                                                                    \
src_pte = dst_pte = ref_pte = NULL;                                     \
dst_ptl = src_ptl = NULL;                                               \
if (*dst_pmd && !pmd_none_or_clear_bad(*dst_pmd))                       \
    dst_pte = pte_offset_map_lock(dst_mm, *dst_pmd, addr, &dst_ptl);    \
if (src_pmd && !pmd_none_or_clear_bad(src_pmd)) {                       \
    src_pte = pte_offset_map(src_pmd, addr);                            \
    src_ptl = pte_lockptr(src_mm, src_pmd);                             \
    spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING); }                  \
if (ref_pmd && !pmd_none_or_clear_bad(ref_pmd))                         \
    ref_pte = pte_offset_map(ref_pmd, addr);                            \
orig_src_pte = src_pte;                                                 \
orig_dst_pte = dst_pte;                                                 \
orig_ref_pte = ref_pte;                                                 \
arch_enter_lazy_mmu_mode();                                             \
} while (0)

#define drop_merge_locks()                              \
do {                                                    \
arch_leave_lazy_mmu_mode();                             \
if (orig_ref_pte)                                       \
    pte_unmap(orig_ref_pte);                            \
if (orig_src_pte) {                                     \
    spin_unlock(src_ptl);                               \
    pte_unmap(orig_src_pte); }                          \
add_mm_rss(dst_mm, rss[0], rss[1]);                     \
if (orig_dst_pte)                                       \
    pte_unmap_unlock(orig_dst_pte, dst_ptl);            \
} while (0)

/* *_pmd pointers MIGHT be null! Should be inlined. */
_STATIC_F_ _WANT_INLINE_ int
merge_pte_range(struct task_struct *dst_tsk, struct task_struct *src_tsk,
        struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
        struct mm_struct *ref_mm,
        pgd_t *dst_pgd, pud_t **dst_pud, pmd_t **dst_pmd, pmd_t *src_pmd,
        pmd_t *ref_pmd, unsigned long addr, unsigned long end)
{
    int ret = 0;
    pte_t *orig_src_pte, *orig_dst_pte, *orig_ref_pte;
    pte_t *src_pte, *dst_pte, *ref_pte;
    spinlock_t *src_ptl, *dst_ptl;
    int progress = 0;
    int rss[NR_MM_COUNTERS];
    int do_reschedule;
    struct mm_struct *dst_mm = dst_vma->vm_mm;
    struct mm_struct *src_mm = src_vma->vm_mm;

again:
    do_reschedule = 1;
    init_rss_vec(rss);

    acquire_merge_locks();

    do {
        pteval_t spte, dpte, rpte;
        struct vm_area_struct *ref_vma;

        if (progress >= 32) {
            progress = 0;
            if (need_resched() ||
                    (src_ptl && spin_needbreak(src_ptl)) ||
                    (dst_ptl && spin_needbreak(dst_ptl)))
                break;
        }

        spte = get_pte_value(src_pte);
        dpte = get_pte_value(dst_pte);
        rpte = get_pte_value(ref_pte);

        if (spte == rpte)
        { /* Nothing changed in source, continue; */
            ++progress;
            continue;
        }

        /* We have no idea how the reference mm's vm_areas are distrubuted, so
         * we just call find_Vma each time. Thankfull,y find_vma is decently
         optimized for this. */
        ref_vma = find_vma(ref_mm, addr);
        if (dpte == rpte)
        { /* Only source changed, so COW the page. */
            if (!dst_pte)
            {
                if ((ret = fix_page_tables(dst_mm, dst_pgd, dst_pud, dst_pmd,
                                addr)))
                    goto drop;
                do_reschedule = 0;
                break;
                /* This will correctly allocate the dst_pte. TODO test this
                   part. */
            }
            ++progress;
            copy_one_pte(dst_mm, src_mm, dst_pte, src_pte, src_vma, addr, rss);
            continue;
        }

        /* Must compare byte by byte. */
        if ((ret = merge_one_pte(dst_pte, src_pte, ref_pte, dst_vma, src_vma,
                        ref_vma, addr)))
            goto drop;
        progress += 8;
    } while ((dst_pte ? ++dst_pte : 0), (src_pte ? ++src_pte : 0),
            (ref_pte ? ++ref_pte : 0), addr += PAGE_SIZE, addr != end);

drop:
    drop_merge_locks();
    if (ret)
        goto ret;

    if (do_reschedule)
        cond_resched();
    if (addr != end)
        goto again;

ret:
    return ret;
}

/* *_pud pointers MIGHT be null! */
_STATIC_F_ _WANT_INLINE_ int
merge_pmd_range(struct task_struct *dst_tsk, struct task_struct *src_tsk,
        struct vm_area_struct *dst_vma, struct vm_area_struct *src_vma,
        struct mm_struct *ref_mm, pgd_t *dst_pgd, pud_t **dst_pud,
        pud_t *src_pud, pud_t *ref_pud, unsigned long addr, unsigned long end)
{
    pmd_t *src_pmd, *dst_pmd, *ref_pmd;
    unsigned long next;

    src_pmd = dst_pmd = ref_pmd = NULL;
    if (*dst_pud && !pud_none_or_clear_bad(*dst_pud))
        dst_pmd = pmd_offset(*dst_pud, addr);
    if (src_pud && !pud_none_or_clear_bad(src_pud))
        src_pmd = pmd_offset(src_pud, addr);
    if (ref_pud && !pud_none_or_clear_bad(ref_pud))
        ref_pmd = pmd_offset(ref_pud, addr);
    do {
        next = pmd_addr_end(addr, end);
        /* Split huge pages. */
        if (*dst_pud && !pud_none_or_clear_bad(*dst_pud))
            split_huge_page_pmd(dst_vma->vm_mm, dst_pmd);
        if (src_pud && !pud_none_or_clear_bad(src_pud))
            split_huge_page_pmd(src_vma->vm_mm, src_pmd);
        if (ref_pud && !pud_none_or_clear_bad(ref_pud))
            split_huge_page_pmd(ref_mm, ref_pmd);
        if (merge_pte_range(dst_tsk, src_tsk, dst_vma, src_vma, ref_mm,
                    dst_pgd, dst_pud, &dst_pmd, src_pmd, ref_pmd,
                    addr, next))
            return -ENOMEM;
    } while ((dst_pmd ? ++dst_pmd : 0), (src_pmd ? ++src_pmd : 0),
            (ref_pmd ? ++ref_pmd : 0), addr = next, addr != end);
    return 0;
}

/* *_pgd pointers are NOT null. */
_STATIC_F_ _WANT_INLINE_ int
merge_pud_range(struct task_struct *dst_tsk,
        struct task_struct *src_tsk, struct vm_area_struct *dst_vma,
        struct vm_area_struct *src_vma, struct mm_struct *ref_mm,
        pgd_t *dst_pgd, pgd_t *src_pgd, pgd_t *ref_pgd, unsigned long addr,
        unsigned long end)
{
    pud_t *src_pud, *dst_pud, *ref_pud;
    unsigned long next;

    src_pud = dst_pud = ref_pud = NULL;
    if (!pgd_none_or_clear_bad(dst_pgd))
        dst_pud = pud_offset(dst_pgd, addr);
    if (!pgd_none_or_clear_bad(src_pgd))
        src_pud = pud_offset(src_pgd, addr);
    if (!pgd_none_or_clear_bad(ref_pgd))
        ref_pud = pud_offset(ref_pgd, addr);
    do {
        next = pud_addr_end(addr, end);
        if (merge_pmd_range(dst_tsk, src_tsk, dst_vma, src_vma, ref_mm,
                    dst_pgd, &dst_pud, src_pud, ref_pud, addr, next))
            return -ENOMEM;
    } while ((dst_pud ? ++dst_pud : 0), (src_pud ? ++src_pud : 0),
            (ref_pud ? ++ref_pud : 0), addr = next, addr != end);
    return 0;
}

/* The assumption is that all memory is contained entirely within one page. */
_STATIC_F_ int
manuallyMerge(struct task_struct *dst_tsk, struct task_struct *src_tsk,
        struct mm_struct *ref_mm, unsigned long addr, unsigned long end)
{
    unsigned char *daddr, *saddr, *raddr;
    int ret;
    size_t size, off;
    unsigned long aligned;
    struct vm_area_struct *src_vma, *dst_vma;
    struct page *dpage, *spage, *rpage;

    src_vma = find_vma(src_tsk->mm, addr);
    if (!src_vma || src_vma->vm_start > addr)
        return 0; /* Source not even mapped, nothing to do. */

    size = end - addr;
    aligned = LOWER_PAGE(addr);
    off = addr - aligned;

    ret = -ENOMEM;
    dst_vma = find_vma(dst_tsk->mm, addr);
    if (!dst_vma || dst_vma->vm_start > addr)
    {
        /* If destination has never been mapped, we map it and copy the source
           into it. */
        unsigned long mapped = do_brk_gen(dst_tsk, aligned, PAGE_SIZE,
                src_vma->vm_flags & VM_DATA_DEFAULT_FLAGS);
        if (mapped != aligned)
            goto ret;
    }

    daddr = pin_one_page(dst_tsk, dst_tsk->mm, aligned, 1, &dpage);
    if (!daddr || IS_ERR(daddr))
        goto ret;
    saddr = pin_one_page(src_tsk, src_tsk->mm, aligned, 1, &spage);
    if (!saddr || IS_ERR(saddr))
        goto unmap_one;

    /* If reference page is not mapped, just pass zero page frame. */
    raddr = pin_one_page(src_tsk, ref_mm, aligned, 0, &rpage);
    if (!raddr || IS_ERR(raddr))
    {
        raddr = kmap(rpage = ZERO_PAGE(0));
        if (!raddr)
            goto unmap_two;
    }

    /* MUST check individual bytes, no larger granularity. */
    ret = merge_mapped_range(daddr, saddr, raddr, off, size, addr);

    if (ZERO_PAGE(0) != rpage)
        page_cache_release(rpage);
    kunmap(rpage);
unmap_two:
    page_cache_release(spage);
    kunmap(spage);
unmap_one:
    page_cache_release(dpage);
    kunmap(dpage);

ret:
    return ret;
}

/* Ensures the destination memory map is fully mapped in the range [addr, end)
   by mapping the holes. Returns 0 on success. */
_STATIC_F_ int
map_gaps(struct task_struct *tsk, unsigned long addr, unsigned long end,
        unsigned long flags)
{
    struct mm_struct *mm = get_task_mm(tsk);
    struct vm_area_struct *vma;
    unsigned long ret;
    int actualRet = 0;

    vma = find_vma(mm, addr);
    while (vma && (vma->vm_start < end))
    {
        if (addr < vma->vm_start)
        {
            ret = do_brk_gen(tsk, addr, vma->vm_start - addr, flags);
            if (ret != addr)
            {
                actualRet = -ENOMEM;
                goto ret;
            }
        }
        addr = vma->vm_end;
        vma = vma->vm_next;
    }
    /* Map the rest of the gap. */
    if (addr < end)
    {
        /* Map the rest of the region. */
        ret = do_brk_gen(tsk, addr, end - addr, flags);
        if (unlikely(ret != addr))
        {
            actualRet = -ENOMEM;
            goto ret;
        }
    }

ret:
    mmput(mm);
    return actualRet;
}

/* Similar to map_gaps, except that already mapped areas are re-mapped
   (essentially a zero-fill). Old areas retain their original memory
   protection flags. */
_STATIC_F_ int
remap_region(struct task_struct *tsk, unsigned long addr, unsigned long end,
        unsigned long flags)
{
    struct mm_struct *mm = tsk->mm;
    struct vm_area_struct *vma, *next;
    unsigned long ret;
    int actualRet = 0;

    /*printk("remap_region MM=%08lx %08lx %08lx %08lx\n", mm, addr, end,
      flags);*/
    vma = find_vma(mm, addr);
    while (vma && (vma->vm_start < end))
    {
        unsigned long local_flags, local_end;
        if (addr < vma->vm_start)
        { /* Map a previously un mapped area. */
            ret = do_brk_gen(tsk, addr, vma->vm_start - addr, flags);
            if (ret != addr)
            {
                actualRet = -ENOMEM;
                goto ret;
            }
        }
        /* Remap the old area. */
        //addr = vma->vm_start;
        local_end = vma->vm_end > end ? end : vma->vm_end;
        next = vma->vm_next;
        local_flags = vma->vm_flags & VM_DATA_DEFAULT_FLAGS;
        do_brk_gen(tsk, addr, local_end - addr, local_flags);
        /* The regions vma and next should *not* be merged since they we not
           merged before. */
        addr = local_end;
        vma = next;
    }
    /* Map the rest of the gap. */
    if (addr < end)
    {
        /* Map the rest of the region. */
        ret = do_brk_gen(tsk, addr, end - addr, flags);
        if (unlikely(ret != addr))
        {
            actualRet = -ENOMEM;
            goto ret;
        }
    }

ret:
    return actualRet;
}

/* Only allow merge if the src and dst mmaps match up:
case 1:
src:  [-----][--------][---]
dst:  [-----][--------][---]

case 2:
src:  [-----][--------][---]
dst:  [-----]          [---]

case 3:
src:  [-----]          [---]
dst:  [-----][--------][---]
   
   */
_STATIC_F_ int
can_merge(struct mm_struct *dmm, struct mm_struct *smm, unsigned long addr,
        unsigned long end)
{
    addr = LOWER_PAGE(addr);
    end = PAGE_ALIGN(end);
    struct vm_area_struct *svma = find_vma(smm, addr);
    struct vm_area_struct *dvma = find_vma(dmm, addr);
    while (svma && dvma && dvma->vm_start < end)
    {
        int changed = 0;
        while (svma && svma->vm_end <= dvma->vm_start)
            svma = svma->vm_next;
        if (!svma)
            return 1;
        if (!changed)
        {
            while (dvma && dvma->vm_end <= svma->vm_start)
                dvma = dvma->vm_next;
            if (!dvma || dvma->vm_start >= end)
                return 1;
        }
        if (dvma->vm_start != svma->vm_start || dvma->vm_end != svma->vm_end)
        {
            printk("Cant merge 2 [%08lx %08lx] [%08lx %08lx] (%08lx, %08lx)\n", dvma->vm_start,
                    dvma->vm_end, svma->vm_start, svma->vm_end, addr,end);
            return 0;
        }
        svma = svma->vm_next;
        dvma = dvma->vm_next;
    }
    return 1;
}

/* Examines and merges changes between memory regions. Returns 0 whenever all
   memory from the source is successfully merged into the destination and there
   were no conflicts. This is accomplished by efficiently examining page table
   entries and only examining byte-by-byte when page table entries are not
   definitive. Returns 0 on success, != 0 otherwise. */
_STATIC_F_ int
merge(struct task_struct *dst_tsk, struct task_struct *src_tsk,
        struct mm_struct *ref_mm, unsigned long addr, unsigned long end)
{
    int ret = 0;
    pgd_t *dst_pgd, *src_pgd, *ref_pgd;
    unsigned long next, start_page, last_page;
    struct mm_struct *dst_mm, *src_mm;
    struct vm_area_struct *src_vma;

    dst_mm = get_task_mm(dst_tsk);
    src_mm = get_task_mm(src_tsk);

    /* We order the semaphores according to process hierarchy. First the
       parent, then the child. There is no required ordering for the ref_mm
       semaphore, so we aquire it at the end. */
    down_write(&dst_mm->mmap_sem);
    down_write_nested(&src_mm->mmap_sem, 1);
    down_write_nested(&ref_mm->mmap_sem, 2);

    if (!can_merge(dst_mm, src_mm, addr, end))
    {
        ret = -EINVAL;
        goto unlock;
    }

    start_page = PAGE_ALIGN(addr);
    last_page = LOWER_PAGE(end);

    /* [addr, end) is contained entirely in a single page of memory. */
    if (start_page > last_page)
    {
        /* Merge the single region within a page, then return. */
        ret = manuallyMerge(dst_tsk, src_tsk, ref_mm, addr, end);
        goto unlock;
    }

    /* Merge the non page aligned regions. */
    if ((addr < start_page) && (ret = manuallyMerge(dst_tsk, src_tsk, ref_mm,
                    addr, start_page)))
    {
        goto unlock;
    }
    if ((last_page < end) && (ret = manuallyMerge(dst_tsk, src_tsk, ref_mm,
                    last_page, end)))
    {
        goto unlock;
    }

    addr = start_page;
    end = last_page;
    if (end == addr)
        goto unlock;
    /* Now we merge the page aligned region. Loop over source VMAs and iterate
       over the four level page structure. Automatically map any region in the
       destination that is not already mapped using the same protection bits
       as the source. */
    src_vma = find_vma(src_mm, addr);
    if (!(src_vma && src_vma->vm_start < end))
        goto unlock;

    /*flush_cache_range(src_mm, start_page, last_page);
    flush_cache_range(dst_mm, start_page, last_page);*/
    flush_cache_mm(src_mm);
    flush_cache_mm(dst_mm);
    do
    {
        struct vm_area_struct *dst_vma;
        unsigned long local_end;
        if (src_vma->vm_file && !(src_vma->vm_flags & VM_WRITE))
        {
            /* Skip read-only file mappings. */
            printk("Skipping %08lx\n", src_vma->vm_start);
            continue;
        }
        if (unlikely(map_gaps(dst_tsk, src_vma->vm_start, src_vma->vm_end,
                        src_vma->vm_flags & VM_DATA_DEFAULT_FLAGS)))
        {
            ret = -ENOMEM;
            goto flush;
        }
        dst_vma = find_vma(dst_mm, addr);
        if (unlikely(anon_vma_prepare(dst_vma)))
        {
            ret = -ENOMEM;
            goto flush;
        }
        printk("Merged anon\n");

        local_end = src_vma->vm_end > end ? end : src_vma->vm_end;
        /* Now we can compare the two regions. */
        dst_pgd = pgd_offset(dst_mm, addr);
        src_pgd = pgd_offset(src_mm, addr);
        ref_pgd = pgd_offset(ref_mm, addr);
        do {
            next = pgd_addr_end(addr, local_end);
            /* We must check each individual entry in the next page level. */
            if (unlikely(ret = merge_pud_range(dst_tsk, src_tsk, dst_vma,
                            src_vma, ref_mm, dst_pgd, src_pgd, ref_pgd, addr,
                            next)))
                goto flush;
        } while (++dst_pgd, ++src_pgd, ++ref_pgd, addr = next,
                addr != local_end);

    } while (src_vma = src_vma->vm_next, src_vma &&
            (addr = src_vma->vm_start) < end);

flush:
    /*flush_tlb_range(src_mm, start_page, last_page);
    flush_tlb_range(dst_mm, start_page, last_page);*/
    //flush_tlb_mm(src_mm);
    //flush_tlb_mm(dst_mm);
    flush_tlb_all();
unlock:
    up_write(&ref_mm->mmap_sem);
    up_write(&src_mm->mmap_sem);
    up_write(&dst_mm->mmap_sem);
    mmput(src_mm);
    mmput(dst_mm);

    return ret;
}

/* Manually (via memcpy) copy virtual memory region. [addr, end) must be
   contained in a single page. Call this function with mmap_sems held.
   Assumes src is already mapped. Returns 0 on success. */
_STATIC_F_ int
manuallyCopy(struct task_struct *dst_tsk, struct task_struct *src_tsk,
        unsigned long dst_addr, unsigned long addr, size_t size,
        unsigned long prot_flags, int force_map)
{
    int off;
    unsigned long aligned, dst_aligned;
    struct vm_area_struct *dst_vma;
    void *daddr, *saddr;
    struct page *dpage, *spage;

    dst_vma = find_vma(dst_tsk->mm, dst_addr);
    if (!dst_vma || dst_vma->vm_start > dst_addr)
    {
        unsigned long rc;

        if (!force_map)
            return -EINVAL; /* Region is not mapped so we can't zero it. */

        /* We map the page area in the destination, but we do not use COW since
           the user asked to copy on a strict subset of the page and we do not
           want to copy more than asked. */
        dst_aligned = LOWER_PAGE(dst_addr);
        rc = do_brk_gen(dst_tsk, dst_aligned, PAGE_SIZE, prot_flags);
        if (rc != dst_aligned)
            return -ENOMEM;
    }

    aligned = LOWER_PAGE(addr);
    dst_aligned = LOWER_PAGE(dst_addr);
    daddr = pin_one_page(dst_tsk, dst_tsk->mm, dst_aligned, 1, &dpage);
    if (!daddr)
        return -ENOMEM;
    saddr = pin_one_page(src_tsk, src_tsk->mm, aligned, 0, &spage);
    if (!saddr)
    {
        page_cache_release(dpage);
        kunmap(dpage);
        return -ENOMEM;
    }
    off = addr - aligned;
    daddr += off;
    saddr += off;
    memcpy(daddr, saddr, size);
    //page_cache_release(spage);
    set_page_dirty_lock(spage);
    kunmap(spage);
    //page_cache_release(dpage);
    set_page_dirty_lock(dpage);
    //if (dst_vma) flush_cache_page(dst_vma, dst_aligned, );
    kunmap(dpage);

    return 0;
}

_STATIC_F_ int
copy_memory(struct task_struct *dst_tsk, struct task_struct *src_tsk,
        unsigned long dst_addr, unsigned long addr, size_t size,
        unsigned long prot_flags)
{
    unsigned long ret;
    struct mm_struct *dst_mm, *src_mm;
    struct vm_area_struct *src_vma, *prev;
    unsigned long start_page, last_page, dst_start_page, dst_last_page;
    unsigned long src_end = addr + size;
    unsigned long dst_end = dst_addr + size;

    //printk("Going to copy %08lx %08lx %08lx\n", dst_addr, addr, size);
    dst_mm = get_task_mm(dst_tsk);
    src_mm = get_task_mm(src_tsk);
    if (!dst_mm || !src_mm)
    {
        if (dst_mm)
            mmput(dst_mm);
        if (src_mm)
            mmput(src_mm);
        return -EINVAL;
    }
    down_write(&dst_mm->mmap_sem); /* TODO fix locks. */
    down_write(&src_mm->mmap_sem);

    /* Check that the source is fully mapped. */
    prev = NULL;
    ret = -EINVAL;
    src_vma = find_vma(src_mm, addr);
    if (src_vma->vm_start > addr)
        goto unlock; /* Beginning of region not covered by mapping. */
    while (src_vma && src_vma->vm_start < src_end)
    {
        if (prev && (prev->vm_end != src_vma->vm_start))
            goto unlock;
        prev = src_vma;
        src_vma = src_vma->vm_next;
    }
    if (prev->vm_end < src_end)
        goto unlock;

    start_page = PAGE_ALIGN(addr);
    last_page = LOWER_PAGE(src_end);
    dst_last_page = LOWER_PAGE(dst_end);

    ret = 0;
    if (start_page > last_page) /* Does not cross/touch a page boundary. */
    {
        if (unlikely(manuallyCopy(dst_tsk, src_tsk, dst_addr, addr, size,
                        prot_flags, 1)))
        {
            ret = -ENOMEM;
        }
        goto unlock;
    }

    /* First, copy the non page aligned regions. */
    if (addr < start_page) 
    {
        if (unlikely(manuallyCopy(dst_tsk, src_tsk, dst_addr, addr,
                        start_page - addr, prot_flags, 1)))
        {
            ret = -ENOMEM;
            goto unlock;
        }
    }
    if (last_page < src_end)
    {
        unsigned long len = src_end - last_page;
        if (unlikely(manuallyCopy(dst_tsk, src_tsk, dst_last_page,
                        last_page, len, prot_flags, 1)))
        {
            ret = -ENOMEM;
            goto unlock;
        }
    }

    /* If we only crossed/touched one page boundary, we are done. */
    if (start_page == last_page)
        goto unlock;

    addr = start_page;
    src_end = last_page;
    dst_addr = dst_start_page = PAGE_ALIGN(dst_addr);
    dst_end = dst_last_page;

    /* Loop over each source VMA that includes the region to copy. */
    ret = -ENOMEM;
    /*flush_cache_range(src_mm, start_page, last_page);
    flush_cache_range(dst_mm, dst_start_page, dst_last_page);*/
    flush_cache_mm(src_mm);
    flush_cache_mm(dst_mm);

    /* Remap the destination, then copy page table entries (COW style). */
    remap_region(dst_tsk, dst_addr, dst_end, prot_flags);

    src_vma = find_vma(src_mm, addr);
    while (src_vma && (src_vma->vm_start < src_end))
    {
        unsigned long local_end =
            src_end < src_vma->vm_end ? src_end : src_vma->vm_end;
        //printk("copy_page_range_dst %08lx %08lx %08lx\n", dst_addr, addr,
        //        local_end-addr);
        if (copy_page_range_dst(dst_mm, src_mm, src_vma, dst_addr, addr,
                    local_end))
            goto flush;
        dst_addr += local_end - addr;
        addr += local_end - addr;
        src_vma = src_vma->vm_next;
    }
    ret = 0;

flush:
    /*flush_tlb_range(src_mm, start_page, last_page);
    flush_tlb_range(dst_mm, dst_start_page, dst_last_page);*/
    //flush_tlb_mm(src_mm);
    //flush_tlb_mm(dst_mm);
    flush_tlb_all();
unlock:
    up_write(&src_mm->mmap_sem);
    up_write(&dst_mm->mmap_sem);
    mmput(src_mm);
    mmput(dst_mm);

    return ret;
}

/* Debugging tools. */
_STATIC_F_ void
printtlb4(struct mm_struct *mm, pmd_t *pmd, unsigned long addr,
        unsigned long end)
{
    pte_t *orig;
    pte_t *pte;

    struct vm_area_struct *vma = find_vma(mm, addr);

    pte = pte_offset_map(pmd, addr);
    orig = pte;

    do {
        pteval_t vpte = pte_val(*pte);
        struct page *page = vm_normal_page(vma, addr, *pte);
        printk("(%08lx) is %08lx pg count=%d (pfn=%08lx valid?=%d)\n",
                addr, vpte, page_mapcount(page), pte_pfn(*pte),
                pfn_valid(pte_pfn(*pte)));
    } while (++pte, addr += PAGE_SIZE, addr != end);

    pte_unmap(orig);
}
_STATIC_F_ void
printtlb3(struct mm_struct *mm, pud_t *pud, unsigned long addr,
        unsigned long end)
{
    pmd_t *pmd;
    unsigned long next;
    pmd = pmd_offset(pud, addr);
    do
    {
        next = pmd_addr_end(addr, end);
        if (pmd_none_or_clear_bad(pmd))
            continue;
        printtlb4(mm, pmd, addr, next);
    } while (++pmd, addr = next, addr != end);
}
_STATIC_F_ void
printtlb2(struct mm_struct *mm, pgd_t *pgd, unsigned long addr,
        unsigned long end)
{
    unsigned long next;
    pud_t *pud;
    pud = pud_offset(pgd, addr);
    do
    {
        if (pud_none_or_clear_bad(pud))
            continue;
        next = pud_addr_end(addr, end);
        printtlb3(mm, pud, addr, next);
    } while (++pud, addr = next, addr != end);
}
_STATIC_F_ void
printtlb(struct mm_struct *mm, unsigned long addr, unsigned long end)
{
    pgd_t *pgd;
    unsigned long next;
    down_write(&mm->mmap_sem);
    pgd = pgd_offset(mm, addr);
    do
    {
        next = pgd_addr_end(addr, end);
        if (pgd_none_or_clear_bad(pgd))
            continue;
        printtlb2(mm, pgd, addr, next);
    } while (++pgd, addr = next, addr != end);
    up_write(&mm->mmap_sem);
}

_STATIC_F_ void
printvmas(struct mm_struct *mm)
{
    struct vm_area_struct *vma = mm->mmap;
    for ( ; vma; vma = vma->vm_next)
    {
        unsigned long p = *(unsigned long*)&vma->vm_page_prot;
        printk("VMA is from %08lx to %08lx (flags=%08lx prot=%08lx, "
                "file=%08lx anon=%08lx)\n",
                vma->vm_start, vma->vm_end, vma->vm_flags, p,
                (unsigned long)vma->vm_file, (unsigned long)vma->anon_vma);
    }
}

