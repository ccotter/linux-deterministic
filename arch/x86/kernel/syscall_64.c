/* System call table for x86-64. */

#include <linux/determinism.h>
#include <linux/linkage.h>
#include <linux/sys.h>
#include <linux/cache.h>
#include <asm/asm-offsets.h>

#define __NO_STUBS

#undef __SYSCALL
#define __SYSCALL(nr, sym) extern asmlinkage void sym(void) ;
#undef _ASM_X86_UNISTD_64_H
#include <asm/unistd_64.h>

#undef __SYSCALL
#define __SYSCALL(nr, sym) [nr] = sym,
#undef _ASM_X86_UNISTD_64_H

long is_valid_syscall(long nr)
{
	if (!is_deterministic(current))
		return 0;
	switch (nr) {
		case __NR_exit:
		case __NR_write: /* Allow this for debugging. */
		case __NR_dput:
		case __NR_dget:
		case __NR_dret:
			return 0;
	}
	return -EINVAL;
}

typedef void (*sys_call_ptr_t)(void);

extern void sys_ni_syscall(void);

const sys_call_ptr_t sys_call_table[__NR_syscall_max+1] = {
	/*
	*Smells like a like a compiler bug -- it doesn't work
	*when the & below is removed.
	*/
	[0 ... __NR_syscall_max] = &sys_ni_syscall,
#include <asm/unistd_64.h>
};
