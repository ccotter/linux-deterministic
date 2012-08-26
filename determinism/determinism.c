
#include <linux/syscalls.h>

SYSCALL_DEFINE5(dput, pid_t, childid, long, flags, unsigned long, start,
		size_t, size, unsigned long, dst)
{
	printk("IN DPUT\n");
	return 0;
}

SYSCALL_DEFINE5(dget, pid_t, childid, long, flags, unsigned long, start,
		size_t, size, unsigned long, dst)
{
	printk("IN DGET\n");
	return 0;
}

SYSCALL_DEFINE0(dret)
{
	printk("IN DRET\n");
	return 0;
}

