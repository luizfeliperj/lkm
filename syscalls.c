#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/unistd.h>
#include <asm/ia32_unistd.h>
#include "intercept.h"

extern long intercept_flags;
extern unsigned long *syscall_table, *syscall32_table;

asmlinkage ssize_t our_fake_read_function(int, void __user *, size_t );
asmlinkage ssize_t our_fake_write_function(int, void __user *, size_t);
asmlinkage ssize_t our_fake32_read_function(int, void __user *, size_t );
asmlinkage ssize_t our_fake32_write_function(int, void __user *, size_t);

extern asmlinkage ssize_t (*original_sys_read) (int fd, void __user *buf, size_t count);
extern asmlinkage ssize_t (*original_sys_write) (int fd, void __user *buf, size_t count);
extern asmlinkage ssize_t (*original_sys32_read) (int fd, void __user *buf, size_t count);
extern asmlinkage ssize_t (*original_sys32_write) (int fd, void __user *buf, size_t count);

void
syscall_rewrite_on (void)
{
	if ( ! intercept_flags & SYSCALL_HOOKED )
		return;

	DEBUG ("Rewriting system calls...\n");

	write_cr0 (read_cr0 () & (~ 0x10000));

	// read
        original_sys_read =(void*)xchg(&syscall_table[__NR_read], our_fake_read_function);
        original_sys32_read =(void*)xchg(&syscall32_table[__NR_ia32_read], our_fake32_read_function);

	// write
        original_sys_write =(void*)xchg(&syscall_table[__NR_write], our_fake_write_function);
        original_sys32_write =(void*)xchg(&syscall32_table[__NR_ia32_write], our_fake32_write_function);

	write_cr0 (read_cr0 () | 0x10000);

	intercept_flags |= SYSCALL_HIJACKED;

	DEBUG ("original_sys_read is on %lx\n", (long) original_sys_read);
	DEBUG ("original_sys_write is on %lx\n", (long) original_sys_write);
	DEBUG ("original_sys32_read is on %lx\n", (long) original_sys32_read);
	DEBUG ("original_sys32_write is on %lx\n", (long) original_sys32_write);
}
        
void
syscall_rewrite_off (void)
{
	if ( ! intercept_flags & SYSCALL_HOOKED )
		return;

	DEBUG ("Returning to original system calls...\n");

	write_cr0 (read_cr0 () & (~ 0x10000));

	// read
       	xchg(&syscall_table[__NR_read], original_sys_read);
       	xchg(&syscall32_table[__NR_ia32_read], original_sys32_read);

	// write
       	xchg(&syscall_table[__NR_write], original_sys_write);
       	xchg(&syscall32_table[__NR_ia32_write], original_sys32_write);

	write_cr0 (read_cr0 () | 0x10000);

	intercept_flags &= ~SYSCALL_HIJACKED;
}
