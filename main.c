#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include "intercept.h"
#undef __NO_VERSION__

int intercept_debug;
long intercept_flags;
long intercept_fifosz;
extern struct file_operations proc_flops;
extern struct inode_operations proc_inode;

void hash_init (void);
void hash_finit(void);
void fifo_init (void);
void fifo_finit(void);
char *search_file(char *);
int createdevfsfile(void);
int createprocfsfile(void);
void removedevfsfile(void);
void removeprocfsfile (void);
void syscall_rewrite_off (void);
int find_sys_call_table (char *);
intercept_t *pid_search_noparent(struct task_struct* t);

intercept_t* (*pid_search) (struct task_struct* t);

module_param(intercept_fifosz, long, S_IRUGO);
module_param(intercept_debug, int, S_IRUGO);

static int __init init (void)
{
        char *buf;
        char *kern_ver;

	if (intercept_debug)
		intercept_flags |= DEBUG_ENABLED;

        buf = kmalloc(MAX_LEN, GFP_KERNEL);
        if ( buf == NULL )
	{
		WARNING ("kmalloc returned error");
                return -1;
	}

        kern_ver = search_file(buf);
        if ( kern_ver == NULL )
	{
		WARNING ("Unable to find System.map");
                return -1;
	}

        WARNING("Kernel interceptor compiled on "__DATE__"@"__TIME__"\n");
        DEBUG("Kernel version found: %s\n", kern_ver);

        if ( find_sys_call_table(kern_ver) == -1 )
	{
		WARNING ("Unable to find syscall table entry point");
                return -1;
	}

	pid_search = pid_search_noparent;
	intercept_flags |= SYSCALL_HOOKED;

	createprocfsfile();
	createdevfsfile();
	hash_init();
	fifo_init();

	kfree (buf);

        return 0;

}
        
static void __exit finit (void)
{
	if (intercept_flags & SYSCALL_HIJACKED)
		syscall_rewrite_off();

	if (intercept_flags & HASH_INIT)
		hash_finit();

	if (intercept_flags & FIFO_INIT)
		fifo_finit();

	removedevfsfile();
	removeprocfsfile();
}


MODULE_AUTHOR("Luiz Felipe Silva");
MODULE_DESCRIPTION("System Call Interceptor");
MODULE_VERSION("0.2");
MODULE_LICENSE ("GPL");

module_init(init);
module_exit(finit);
