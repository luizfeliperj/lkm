#include <linux/module.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include "intercept.h"

extern long intercept_flags;
extern intercept_t *hash_find(int pid);
unsigned long *syscall_table, *syscall32_table;

const struct {
	const char *name;
	unsigned long ** table;
} sys_call_tables[] = {
	{.name = "sys_call_table",      .table = &syscall_table},
	{.name = "ia32_sys_call_table", .table = &syscall32_table},
	{.name = NULL,                  .table = NULL}
};


intercept_t *pid_search_parent (struct task_struct* t)
{
	for (; t != &init_task; t = t->parent) {
		intercept_t *p = hash_find (t->tgid);
		if (p != NULL)
			return p;
	}

	return hash_find (t->parent->tgid);
}

intercept_t *pid_search_noparent (struct task_struct* t)
{
	return hash_find(t->tgid);
}

char *search_file(char *buf) {

        struct file *f;
        char *ver;
        mm_segment_t oldfs;

        oldfs = get_fs();
        set_fs (KERNEL_DS);

        f = filp_open(PROC_VERSION, O_RDONLY, 0);

        if ( IS_ERR(f) || ( f == NULL )) {

                return NULL;

        }

        memset(buf, 0, MAX_LEN);

        vfs_read(f, buf, MAX_LEN, &f->f_pos);

        ver = strsep(&buf, " ");
        ver = strsep(&buf, " ");
        ver = strsep(&buf, " ");

        filp_close(f, 0);
        set_fs(oldfs);

        return ver;
}

int
find_sys_call_table (char *kern_ver)
{

        char buf[MAX_LEN];
        int table, i = 0;
        char *filename;
        char *p;
        struct file *f = NULL;

        mm_segment_t oldfs;

        oldfs = get_fs();
        set_fs (KERNEL_DS);

        filename = kmalloc(strlen(kern_ver)+strlen(BOOT_PATH)+1, GFP_KERNEL);

        if ( filename == NULL )
	{
		WARNING ("kmalloc returned error");
                return -1;
	}

        memset(filename, 0, strlen(BOOT_PATH)+strlen(kern_ver)+1);

        strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
        strncat(filename, kern_ver, strlen(kern_ver));

        DEBUG("System.map path %s\n", filename);

	for (table = 0; sys_call_tables[table].name != NULL; table++)
	{
        	f = filp_open(filename, O_RDONLY, 0);

        	if ( IS_ERR(f) || ( f == NULL ))
                	return -1;

        	p = buf;
        	memset(buf, 0x0, MAX_LEN);

        	while (vfs_read(f, p+i, 1, &f->f_pos) == 1) {

                	if ( p[i] == '\n' || i == 255 ) {
				unsigned long addr = 0;
                        	i = 0;

                        	if ( (strstr(p, sys_call_tables[table].name)) != NULL ) {

                                	char *sys_string;

                                	sys_string = kmalloc(MAX_LEN, GFP_KERNEL);

                                	if ( sys_string == NULL ) { 
						WARNING ("kmalloc returned error");

                                        	filp_close(f, 0);
                                        	set_fs(oldfs);

                                        	kfree(filename);
                                        	return -1;
                                	}

                                	memset(sys_string, 0, MAX_LEN);
                                	strncpy(sys_string, strsep(&p, " "), MAX_LEN);
					addr = simple_strtoull(sys_string, NULL, 16);

                                	*(sys_call_tables[table].table) = (unsigned long *) addr;

        				DEBUG("Found %s on %lx\n", sys_call_tables[table].name, addr);

                                	kfree(sys_string);
                                	break;
                        	}

                        	memset(buf, 0x0, MAX_LEN);
                        	continue;
                	}

                	i++;
        	}
        	filp_close(f, 0);
	}

        set_fs(oldfs);
        kfree(filename);
        return 0;
}
