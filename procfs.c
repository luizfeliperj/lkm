#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include "intercept.h"

extern long intercept_flags;
extern intercept_t *(*pid_search) (struct task_struct *t);

char *hash_fetch_all(void);
intercept_t *hash_find(int pid);
void syscall_rewrite_on (void);
void syscall_rewrite_off (void);
void hash_insert (intercept_t *i);
void hash_delete (intercept_t *i);
intercept_t *pid_search_parent (struct task_struct *t);
intercept_t *pid_search_noparent (struct task_struct *t);

static struct proc_dir_entry *entry;

static int
proc_read (char *buffer, char **buffer_location, off_t offset, int buffer_length, int *eof, void *data)
{
	int i,len;
	char *pids;
	char *flags;

	struct { long l; char *p; } opts[] = {
				{ SYSCALL_HIJACKED , "SYSCALL_HIJACKED" },
				{ SYSCALL_HOOKED ,   "SYSCALL_HOOKED"   },
				{ DEBUG_ENABLED , "DEBUG_ENABLED" },
				{ SEEK_PARENT , "SEEK_PARENT" },
				{ FIFO_INIT , "FIFO_INIT" },
				{ HASH_INIT , "HASH_INIT" },
				{ MAJOR_FAULT , "MAJOR_FAULT" },
				{ -1, NULL }
	};

	flags = kmalloc (1, GFP_KERNEL);
	flags[0] = '\0';

	for (i = 0; opts[i].l != -1; i++)
	{
		char *p;

		if (!(intercept_flags & opts[i].l))
			continue;

		p = kasprintf (GFP_KERNEL, "%s %s", opts[i].p, flags);
		kfree (flags);
		flags = p;
	}

	pids = hash_fetch_all();

	len = snprintf (buffer, buffer_length, "Flags: [%016lx] %s\n", intercept_flags, flags);
	len += snprintf(buffer+len, buffer_length - len, "Monitored PIDs: %s\n", pids);

	*eof = 1;

	kfree (pids);

	return len;
}

static int
proc_write (struct file *file, const char *buffer, unsigned long count, void *data)
{
	int p;
	char *line = kmemdup (buffer, count, GFP_KERNEL);
	line[count] = '\0';

	if (sscanf (line, "[%d]", &p))
	{
		intercept_t *in = hash_find(p);

		if (!in)
		{
			in = (intercept_t*) kmalloc (sizeof(intercept_t), GFP_KERNEL);
			memset (in, sizeof(intercept_t), 0);

			in->pid = p;

			hash_insert (in);
		}
		else
		{
			hash_delete (in);
			kfree(in);
		}
	}

/*
	else if (!strncasecmp (line, FLAG_HIJACKED, strlen(FLAG_HIJACKED)))
	{
		if (intercept_flags & SYSCALL_HIJACKED)
			syscall_rewrite_off();

		else
			syscall_rewrite_on();

	}
*/

	else if (!strncasecmp (line, FLAG_DEBUG, strlen(FLAG_DEBUG)))
	{
		if (intercept_flags & DEBUG_ENABLED)
			intercept_flags &= ~DEBUG_ENABLED;

		else
			intercept_flags |= DEBUG_ENABLED;
	}

	else if (!strncasecmp (line, FLAG_PARENT, strlen(FLAG_PARENT)))
	{
		if (intercept_flags & SEEK_PARENT)
		{
			pid_search = pid_search_noparent;
			intercept_flags &= ~SEEK_PARENT;
		}

		else
		{
			pid_search = pid_search_parent;
			intercept_flags |= SEEK_PARENT;
		}
	}

	else
		DEBUG ("Unknown token '%s`\n", line);

	kfree(line);
	return count;
}

int
createprocfsfile(void)
{
	entry = create_proc_entry(PROC_ENTRY_FILENAME, 0644, NULL);
	if (entry == NULL) {
		DEBUG ("Error: Could not initialize /proc/" PROC_ENTRY_FILENAME "\n");
		return -ENOMEM;
	}

	entry->owner = THIS_MODULE;
	entry->read_proc = proc_read;
	entry->write_proc = proc_write;
	entry->mode = S_IFREG | S_IRUGO | S_IWUGO;
	entry->uid = 0;
	entry->gid = 0;
	entry->size = 0;

	return 0;
}
        
void
removeprocfsfile (void)
{
	remove_proc_entry(PROC_ENTRY_FILENAME, &proc_root);
}
