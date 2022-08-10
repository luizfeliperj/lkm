#include <linux/module.h>
#include <linux/file.h>
#include <linux/net.h>
#include <net/inet_sock.h>
#include "intercept.h"

extern long intercept_flags;
extern intercept_t* (*pid_search)(struct task_struct*);

void devfs_signal (void);
unsigned int fifo_put (data_t *);

asmlinkage ssize_t (*original_sys_read) (int fd, void __user *buf, size_t count);
asmlinkage ssize_t (*original_sys_write) (int fd, void __user *buf, size_t count);
asmlinkage ssize_t (*original_sys32_read) (int fd, void __user *buf, size_t count);
asmlinkage ssize_t (*original_sys32_write) (int fd, void __user *buf, size_t count);

static inline void
push_to_fifo (struct inet_sock *inet, const void __user *buf, size_t count,  const char readwrite, int fd)
{
	struct timespec tv = { -1, -1 };
	data_t *data = kmalloc (sizeof(data_t) + count, GFP_KERNEL);
	if (!data)
	{
		WARNING("kmalloc returned error");
		return;
	}


	data->size = count;
	data->filedes = fd;
	data->readwrite = readwrite;

	data->daddr = inet->daddr;
	data->dport = inet->dport;

	data->saddr = inet->saddr;
	data->sport = inet->sport;

	data->pid = current->pid;
	data->tgid = current->tgid;

	data->parentpid = current->parent->pid;
	data->parenttgid = current->parent->tgid;

	getnstimeofday (&tv);
	data->tv.sec = tv.tv_sec;
	data->tv.nsec = tv.tv_nsec;

	copy_from_user((unsigned char *)data + sizeof(data_t), buf, count);

	fifo_put (data);
	kfree(data);

	devfs_signal();
}

static ssize_t
fake_function_common(int fd, void __user *buf, size_t count, const char rw, asmlinkage ssize_t (*op)(int, void __user*, size_t))
{
	int err;
	ssize_t retcode;
	struct socket *s = NULL;
	struct inet_sock *inet = NULL;

	try_module_get (THIS_MODULE);

	if (!pid_search(current))
		goto END_func;

	s = sockfd_lookup (fd, &err);
	if (!s)
		goto END_func;

	inet = inet_sk(s->sk);

	DEBUG("fake %c function D:" NIPQUAD_FMT "[%d] S:" NIPQUAD_FMT "[%d]\n", rw,
		NIPQUAD(inet->daddr), ntohs(inet->dport), NIPQUAD(inet->saddr), ntohs(inet->sport));

END_func:
	retcode = op(fd, buf, count);

	if (inet /* && !strncmp (buf, "GIOP", 4)*/ )
	{
		if (retcode > 0)
			push_to_fifo (inet, buf, retcode, rw, fd);
		sockfd_put(s);
	}

	module_put (THIS_MODULE);

        return retcode;
}

asmlinkage ssize_t
our_fake_read_function (int fd, void __user *buf, size_t count)
{
	return fake_function_common (fd, buf, count, 'r', original_sys_read);
}

asmlinkage ssize_t
our_fake_write_function (int fd, void __user *buf, size_t count)
{
	return fake_function_common (fd, buf, count, 'w', original_sys_write);
}

asmlinkage ssize_t
our_fake32_read_function (int fd, void __user *buf, size_t count)
{
	return fake_function_common (fd, buf, count, 'r', original_sys32_read);
}

asmlinkage ssize_t
our_fake32_write_function (int fd, void __user *buf, size_t count)
{
	return fake_function_common (fd, buf, count, 'w', original_sys32_write);
}
