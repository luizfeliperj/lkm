#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/completion.h>
#include <asm/uaccess.h>
#include "intercept.h"

extern long intercept_flags;

void fifo_reset (void);
unsigned int fifo_len (void);
unsigned int fifo_get (data_t **d);
void syscall_rewrite_on (void);
void syscall_rewrite_off (void);

static struct mydata_t {
	dev_t dev;
	ssize_t len;
	data_t *data;
	struct cdev cdev;
	unsigned char *ptr;
} mydata;

static atomic_t inuse = ATOMIC_INIT(0);
static DECLARE_COMPLETION(intercept_cdev_completion);

static int
devfs_open (struct inode *inode, struct file *filp)
{
	if ( (filp->f_flags & O_ACCMODE) != O_RDONLY )
		return -EINVAL;

	if (atomic_xchg(&inuse, 1))
		return -EBUSY;

	DEBUG("CDEV device open\n");

	filp->private_data = container_of (inode->i_cdev, struct mydata_t, cdev);

	mydata.len = 0;
	mydata.data = NULL;

	INIT_COMPLETION(intercept_cdev_completion);

	fifo_reset();

	syscall_rewrite_on();

	return 0;
}

static ssize_t
devfs_read (struct file *file, char __user *buffer, size_t count, loff_t *offp)
{
	int ret = 0;
	struct mydata_t *private;
	private = file->private_data;

	if (mydata.len == 0)
	{
		if (fifo_len() < sizeof (data_t))
		{
			INIT_COMPLETION(intercept_cdev_completion);

			if (wait_for_completion_interruptible(&intercept_cdev_completion))
				return -ERESTARTSYS;

			DEBUG("Received signal\n");
		}

		ret = fifo_get (&(mydata.data));
		if (ret < 0)
			return ret;

		mydata.len = ret;
		mydata.ptr = (unsigned char *) mydata.data;

		DEBUG("Loaded %d from fifo\n", ret);
	}

	ret = min (mydata.len, (ssize_t)count);
	if (copy_to_user (buffer, mydata.ptr, ret))
		return -EFAULT;

	DEBUG("Wrote %d bytes to user\n", ret);

	mydata.len -= ret;
	mydata.ptr += ret;

	if (mydata.len == 0)
		kfree (mydata.data);

	return ret;
}

static int
devfs_close (struct inode *inode, struct file *file)
{
	syscall_rewrite_off();

	if (mydata.len > 0)
		kfree (mydata.data);

	atomic_set (&inuse, 0);

	DEBUG("CDEV device close\n");

	return 0;
}

void devfs_signal (void)
{
	return complete (&intercept_cdev_completion);
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = devfs_open,
	.read = devfs_read,
	.release = devfs_close,
};

int
createdevfsfile (void)
{
	int r;

	r = alloc_chrdev_region (&mydata.dev, 0, 1, DEVFS_ENTRY_FILENAME);
	if (r != 0)
		return r;

	WARNING("Registered character device major %d minor %d\n", MAJOR(mydata.dev),
									MINOR(mydata.dev));

	cdev_init(&mydata.cdev, &fops);
	mydata.cdev.owner = THIS_MODULE;

	r = cdev_add (&mydata.cdev, mydata.dev, 1);
	if (r != 0)
		return r;
	
	return 0;
}

void
removedevfsfile (void)
{
	cdev_del (&mydata.cdev);
	unregister_chrdev_region (mydata.dev, 1);
}
