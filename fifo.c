#include <linux/module.h>
#include <linux/err.h>
#include <linux/net.h>
#include <linux/mm.h>
#include <linux/kfifo.h>
#include "intercept.h"

extern long intercept_flags;
extern long intercept_fifosz;

static struct kfifo *fifo;
static spinlock_t fifolock = SPIN_LOCK_UNLOCKED;

void
fifo_init (void)
{
	if (intercept_fifosz == 0)
	{
		long totalram;
		struct sysinfo s;

		si_meminfo(&s);
		totalram = s.totalram * s.mem_unit;

		DEBUG("Total amount of RAM available is: %ld\n", totalram);

		if ( totalram > 1024 * 1024 )
			intercept_fifosz = 128 * 1024;
		else
			intercept_fifosz = totalram >> 3;
	}

	DEBUG("Fifo size is %ld\n", intercept_fifosz);
	
	fifo = kfifo_alloc (intercept_fifosz, GFP_KERNEL, &fifolock);
	if (!IS_ERR(fifo))
		intercept_flags |= FIFO_INIT;

	if (ERR_PTR(-ENOMEM) == fifo)
		WARNING("ENOMEM when creating fifo [%ld]\n", intercept_fifosz);
}

void
fifo_reset (void)
{
	return kfifo_reset(fifo);
}

unsigned int
fifo_put (data_t *d)
{
	int ret;
	unsigned int fifosz;

	if (!(intercept_flags & FIFO_INIT) || (intercept_flags & MAJOR_FAULT))
		return -EINVAL;

	// usar o kfifo_len() para ver se tem espaco live,
	// se nao tiver, usar o kfifo_reset() pra liberar espaco
	// e continuar
	fifosz = kfifo_len(fifo);
	DEBUG("kfifo_len=%d\n", fifosz);

	if (intercept_fifosz <  fifosz + sizeof(data_t) + d->size)
		return 0;

	ret =  kfifo_put (fifo, (unsigned char*)d , sizeof (data_t) + d->size);

	return ret;
}

unsigned int
fifo_get (data_t **d)
{
	data_t data;

	if (!(intercept_flags & FIFO_INIT) || (intercept_flags & MAJOR_FAULT))
		return -EINVAL;

	if (kfifo_len(fifo) < sizeof (data_t))
		return 0;

	if (kfifo_get (fifo, (unsigned char*)(&data) , sizeof (data_t)) != sizeof (data_t))
	{
		WARNING("Major Fault! Aborting FIFO operations\n");
		intercept_flags |= MAJOR_FAULT;
		return -EFAULT;
	}

	*d = kmalloc (sizeof(data_t) + data.size, GFP_KERNEL);
	memcpy (*d, &data, sizeof(data_t));

	return kfifo_get (fifo, (unsigned char*)*d + sizeof (data_t), data.size) + sizeof (data_t);
}

unsigned int
fifo_len (void)
{
	return kfifo_len (fifo);
}

void
fifo_finit (void)
{
	if (intercept_flags & FIFO_INIT)
		kfifo_free(fifo);
}
