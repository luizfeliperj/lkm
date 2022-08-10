#include <linux/kernel.h>
#include <linux/module.h>
#include "hash_table.h"
#include "intercept.h"

extern long intercept_flags;

typedef struct hash_table hash_table;
typedef struct hash_entry hash_entry;
typedef struct {
        intercept_t *in;
        struct hash_entry hash;
} hash_t;

static hash_table hashtable;

char *hash_fetch_all (void)
{
	char *pids;
	hash_entry *hentry;
        
	pids = (char *) kmalloc (1, GFP_KERNEL);
	if (!pids)
	{
		WARNING ("kmalloc returned error");
		return EMPTY;
	}

	pids[0] = '\0';

	if (!(intercept_flags & HASH_INIT))
		return pids;

        hash_table_for_each(hentry, &hashtable)
        {
                hash_t *h = hash_entry(hentry, hash_t, hash);

                char *p = kasprintf(GFP_KERNEL, "%d %s", h->in->pid, pids);
		if (!p)
		{
                	kfree(pids);
			WARNING ("kmalloc returned error");
			return EMPTY;
		}

                kfree(pids);
                pids = p;
        }

	return pids;
}

void hash_init (void)
{
	int r = hash_table_init (&hashtable, INITIAL_HASHTABLE_SIZE, NULL);
	if (r == 0)
		intercept_flags |= HASH_INIT;
		
}

void hash_finit (void)
{
	if (intercept_flags & HASH_INIT)
		hash_table_finit (&hashtable);
}

static hash_t *find (int pid)
{
	hash_entry *hentry;

	if (!(intercept_flags & HASH_INIT))
		return NULL;

	hentry = hash_table_lookup_key_safe (&hashtable, (char *)&pid, sizeof (int));
	if (hentry == NULL)
		return NULL;

	return hash_entry (hentry, hash_t, hash);
}

intercept_t *hash_find(int pid)
{
	hash_t *h;

	if (!(intercept_flags & HASH_INIT))
		return NULL;

	h = find (pid);
	if (h == NULL)
		return NULL;

	return h->in;
}

void hash_insert (intercept_t *in)
{
	hash_t *h;

	if (!(intercept_flags & HASH_INIT))
		return;

	h = kmalloc (sizeof (hash_t), GFP_KERNEL);
	if (!h)
	{
		WARNING ("kmalloc returned error");
		return;
	}

	h->in = in;

	hash_table_insert_safe (&hashtable, &h->hash, (char*)&in->pid, sizeof(int));
}

void hash_delete (intercept_t *in)
{
	hash_t *h;

	if (!(intercept_flags & HASH_INIT))
		return;

	h = find(in->pid);
	if (!h)
		return;

	hash_table_del_key_safe (&hashtable, (char*)&in->pid, sizeof (int));
	kfree (h);
}
