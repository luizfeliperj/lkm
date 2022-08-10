#define __NO_VERSION__
#define MAX_LEN                 0x100
#define INITIAL_HASHTABLE_SIZE	0x010

#define EMPTY			""
#define BOOT_PATH               "/boot/System.map-"
#define PROC_VERSION            "/proc/version"
#define PROC_ENTRY_FILENAME	"interceptor"
#define DEVFS_ENTRY_FILENAME	"interceptor"

#define FLAG_DEBUG		"debug"
#define FLAG_PARENT		"parent"
#define FLAG_HIJACKED		"hijack"

#define MAJOR_FAULT		0x1
#define HASH_INIT		0x2
#define FIFO_INIT		0x4
#define SEEK_PARENT		0x8
#define DEBUG_ENABLED		0x10
#define SYSCALL_HOOKED		0x20
#define SYSCALL_HIJACKED	0x40

#define __MYFILE__		strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__

#define WHERESTR		"interceptor[%s:%s:%d]: "
#define WHEREARG		__MYFILE__,__FUNCTION__, __LINE__

#define WARNING2(...)		printk (KERN_ALERT __VA_ARGS__)
#define WARNING(_fmt, ...)	WARNING2(WHERESTR _fmt, WHEREARG, ##__VA_ARGS__)

#define DEBUG2(...)		if (intercept_flags & DEBUG_ENABLED) printk(KERN_INFO __VA_ARGS__)
#define DEBUG(_fmt, ...)	DEBUG2(WHERESTR _fmt, WHEREARG, ##__VA_ARGS__)

typedef struct {
        int pid;
} intercept_t;

typedef struct {
	struct {
		__u64 sec;
		__s64 nsec;
	} tv;
	__be32 saddr, daddr;

        __s32 pid, tgid;
        __s32 parentpid, parenttgid;
        __s32 filedes;

	__be16 sport, dport;

	__u16 size;
	__u8 readwrite;
} data_t;
