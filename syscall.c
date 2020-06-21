
#include <linux/kernel.h>	/* We're doing kernel work */
#include <linux/module.h>	/* Specifically, a module, */
#include <linux/moduleparam.h>	/* which will have params */
#include <linux/unistd.h>	/* The list of system calls */
#include <linux/string.h>
#include <linux/slab.h>
//#include <asm/semaphore.h>
//#include <asm/cacheflush.h>
#define CR0_WRITE_PROTECT   (1 << 16)


MODULE_LICENSE("GPL");
MODULE_AUTHOR("GalHar");
MODULE_DESCRIPTION("simpole module trial");
MODULE_VERSION("0.01");

unsigned long *sys_call_table = (unsigned long *) 0xffffffff81e001e0;

//int set_page_rw(long unsigned int _addr)
//{
//   struct page *pg;
//   pgprot_t prot;
//   pg = virt_to_page(_addr);
//   prot.pgprot = VM_READ | VM_WRITE;
//   return change_page_attr(pg, 1, prot);
//}



static uint64_t
get_cr0(void)
{
    uint64_t ret;

    __asm__ volatile (
        "movq %%cr0, %[ret]"
        : [ret] "=r" (ret)
    );
    
    return ret;
}

static void
set_cr0(uint64_t cr0)
{
    __asm__ volatile (
        "movq %[cr0], %%cr0"
        :
        : [cr0] "r" (cr0)
    );
}



void set_addr_rw(unsigned long addr) {

    unsigned int level;
    pte_t *pte = lookup_address(addr, &level);

    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;

}


inline void mywrite_cr0(unsigned long cr0) {
  asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

void enable_write_protection(void) {
  printk(KERN_INFO "enable write protection");
  
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  mywrite_cr0(cr0);
}

void disable_write_protection(unsigned long place_to_write) {
  printk(KERN_INFO "disable write protection");
  set_addr_rw(place_to_write);
  set_cr0(get_cr0() & ~CR0_WRITE_PROTECT);
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  mywrite_cr0(cr0);
}







/* 
 * A pointer to the original system call. The reason
 * we keep this, rather than call the original function
 * (sys_open), is because somebody else might have
 * replaced the system call before us. Note that this
 * is not 100% safe, because if another module
 * replaced sys_open before us, then when we're inserted
 * we'll call the function in that module - and it
 * might be removed before we are.
 *
 * Another reason for this is that we can't get sys_open.
 * It's a static variable, so it is not exported. 
 */
asmlinkage int (*original_call) (int, const char *, int);


asmlinkage int our_sys_unlinkat(int dirfd, const char *pathname, int flags)
{
	
	printk(KERN_INFO "unlinking?\n");	
	if (pathname[0] == 'a'){
		
		printk(KERN_INFO "unlinked\n");
		return 1;
	}


	return original_call(dirfd, pathname, flags);
}

/* 
 * Initialize the module - replace the system call 
 */
int init_module()
{


	printk(KERN_INFO "Loaded syscall");
	
	disable_write_protection(&(sys_call_table[__NR_unlinkat]));
	original_call = sys_call_table[__NR_unlinkat];
	
	
	sys_call_table[__NR_unlinkat] = our_sys_unlinkat;
	enable_write_protection();

	printk(KERN_INFO "linked the syscall");

	return 0;
}


/* 
 * Cleanup - unregister the appropriate file from /proc 
 */
void cleanup_module()
{
	/* 
	 * Return the system call back to normal 
	 */
	if (sys_call_table[__NR_unlinkat] != our_sys_unlinkat) {
		printk(KERN_ALERT "Somebody else also played with the ");
		printk(KERN_ALERT "open system call\n");
		printk(KERN_ALERT "The system may be left in ");
		printk(KERN_ALERT "an unstable state.\n");
	}

	sys_call_table[__NR_unlinkat] = original_call;
}
