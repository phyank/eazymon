/*
* System Audit by Inline Hooking
*
*/


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/unistd.h>
#include <linux/utsname.h>
#include <asm/pgtable.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>
#include <linux/fs.h>
#include <linux/fs_struct.h>
#include <linux/limits.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <linux/ctype.h>

#include <net/sock.h>
#include <net/netlink.h>

#define MAX_LENGTH 512
#define K_PATH_MAX 512

#define NETLINK_MY 25

/*
** module macros
*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("phyank");
MODULE_DESCRIPTION("hook sys_call_table");

/*
** module constructor/destructor
*/
struct nl_msg{
    struct timespec timeStamp;
    unsigned msgLength;
    int pid;
    int tgid;
    int uid;
    int euid;
    int syscallNum;
    long ret;
    char msgJSON[];
};

long long_pow(long a,int b){
    if (b<0) return 0;
    else if(b==0){
        return 1;
    }else{
        long c=1;
    for(;b>0;b--)c*=a;
    return c;}
}

void ltostr(const long v,char* buf){

    int index=0;
    long r=v;
    if (v<0) {buf[index]='-';index++;r=-v;};
    
    int count=0;
    while(r%(long_pow(10,count))!=r)
        count++;

    long tmp;
    count--;
    for(;index<=19;){
        if(count<0)break;

        tmp=r/long_pow(10,count);
        buf[index]=(char)('0'+tmp);
        index++;

        r=r%long_pow(10,count);

        count--;
    }

    buf[index]='\0';
    if (index>19) strcat(buf,"(overflow)");
    return;

}

void get_fullname(const char *pathname,char *fullname)
{
	struct dentry *parent_dentry = current->fs->pwd.dentry;
	char buf[MAX_LENGTH];
	
	memset(buf,0,MAX_LENGTH);
	memset(fullname,0,K_PATH_MAX);

	// pathname could be a fullname
	if (*(parent_dentry->d_iname)=='/'){
	    strcpy(fullname,pathname);
	    return;
	}

	// pathname is not a fullname
	for(;;){
	if (unlikely(*(parent_dentry->d_iname)=='/'))
		buf[0]='\0';//reach the root dentry.
	else
	    strcpy(buf,parent_dentry->d_iname);
    strcat(buf,"/");
    strcat(buf,fullname);
    strcpy(fullname,buf);

    if (unlikely((parent_dentry == NULL) || (*(parent_dentry->d_iname)=='/')))
        break;

    parent_dentry = parent_dentry->d_parent;
	}

	strcat(fullname,pathname);

	return;
}



typedef void (*my_sys_call_ptr_t)(void);
my_sys_call_ptr_t *_sys_call_table = NULL;

typedef asmlinkage long (*old_mkdir_t)(struct pt_regs *regs);
typedef asmlinkage long (*old_open_t)(struct pt_regs *regs);
typedef asmlinkage long (*old_read_t)(struct pt_regs *regs);

old_mkdir_t old_mkdir=NULL;
old_open_t old_open=NULL;
old_read_t old_read=NULL;

struct sock * nl_sock=NULL;

unsigned int level;
pte_t *pte;

int send_audit_message_nl(const char* jsonBuf,int syscall_num,long ret){

        unsigned payloadLen=sizeof(struct timespec)+sizeof(unsigned)+ sizeof(int)*5+ sizeof(long)+strlen(jsonBuf)+1;

        struct sk_buff *skb=nlmsg_new(payloadLen,GFP_KERNEL);

        struct nlmsghdr *nlh=nlmsg_put(skb,0,666,0,payloadLen,GFP_KERNEL);
        if (nlh==NULL) printk("!!!nlmsg_put return NULL");
        //dump_nlmsg(nlh);//Debug

        struct nl_msg *msg=(struct nl_msg*)NLMSG_DATA(nlh);
        getnstimeofday(&(msg->timeStamp));
        msg->msgLength=payloadLen;
        msg->pid=current->pid;
        msg->tgid=current->tgid;
        const struct cred *cred = current_cred();
        msg->uid=cred->uid.val;
        msg->euid=cred->euid.val;
        msg->syscallNum=syscall_num;
        msg->ret=ret;
        strcpy(msg->msgJSON,jsonBuf);

        //printk(msg->msgJSON);

        NETLINK_CB(skb).dst_group = 123;

        /*multicast the message to all listening processes*/
        netlink_broadcast(nl_sock, skb, 0, 1, GFP_KERNEL);

        return 0;
}

// hooked mkdir function
asmlinkage long hooked_mkdir(struct pt_regs *regs) {

        char buff[K_PATH_MAX];
        char full_name[K_PATH_MAX];


        long nbytes=strncpy_from_user(buff,(char*)(regs->di),K_PATH_MAX);

        get_fullname(buff,full_name);

        long ret=old_mkdir(regs);

        char jsonBuf[K_PATH_MAX];
        memset(jsonBuf,0,K_PATH_MAX);
        strcpy(jsonBuf,"{\"dir_name\":\"");
        strcat(jsonBuf,buff);
        strcat(jsonBuf,"\",\"full_name\":\"");
        strcat(jsonBuf,full_name);
        strcat(jsonBuf,"\",\"proc_name\":\"");
        strcat(jsonBuf,current->comm);
        strcat(jsonBuf,"\"}");

        unsigned payloadLen=sizeof(struct timespec)+sizeof(unsigned)+ sizeof(int)*5+ sizeof(long)+strlen(jsonBuf)+1;

        struct sk_buff *skb=nlmsg_new(payloadLen,GFP_KERNEL);

        struct nlmsghdr *nlh=nlmsg_put(skb,0,666,0,payloadLen,GFP_KERNEL);
        if (nlh==NULL) printk("!!!nlmsg_put return NULL");
        //dump_nlmsg(nlh);//Debug

        struct nl_msg *msg=(struct nl_msg*)NLMSG_DATA(nlh);
        getnstimeofday(&(msg->timeStamp));
        msg->msgLength=payloadLen;
        msg->pid=current->pid;
        msg->tgid=current->tgid;
        const struct cred *cred = current_cred();
        msg->uid=cred->uid.val;
        msg->euid=cred->euid.val;
        msg->syscallNum=__NR_mkdir;
        msg->ret=ret;
        strcpy(msg->msgJSON,jsonBuf);

        //printk(msg->msgJSON);

        NETLINK_CB(skb).dst_group = 123;

        /*multicast the message to all listening processes*/
        netlink_broadcast(nl_sock, skb, 0, 1, GFP_KERNEL);

        return ret;
}

asmlinkage long hooked_read(struct pt_regs *regs){

        //printk("hooked sys_read(). process %s(%d) read %ld bytes from fd %ld.\n",current->comm,current->tgid,regs->dx,regs->bx);
        char jsonBuf[K_PATH_MAX];
        memset(jsonBuf,0,K_PATH_MAX);
        strcpy(jsonBuf,"{\"process_name\":\"");
        strcat(jsonBuf,current->comm);
        strcat(jsonBuf,"\",\"read_bytes\":\"");
        //sprintf(jsonBuf+strlen(jsonBuf),"%l",regs->dx)
        ltostr(regs->dx,jsonBuf+strlen(jsonBuf));
        strcat(jsonBuf,"\",\"from_fd\":\"");
        ltostr(regs->di,jsonBuf+strlen(jsonBuf));
        strcat(jsonBuf,"\"}");

        long ret=old_read(regs);

        send_audit_message_nl(jsonBuf,__NR_read,ret);

        return ret;
}


//asmlinkage long hooked_open(struct pt_regs *regs)
//{
//	long ret;
//  	static char* msg = "hooked sys_open(), file name: ";
//
//  	char buff[K_PATH_MAX];
//  	long nbytes=strncpy_from_user(buff,(char*)(regs->bx),K_PATH_MAX);
//  	printk("%s%s(%ld bytes)",msg,buff,nbytes);
//	ret = old_open(regs);
//  	return ret;
//}

static void nl_data_ready (struct sk_buff * skb)
{
  return;
}



// initialize the module
static int hooked_init(void) {
    printk("+ Loading hook module\n");

    struct netlink_kernel_cfg cfg = {
        .input = nl_data_ready,
    };
    nl_sock=netlink_kernel_create(&init_net,NETLINK_MY, &cfg);
    if (nl_sock==NULL)
    {
        return -10;}


     _sys_call_table=(my_sys_call_ptr_t *)kallsyms_lookup_name("sys_call_table");

    // print out sys_call_table address
    printk("! sys_call_table is at %lx\n", (long)_sys_call_table);

    // now we can hook syscalls ...such as uname
    // first, save the old gate (fptr)

    old_mkdir =  (old_mkdir_t) _sys_call_table[__NR_mkdir];
    printk("Old mkdir:%lx\n",(long)old_mkdir);

    old_open= (old_open_t) _sys_call_table[__NR_open];
    printk("Old open:%lx\n",(long)old_open);

    old_read=(old_read_t) _sys_call_table[__NR_read];
    printk("Old read:%lx\n",(long)old_read);

    // unprotect sys_call_table memory page
    pte = lookup_address((unsigned long) _sys_call_table, &level);

    // change PTE to allow writing
    set_pte_atomic(pte, pte_mkwrite(*pte));

    printk("! Disable write-protection of page with sys_call_table\n");

    _sys_call_table[__NR_mkdir] = (my_sys_call_ptr_t) hooked_mkdir;
//    _sys_call_table[__NR_open] = (my_sys_call_ptr_t) hooked_open;
    _sys_call_table[__NR_read] = (my_sys_call_ptr_t) hooked_read;

    set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));

    printk("! sys_call_table hooked!\n");

    return 0;
}

static void hooked_exit(void) {
    if(old_mkdir != NULL) {

        pte = lookup_address((unsigned long) _sys_call_table, &level);
        set_pte_atomic(pte, pte_mkwrite(*pte));

        // restore sys_call_table to original state
        _sys_call_table[__NR_mkdir] = (my_sys_call_ptr_t) old_mkdir;
        _sys_call_table[__NR_open] = (my_sys_call_ptr_t) old_open;
        _sys_call_table[__NR_read] = (my_sys_call_ptr_t) old_read;
        // reprotect page
        set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
    }
    sock_release(nl_sock->sk_socket);
    printk("+ Unloading hook module\n");
}

/*
** entry/exit macros
*/
module_init(hooked_init);
module_exit(hooked_exit);
