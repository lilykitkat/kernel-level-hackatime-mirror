#include <linux/module.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/textsearch.h>
#include <linux/ipv6.h>
#include <linux/netfilter_ipv6.h>
#include <net/ipv6.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#define ACTIVITY_TIMEOUT_SECS 10
#define ACTIVITY_TIMEOUT_JIFF (ACTIVITY_TIMEOUT_SECS * HZ)
static unsigned long last_event;
static bool event;
static __u16 last_vendor;
static __u16 last_product;
static const char blocked_host[]="hackatime.hackclub.com";
static struct ts_config *host_ts;

bool hid_active(void);
bool hid_active(void){
    unsigned long last;
    if(!READ_ONCE(event))   return false;
    last = READ_ONCE(last_event);
    return time_before(jiffies, last+ACTIVITY_TIMEOUT_JIFF);
}
EXPORT_SYMBOL(hid_active);
__bpf_kfunc_start_defs(); // register as a kfunc
__bpf_kfunc bool bpf_hid_active(void){
    return hid_active();
}
__bpf_kfunc_end_defs();
BTF_KFUNCS_START(hid_kfunc_ids)
BTF_ID_FLAGS(func, bpf_hid_active)
BTF_KFUNCS_END(hid_kfunc_ids)

static const struct btf_kfunc_id_set hid_kfunc_set = {
    .owner = THIS_MODULE,
    .set   = &hid_kfunc_ids,
};
static unsigned int hk_check_tcp(struct sk_buff *skb, unsigned int thoff){
    struct tcphdr _th, *th;
    unsigned int payoff;
    u8 _tls[6], *tls;

    th=skb_header_pointer(skb, thoff, sizeof(_th), &_th);
    //istg if you are connecting to hackatime over ssh or a non-443 port somehow
    if(!th||th->dest!=htons(443)) return NF_ACCEPT;
    payoff=thoff+th->doff*4;
    tls=skb_header_pointer(skb, payoff, sizeof(_tls), &_tls);
    if(!tls) return NF_ACCEPT;
    if(tls[0]!=0x16 /*handshake*/ ||tls[5]!=0x01/*ClientHello*/){
        return NF_ACCEPT;
    }
    if(skb_find_text(skb, payoff, skb->len, host_ts)==UINT_MAX) return NF_ACCEPT
        ;// that's not hackatime
    pr_info_ratelimited("kernel_level_hackatime: blocked hackatime\n");
    return NF_DROP;
}
static unsigned int hk_out_hook4(void *priv, struct sk_buff *skb, const struct
        nf_hook_state *state){
    //if you are connecting over hackatime over udp might asw just rmmod this
    if(hid_active()||ip_hdr(skb)->protocol!=IPPROTO_TCP) return NF_ACCEPT;
    return hk_check_tcp(skb, ip_hdrlen(skb));
}

static unsigned int hk_out_hook6(void *priv, struct sk_buff *skb, const struct
        nf_hook_state *state){
    if(hid_active()) return NF_ACCEPT;
    u8 nexthdr=ipv6_hdr(skb)->nexthdr;
    __be16 frag_off;
    int thoff;
    thoff=ipv6_skip_exthdr(skb,sizeof(struct ipv6hdr),&nexthdr,&frag_off);
    if(thoff<0||nexthdr!=IPPROTO_TCP) return NF_ACCEPT;
    return hk_check_tcp(skb, thoff);
}
static struct nf_hook_ops hk_ops[] = {
    {
        .hook     = hk_out_hook4,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FILTER,
    },
    {
        .hook     = hk_out_hook6,
        .pf       = NFPROTO_IPV6,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP6_PRI_FILTER,
    },
};
static void hid_event(struct input_handle *handle, unsigned int type,
        unsigned int code, int value){
    if(type!=EV_KEY)    return;
    WRITE_ONCE(last_event,jiffies);
    WRITE_ONCE(event,true);
}
static int hid_connect(struct input_handler *handler, struct input_dev *dev,
        const struct input_device_id *id){
    struct input_handle *handle; int error;
    handle=kzalloc(sizeof(*handle), GFP_KERNEL);
    if(!handle) return-ENOMEM;
    handle->dev=dev;
    handle->handler=handler;
    handle->name="kernel_level_hackatime";
    error=input_register_handle(handle);
	if (error)  goto err_free;
	error = input_open_device(handle);
	if(error)   goto err_unregister;
	pr_info("kernel_level_hackatime: watching \"%s\"\n", dev->name);
	return 0;
err_unregister:
	input_unregister_handle(handle);
err_free:
	kfree(handle);
	return error;
}
static void hid_disconnect(struct input_handle *handle){
    pr_info("kernel_level_hackatime: stopped watching \"%s\"\n",
            handle->dev->name);
    input_close_device(handle);
    input_unregister_handle(handle);
    kfree(handle);
}
static const struct input_device_id hid_ids[] = {
	{
		.flags = INPUT_DEVICE_ID_MATCH_EVBIT | INPUT_DEVICE_ID_MATCH_KEYBIT,
		.evbit = { BIT_MASK(EV_KEY) },
        .keybit = { [BIT_WORD(KEY_A)] = BIT_MASK(KEY_A) },
	},
	{ },
};
static struct input_handler hid_handler = {
	.event      = hid_event,
	.connect    = hid_connect,
	.disconnect = hid_disconnect,
	.name       = "kernel_level_hackatime",
	.id_table   = hid_ids,
};
static int hid_proc_show(struct seq_file *m, void *v){
	seq_printf(m, "%d\n", hid_active());
	return 0;
}
static int hid_proc_open(struct inode *inode, struct file *file){
	return single_open(file, hid_proc_show, NULL);
}
static const struct proc_ops hid_proc_fops = {
	.proc_open    = hid_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};
static struct proc_dir_entry *hid_proc_entry;
static int __init hid_init(void){
        int error;
        error = register_btf_kfunc_id_set(BPF_PROG_TYPE_LSM, &hid_kfunc_set);
        if (error) return error;
        error=input_register_handler(&hid_handler);
        if (error) return error;
        hid_proc_entry = proc_create("kernel_level_hackatime", 0444, NULL,
            &hid_proc_fops);
        if (!hid_proc_entry){
                error = -ENOMEM;
                goto err_handler;
        }
        host_ts = textsearch_prepare("kmp", blocked_host,
            sizeof(blocked_host) - 1, GFP_KERNEL, TS_AUTOLOAD);
        if (IS_ERR(host_ts)){
                error = PTR_ERR(host_ts);
                goto err_proc;
        }
        error = nf_register_net_hooks(&init_net, hk_ops, ARRAY_SIZE(hk_ops));
        if (error) goto err_ts;
        pr_info("kernel_level_hackatime: loaded (timeout=%ds)\n", ACTIVITY_TIMEOUT_SECS);
        return 0;
err_ts:
        textsearch_destroy(host_ts);
err_proc:
        proc_remove(hid_proc_entry);
err_handler:
        input_unregister_handler(&hid_handler);
        return error;
}
static void __exit hid_exit(void){
        nf_unregister_net_hooks(&init_net, hk_ops, ARRAY_SIZE(hk_ops));
        textsearch_destroy(host_ts);
        proc_remove(hid_proc_entry);
        input_unregister_handler(&hid_handler);
        pr_info("kernel_level_hackatime: unloaded\n");
}

module_init(hid_init);
module_exit(hid_exit);
MODULE_DEVICE_TABLE(input,hid_ids);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lily");
