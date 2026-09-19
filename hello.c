#include <linux/module.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#define ACTIVITY_TIMEOUT_SECS 30
#define ACTIVITY_TIMEOUT_JIFF (ACTIVITY_TIMEOUT_SECS * HZ)
static unsigned long last_event;
static bool event;
bool hid_active(void);
bool hid_active(void){
    unsigned long last;
    if(!READ_ONCE(event))   return false;
    last = READ_ONCE(last_event);
    return time_before(jiffies, last+ACTIVITY_TIMEOUT_JIFF);
}
EXPORT_SYMBOL(hid_active);

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
	pr_info("hidkbd_activity: watching \"%s\"\n", dev->name);
	return 0;
err_unregister:
	input_unregister_handle(handle);
err_free:
	kfree(handle);
	return error;
}
static void hid_disconnect(struct input_handle *handle){
    pr_info("hidkbd_activity: stopped watching \"%s\"\n", handle->dev->name);
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
	.name       = "hidkbd_activity",
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
	error=input_register_handler(&hid_handler);
	if (error) return error;
	hid_proc_entry = proc_create("hidkbd_activity", 0444, NULL,
            &hid_proc_fops);
	if (!hid_proc_entry){
		input_unregister_handler(&hid_handler);
		return -ENOMEM;
	}
	pr_info("hidkbd_activity: loaded (timeout=%ds)\n", ACTIVITY_TIMEOUT_SECS);
	return 0;
}
static void __exit hid_exit(void){
	proc_remove(hid_proc_entry);
	input_unregister_handler(&hid_handler);
	pr_info("hidkbd_activity: unloaded\n");
}
module_init(hid_init);
module_exit(hid_exit);
MODULE_DEVICE_TABLE(input,hid_ids);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("lily");
