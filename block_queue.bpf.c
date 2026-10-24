#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

char LICENSE[] SEC("license") = "GPL";

extern bool bpf_hid_active(void) __ksym;

static const char target[] = "offline_heartbeats.bdb";

SEC("lsm/file_open")
int BPF_PROG(block_queue, struct file *file, int ret)
{
    char name[sizeof(target)];
    const unsigned char *dname;

    if (ret)    return ret;     /* another LSM already denied it */
    if (BPF_CORE_READ(file, f_path.dentry, d_name.len) != sizeof(target) - 1)
        return 0;
    dname = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (bpf_probe_read_kernel_str(name, sizeof(name), dname) < 0)
        return 0;
    if (bpf_strncmp(name, sizeof(name), target) != 0)
        return 0;
    if (bpf_hid_active())
        return 0;
    bpf_printk("kernel_level_hackatime: blocked queue open (idle)");
    return -EPERM;
}
