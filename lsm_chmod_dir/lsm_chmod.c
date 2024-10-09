
//go:build ignore

/*
 * add kernel type definitions (e.g. path->dentry->d_parent->d_name.name,
 * which is the name of the directory in the current path)
 * how to get this file: bpftool btf dump file /sys/kernel/btf/vmlinux format c
 * > vmlinux.h
 */
#include "../include_dir/vmlinux.h"
// add bpf helper functions (e.g bpf_map_lookup_elem(), bpf_map_update_elem())
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include <string.h>

/*
 * available LSM hooks: https://www.kernel.org/doc/html/v5.2/security/LSM.html
 * how to get BPF_PROG function declaration for the path_chmod LSM hook:
 * grep path_chmod oth/X/kernel/linux-6.10/include/linux/lsm_hook_defs.h
 */
SEC("lsm/path_chmod")
/*
 * this program executes whenever a chmod command is performed
 * it reads the name of the directory in which the command is performed
 * and compares it to a given string, "furkan" in this case
 * if it is the same, chmod will not be executed
 * the path argument is the kernel data structure representing the file
 * the mode argument is the desired new mode value
 */
int BPF_PROG(path_chmod, const struct path *path, umode_t mode) {
  char buf[32];
  bpf_probe_read_str(buf, sizeof(buf), path->dentry->d_parent->d_name.name);
  if (strncmp(buf, "furkan", 6) == 0) {
    bpf_printk("chmod attempted in %s\n", buf);
    return -EPERM;
  }
  return 0;
}

char _license[] SEC("license") = "GPL";
