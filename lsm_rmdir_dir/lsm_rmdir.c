
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
 * how to get BPF_PROG function declaration for the path_rmdir LSM hook:
 * grep path_rmdir oth/X/kernel/linux-6.10/include/linux/lsm_hook_defs.h
 */
SEC("lsm/path_rmdir")
/*
 * this program executes whenever a rmdir command is performed
 * it forbids the deletion of the directory furkan
 */
int BPF_PROG(path_rmdir, const struct path *path, struct dentry *dentry) {
  char buf[32];
  // read the directory name that is to be removed
  bpf_probe_read_str(buf, sizeof(buf), dentry->d_name.name);
  if (strncmp(buf, "furkan", 6) == 0) {
    bpf_printk("rmdir attempted in %s\n", buf);
    return -EPERM;
  }
  return 0;
}

char _license[] SEC("license") = "GPL";
