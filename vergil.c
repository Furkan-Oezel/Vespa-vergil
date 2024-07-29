
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include <string.h>

SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode) {
  bpf_printk("hi\n");

  char buf[32];
  // read the directory in which the chmod command is forbidden
  bpf_probe_read_str(buf, sizeof(buf), path->dentry->d_parent->d_name.name);

  if (strncmp(buf, "furkan", 6) == 0) {
    bpf_printk("chmod attempted in %s\n", buf);
    return -EPERM;
  }

  return 0;
}

SEC("lsm/path_rmdir")
int BPF_PROG(path_rmdir, const struct path *path, struct dentry *dentry) {
  bpf_printk("another hello\n");

  char buf[32];
  // read the directory name that is to be removed
  bpf_probe_read_str(buf, sizeof(buf), dentry->d_name.name);

  bpf_printk("second hello\n");

  if (strncmp(buf, "furkan", 6) == 0) {
    bpf_printk("rmdir attempted in %s\n", buf);

    bpf_printk("third hello\n");

    return -EPERM;
  }

  return 0;
}
char _license[] SEC("license") = "GPL";
