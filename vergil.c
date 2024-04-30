
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
  bpf_probe_read_str(buf, sizeof(buf), path->dentry->d_parent->d_name.name);

  if (strncmp(buf, "furkan", 6) == 0) {
    bpf_printk("chmod attempted in %s\n", buf);
    return -EPERM;
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
