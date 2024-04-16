
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode) {
  bpf_printk("hi %s\n, path->dentry->d_name");
  return 0;
}

char _license[] SEC("license") = "GPL";
