
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

struct process_info_t {
  u32 pid;
  u32 uid;
  u64 cgroup_id;
};

/*=============================================*/
/*              *map config*                   */
/* type = array                                */
/* number of entries = 5                       */
/*=============================================*/
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  // declare pointer called 'max_entries' that points to a int array of the size
  // 4096
  __uint(max_entries, 4096);
} map_data SEC(".maps");

char _license[] SEC("license") = "GPL";
