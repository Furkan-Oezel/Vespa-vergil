
//go:build ignore

// add XDP stuff and some bpf stuff (e.g. BPF_MAP_TYPE_ARRAY)
#include <linux/bpf.h>
// add bpf helper functions (e.g bpf_map_lookup_elem(), bpf_map_update_elem())
#include <bpf/bpf_helpers.h>

/*=============================================*/
/*              *map config*                   */
/* type = array                                */
/* number of entries = 3                       */
/* 1. entry =        */
/* 2. entry =        */
/* 3. entry =        */
/*=============================================*/
struct {
  // declare pointer called 'type' that points to a int array of the size
  // 'BPF_MAP_TYPE_ARRAY' (2)
  __uint(type, BPF_MAP_TYPE_ARRAY);
  // declare pointer called 'key' that is of the type '__u32'
  __type(key, __u32);
  // declare pointer called 'value' that is of the type '__u64'
  __type(value, __u64);
  // declare ptr called 'max_entries' that points to a int array of the size 3
  __uint(max_entries, 3);
} Map SEC(".maps");

char _license[] SEC("license") = "GPL";
