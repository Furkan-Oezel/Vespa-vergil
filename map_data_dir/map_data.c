
//go:build ignore

#include "../include_dir/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

/*=============================================*/
/*              *map config*                   */
/* type = ringbuffer                           */
/* max_entries is the size (^2) in bytes       */
/*=============================================*/
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_data SEC(".maps");

char _license[] SEC("license") = "GPL";
