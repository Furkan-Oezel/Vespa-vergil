
//go:build ignore

/*
 * add kernel type definitions (e.g. path->dentry->d_parent->d_name.name,
 * which is the name of the directory in the current path)
 * how to get this file: bpftool btf dump file /sys/kernel/btf/vmlinux format c
 * > vmlinux.h
 */
#include "../include_dir/vmlinux.h"
// #include "../include_dir/api_map.c"
//  add bpf helper functions (e.g bpf_map_lookup_elem(), bpf_map_update_elem())
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include <string.h>

struct {
  // declare pointer called 'type' that points to a int array of the size
  // 'BPF_MAP_TYPE_ARRAY' (2)
  __uint(type, BPF_MAP_TYPE_ARRAY);
  // declare pointer called 'key' that is of the type '__u32'
  __type(key, __u32);
  // declare pointer called 'value' that is of the type '__u64'
  __type(value, char[64]);
  // declare pointer called 'max_entries' that points to a int array of the size
  // 5
  __uint(max_entries, 5);
  // In order for the ELF loader to automatically pin or re-use a pinned map,
  // the map definition needs to have its pinned flag set.
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_policy SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} map_data SEC(".maps");

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
  // read the directory in which chmod is performed
  bpf_probe_read_str(buf, sizeof(buf), path->dentry->d_parent->d_name.name);

  __u32 k = 2;
  char new_value[64] = "banana";
  // update the second entry of map_policy with the string banana
  int ret = bpf_map_update_elem(&map_policy, &k, new_value, BPF_ANY);
  if (ret == 0) {
    bpf_printk("Successfully updated map entry with key %d\n", k);
  } else {
    bpf_printk("Failed to update map entry with key %d\n", k);
  }

  int key = 4;
  // look up and print the forth entry of map_policy
  char *value = bpf_map_lookup_elem(&map_policy, &key);
  if (value)
    bpf_printk("Value read from the map: '%s'\n", value);
  else
    bpf_printk("Failed to read value from the map\n");

  // if the read directory == 'furkan', then return error
  if (strncmp(buf, "furkan", 32) == 0) {
    bpf_printk("chmod attempted in %s\n", buf);
    return -EPERM;
  }
  return 0;
}

char _license[] SEC("license") = "GPL";
