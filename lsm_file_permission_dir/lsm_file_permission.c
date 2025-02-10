
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

#define EXECUTE 0x1
#define WRITE 0x2

/*
 * available LSM hooks: https://www.kernel.org/doc/html/v5.2/security/LSM.html
 * how to get BPF_PROG function declaration for the file_permission LSM hook:
 * grep file_permission oth/X/kernel/linux-6.10/include/linux/lsm_hook_defs.h
 */
SEC("lsm/file_permission")
/*
 * this program hooks into the file_permission LSM hook
 * it monitors file access requests and specifically checks for files whose
 * names end with "confidential". If the file name ends with "confidential", it
 * logs an attempt to access the file, and depending on the access mask
 * ,it may deny the access with -EPERM.
 */
int BPF_PROG(file_permission, struct file *file, int mask) {
  char filename[256];
  const char *suffix = "confidential";
  int suffix_len = 12; // Length of "confidential"

  // Read the file name from the dentry structure
  bpf_probe_read_str(filename, sizeof(filename),
                     file->f_path.dentry->d_name.name);

  int filename_len = 0;
  /*
   * normally the verifier forbids loops
   * pragma unroll is a way to implement loops in eBPF programs
   * the compiler generates repeated code for each iteration of the loop
   */
#pragma unroll
  // get the length of the filename
  for (int i = 0; i < sizeof(filename); i++) {
    if (filename[i] == '\0') {
      break;
    }
    filename_len++;
  }

  if (filename_len >= suffix_len) {
    // compare both pointers
    if (memcmp(&filename[filename_len - suffix_len], suffix, suffix_len) == 0) {
      bpf_printk("Access or manipulation of confidential file: %s\n", filename);
      bpf_printk("the value of mask: %d\n", mask);

      // retrieve file permission information
      umode_t mode = file->f_inode->i_mode;

      /*
       * mask is a bitmask that represents the requested access rights for a
       * file
       * the values can be seen in kernel/linux-6.10/include/linux/fs.h
       * e.g. grep MAY_ kernel/linux-6.10/include/linux/fs.h
       */
      if ((mask & WRITE) | (mask & EXECUTE)) {
        bpf_printk("write/execution denied for file: %s\n", filename);
        return -EPERM;
      } else {
        return 0;
      }
    }
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
