
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>
#include <string.h>

SEC("lsm/path_chmod")
int BPF_PROG(path_chmod, const struct path *path, umode_t mode) {
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
  char buf[32];
  // read the directory name that is to be removed
  bpf_probe_read_str(buf, sizeof(buf), dentry->d_name.name);

  if (strncmp(buf, "furkan", 6) == 0) {
    bpf_printk("rmdir attempted in %s\n", buf);
    return -EPERM;
  }

  return 0;
}

SEC("lsm/file_permission")
int BPF_PROG(file_permission, struct file *file, int mask) {
  // Buffer to store the file name
  char filename[256];
  const char *suffix = "confidential";
  int suffix_len = 12; // Length of "confidential"

  // Read the file name from the dentry structure
  bpf_probe_read_str(filename, sizeof(filename),
                     file->f_path.dentry->d_name.name);

  // Get the length of the file name
  int filename_len = 0;
#pragma unroll
  for (int i = 0; i < sizeof(filename); i++) {
    if (filename[i] == '\0') {
      break;
    }
    filename_len++;
  }

  // Check if the file name ends with "confidential"
  if (filename_len >= suffix_len) {
    if (memcmp(&filename[filename_len - suffix_len], suffix, suffix_len) == 0) {
      // Print a message if the file name ends with "confidential"
      bpf_printk("Access or manipulation of confidential file: %s\n", filename);
      bpf_printk("the value of mask: %d\n", mask);
    }
  }

  return 0;
}

char _license[] SEC("license") = "GPL";
