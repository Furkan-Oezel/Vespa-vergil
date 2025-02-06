// how to compile: gcc configure_policy.c -o configure_policy -lbpf -lelf

#include <stdio.h>
// include userspace API map helpers
#include <bpf/bpf.h>
// include close()
#include <unistd.h>

#define STRING_SIZE 64

int main() {
  int map_file_descriptor;
  int ret;
  __u32 key = 3;
  char value[STRING_SIZE];
  char *map_path = "/sys/fs/bpf/kernel_function/map_policy";
  // open map
  map_file_descriptor = bpf_obj_get(map_path);
  if (map_file_descriptor < 0) {
    perror("Failed to open BPF map");
    return 1;
  }

  // look at the map at index=key and write the value of that entry into the
  // variable value and print it
  ret = bpf_map_lookup_elem(map_file_descriptor, &key, &value);
  if (ret < 0) {
    perror("Failed to read from BPF map");
    close(map_file_descriptor);
    return 1;
  }
  printf("current value of %s at key = %d: %s\n", map_path, key, value);

  // update the map entry with the new value
  strncpy(value, "melon", STRING_SIZE - 1);
  value[STRING_SIZE - 1] = '\0';
  ret = bpf_map_update_elem(map_file_descriptor, &key, &value, BPF_ANY);
  if (ret < 0) {
    perror("Failed to update BPF map");
    close(map_file_descriptor);
    return 1;
  }

  // check the updated value and print it
  char another_value[STRING_SIZE];
  bpf_map_lookup_elem(map_file_descriptor, &key, &another_value);
  printf("updated value of %s at key = %d: %s\n", map_path, key, another_value);

  // close map
  close(map_file_descriptor);
  return 0;
}
