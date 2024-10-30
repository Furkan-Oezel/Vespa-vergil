
#include "../map_policy_dir/map_policy.c"
#include <bpf/bpf_helpers.h>

static __always_inline u64 *get_value(int key) {
  return bpf_map_lookup_elem(&map_policy, &key);
}

static __always_inline u64 *get_dir_in_which_chmod_is_forbidden() {
  int key = 1;
  return get_value(key);
}

static __always_inline u64 *get_dir_which_is_forbidden_to_remove() {
  int key = 2;
  return get_value(key);
}

static __always_inline u64 *get_permission_values() {
  int key = 3;
  return get_value(key);
}
