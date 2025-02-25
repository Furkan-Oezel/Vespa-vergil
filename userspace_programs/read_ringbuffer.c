// how to compile: clang -o read_ringbuffer read_ringbuffer.c -lbpf

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define RINGBUF_PATH "/sys/fs/bpf/kernel_function/map_data"

static volatile int stop = 0;

// Signal handler to safely stop the program
void handle_signal(int sig) { stop = 1; }

// Callback function that is executed when data is received from the ring buffer
int ringbuf_callback(void *ctx, void *data, size_t size) {
  printf("Received %zu bytes: ", size);

  // Interpret the data as an array of bytes
  unsigned char *bytes = (unsigned char *)data;
  for (size_t i = 0; i < size; i++) {
    printf("%02x ", bytes[i]); // Print each byte in hexadecimal format
  }
  printf("\n");

  return 0;
}

int main() {
  int map_fd;
  struct ring_buffer *rb = NULL;

  // Open the pinned ring buffer map from the BPF filesystem
  map_fd = bpf_obj_get(RINGBUF_PATH);
  if (map_fd < 0) {
    perror("Failed to open ring buffer map");
    return 1;
  }

  // Create a ring buffer reader and attach the callback function
  rb = ring_buffer__new(map_fd, ringbuf_callback, NULL, NULL);
  if (!rb) {
    fprintf(stderr, "Failed to create ring buffer\n");
    close(map_fd);
    return 1;
  }

  // Register signal handlers for graceful termination
  signal(SIGINT, handle_signal);
  signal(SIGTERM, handle_signal);

  printf("Reading from ring buffer...\n");

  // Infinite loop to continuously read from the ring buffer
  while (!stop) {
    int err = ring_buffer__poll(rb, 100 /* timeout in milliseconds */);
    if (err < 0) {
      fprintf(stderr, "Error polling ring buffer: %d\n", err);
      break;
    }
  }

  // Cleanup: free ring buffer resources and close the file descriptor
  ring_buffer__free(rb);
  close(map_fd);
  printf("Exiting...\n");

  return 0;
}
