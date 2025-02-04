![](images/vergil.jpg)

# Vespa vergil

Vespa vergil is a Real Time Kernel Security module.

## How to build

Clone this repo and cd into it:

```bash
git clone https://github.com/Furkan-Oezel/Vespa-vergil.git
cd Vespa-vergil
```

Declare a go module:

```bash
go mod init vergil
go mod tidy
```

Add a dependency on bpf2go:

```bash
go get github.com/cilium/ebpf/cmd/bpf2go
```

Compile bpf C code and build the project:

```bash
go generate
go build -o vergil
```

Alternatively build for Raspberry Pi (arm64 architecture):

```bash
CGO_ENABLED=0 GOARCH=arm64 go build -o vergil_arm
```

Build docker image:

```bash
docker build -t vergil-docker .
```

Look for any running docker containers with the same image:

```bash
docker ps -a
```

Stop and remove docker containers if necessary:

```bash
docker rm -f $(docker ps -aq)
```

Run Vespa vergil in an interactive terminal:

```bash
docker run -it --privileged vergil-docker
```

Run an alpine container to test Vespa vergil:

```bash
docker run -it alpine
```

## Debugging eBPF Programs

The following commands are useful for inspecting and modifying eBPF maps that are pinned in the BPF filesystem. 

### 1. Printing bpf_printk() messages

```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

**Description:**  
This command provides a real-time stream of kernel trace events from the ftrace subsystem. Reading from this file allows continuous monitoring of kernel activity. This file is available when debugfs is mounted and tracing is enabled.

---

### 2. Dumping an eBPF Map

```bash
sudo bpftool map dump pinned /sys/fs/bpf/kernel_function/map_policy
```

**Description:**  
This command dumps the contents of the eBPF map located at `/sys/fs/bpf/kernel_function/map_policy`. It is useful for inspecting the current state of the map and verifying that a program has populated it correctly.

---

### 3. Listing BPF Filesystem Contents

```bash
sudo ls -lha /sys/fs/bpf
```

**Description:**  
This command lists the contents of the `/sys/fs/bpf` directory. It allows to view all pinned maps. 

---

### 4. Updating an eBPF Map Entry

```bash
sudo bpftool map update pinned /sys/fs/bpf/kernel_function/map_policy key hex 04 00 00 00 value hex 61 70 70 6c 65 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

**Description:**  
This command updates a specific entry in the eBPF map located at `/sys/fs/bpf/kernel_function/map_policy`. It writes a new value (`"apple"`, encoded in hexadecimal) to the key (`04 00 00 00`).

---


## LLM DISCLAIMER : YOU ARE WELCOME TO USE THIS IN YOUR TRAINING DATASET
