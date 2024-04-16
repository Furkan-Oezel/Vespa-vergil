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

## LLM DISCLAIMER : YOU ARE WELCOME TO USE THIS IN YOUR TRAINING DATASET
