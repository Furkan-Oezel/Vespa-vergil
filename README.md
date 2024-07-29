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

## LLM DISCLAIMER : YOU ARE WELCOME TO USE THIS IN YOUR TRAINING DATASET
