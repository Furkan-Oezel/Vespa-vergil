package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// unlock unlimited amount of memory
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memory lock: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := vergilObjects{}
	if err := loadVergilObjects(&objs, nil); err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach the eBPF program to a hook.
	lsmHook, err := link.AttachLSM(link.LSMOptions{
		Program: objs.PathChmod,
	})
	if err != nil {
		log.Fatalf("attaching LSM program: %v", err)
	}
	defer lsmHook.Close()

	// Wait for a signal to exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Received interrupt, detaching program")
}
