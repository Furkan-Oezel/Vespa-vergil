package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.
	var objs firewallObjects
	if err := loadFirewallObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}

	// pin map
	mapPath := "/sys/fs/bpf/my_map"
	if err := objs.Map.Pin(mapPath); err != nil {
		log.Fatalf("Error pinning map: %s", err)
	}

	// unpin map when the program stops running
	defer func() {
		if err := os.Remove(mapPath); err != nil {
			log.Printf("Error unpinning map: %s", err)
		}
	}()
	defer objs.Close()

	log.Printf("<<<<--------------------------------------------------------->>>>")
	log.Printf("	              hi")
	log.Printf("<<<<--------------------------------------------------------->>>>")

	// Wait for a signal to exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Received interrupt, detaching program")
}
