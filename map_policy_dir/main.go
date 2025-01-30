/*
 * documentation: https://ebpf-go.dev/guides/getting-started/#compile-ebpf-c-and-generate-scaffolding-using-bpf2go
 */

package main

import (
	"log"
	"os"
	"os/signal"
	"path"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memory lock: %v", err)
	}

	/*
	 * Load the compiled eBPF ELF and load it into the kernel.
	 *
	 * objs is an instance of the struct lsm_chmodObjects
	 * the struct is auto-generated by go generate
	 * the name of the struct can be seen in the file lsm_chmod_bpfel.go
	 * loadLSM_chmodObjects is a function that loads the programs and maps from the eBPF object file into the kernel
	 * and assigns them to the provided Go struct (lsm_chmodProgram or lsm_chmodMaps)
	 * objs.Close() is a method of lsm_chmodObjects struct and unloads the eBPF program from the kernel
	 * the GO keyword defer ensures that the deferred call's arguments are evaluated immediately,
	 * but the function call is not executed until the surrounding function returns
	 */
	objs := map_policyObjects{}
	if err := loadMap_policyObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load into the kernel: %v", err)
	}
	defer objs.Close()

	// pin map
	mapPath := "/sys/fs/bpf/map_policy"
	if err := objs.MapPolicy.Pin(mapPath); err != nil {
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
	log.Printf("                 successfully loaded policy map")
	log.Printf("<<<<--------------------------------------------------------->>>>")

	// Wait for a signal (e.g. control c) to exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Received interrupt, detaching program")
}
