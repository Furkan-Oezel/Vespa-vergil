/*
 * documentation: https://ebpf-go.dev/guides/getting-started/#compile-ebpf-c-and-generate-scaffolding-using-bpf2go
 */

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
	objs := lsm_file_permissionObjects{}
	if err := loadLsm_file_permissionObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load into the kernel: %v", err)
	}
	defer objs.Close()

	/*
	 * The link.AttachLSM function attaches the eBPF program to the appropriate LSM hook,
	 * but it’s the eBPF program itself that determines which LSM hook it is attaching to,
	 * based on its definition (in this case lsm/path_chmod)
	 * The LSMOptions struct contains options for how the eBPF program should be attached,
	 * like which program to attach (the PathChmod Program in this case) and any other configuration options.
	 * chmodHook is a variable of type link.Link (from the github.com/cilium/ebpf/link package).
	 * it represents the connection between the eBPF program and the LSM hook
	 * it manages the lifecycle of the link with methods such as Close()
	 * Close() ensures that the link between the eBPF program and the LSM hook (chmod syscall in this case)
	 * is properly cleaned up
	 */
	chmodHook, err := link.AttachLSM(link.LSMOptions{
		Program: objs.FilePermission,
	})
	if err != nil {
		log.Fatalf("failed to attach to LSM Hook: %v", err)
	}
	defer chmodHook.Close()

	log.Printf("<<<<--------------------------------------------------------->>>>")
	log.Printf("                 successfully loaded lsm_file_permission")
	log.Printf("<<<<--------------------------------------------------------->>>>")

	// Wait for a signal (e.g. control c) to exit.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	<-sig
	log.Println("Received interrupt, detaching program")
}
