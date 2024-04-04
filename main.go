package main

import (
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {

	var objs vergilObjects
	if err := loadVergilObjects()(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}

}
