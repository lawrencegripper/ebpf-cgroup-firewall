package main

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"strings"

	"github.com/containerd/cgroups"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/dns"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/moby/sys/mountinfo"
)

func main() {
	fmt.Println("Let's have a peak at what DNS requests are made by this process on port 53!")

	// Actions should already be running the worker in a cgroup so we can just attach to that
	// first find it:
	cgroupProcFile := fmt.Sprintf("/proc/%d/cgroup", os.Getpid())
	_, cgroupPathForCurrentProcess, err := cgroups.ParseCgroupFileUnified(cgroupProcFile)
	if err != nil {
		fmt.Printf("Failed to get cgroup path: %v\n", err)
		os.Exit(102)
	}

	mounts, err := mountinfo.GetMounts(mountinfo.FSTypeFilter("cgroup2"))
	if err != nil {
		fmt.Printf("failed to get cgroup2 mounts: %s\n", err.Error())
		os.Exit(103)
	}
	if len(mounts) == 0 {
		fmt.Printf("no cgroup2 mounts found\n")
		os.Exit(104)
	}
	cgroup2Mount := mounts[0]

	cgroupPathForCurrentProcess = path.Join(cgroup2Mount.Mountpoint, cgroupPathForCurrentProcess)

	fmt.Println("Attaching to cgroup: ", cgroupPathForCurrentProcess)

	// get a port for the DNS server
	dnsPort, err := dns.FindUnusedPort()

	// then attach the eBPF program to it
	ebpfFirewall, err := ebpf.AttachRedirectorToCGroup(cgroupPathForCurrentProcess, dnsPort, os.Getpid())
	if err != nil {
		fmt.Printf("Failed to attach eBPF program to cgroup: %v\n", err)
		os.Exit(105)
	}

	dns, err := dns.StartDNSMonitoringProxy(dnsPort, []string{"example.com"}, ebpfFirewall)
	if err != nil {
		fmt.Printf("Failed to start DNS blocking proxy: %v\n", err)
		os.Exit(101)
	}

	downstreamDnsIP := strings.Split(dns.BlockingDNSHandler.DownstreamServerAddr, ":")[0]
	err = ebpfFirewall.AllowIP(downstreamDnsIP)
	if err != nil {
		fmt.Printf("Failed to allow IP: %v\n", err)
		os.Exit(108)
	}

	// Allow calls to localhost
	err = ebpfFirewall.AllowIP("127.0.0.1")
	if err != nil {
		fmt.Printf("Failed to allow IP: %v\n", err)
		os.Exit(108)
	}

	// Now lets wait and see what DNS request happen
	fmt.Println("DNS monitoring proxy started successfully")

	// In the post hook we'll send a sigint and we can output the log
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	fmt.Println("Sig int received, shutting down")

	// Write DNS requests log to file
	requestsFile, err := os.Create("/tmp/dnsrequests.log")
	if err != nil {
		fmt.Printf("Failed to create requests log file: %v\n", err)
		os.Exit(106)
	}
	defer requestsFile.Close()

	for requestedDomain, logEntry := range dns.BlockingDNSHandler.DNSLog {
		fmt.Fprintf(requestsFile, "Domain: %s\n%v\n\n", requestedDomain, logEntry)
	}

	blockedFile, err := os.Create("/tmp/dnsblocked.log")
	if err != nil {
		fmt.Printf("Failed to create blocked log file: %v\n", err)
		os.Exit(107)
	}
	defer blockedFile.Close()

	for _, logEntry := range dns.BlockingDNSHandler.BlockLog {
		fmt.Fprintf(blockedFile, "%v\n", logEntry)
	}

	fmt.Println("DNS logs written to /tmp/dnsrequests.log and /tmp/dnsblocked.log")
}
