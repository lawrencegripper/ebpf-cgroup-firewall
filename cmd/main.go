package main

import (
	"fmt"
	"os"
	"os/signal"
	"path"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/containerd/cgroups"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/dns"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/moby/sys/mountinfo"
)

type FirewallArgs struct {
	AllowList        []string `xor:"AllowList,BlockList" help:"IPs or Domains which are allowed"`
	BlockList        []string `xor:"AllowList,BlockList" help:"IPs or Domains which are blocked"`
	RefuseDNSRequest bool     `help:"Refuse DNS requests to blocked domains as well as dropping IP packets"`
}

var CmdOptions struct {
	Run    FirewallArgs `cmd:"" help:"Run a command in a new CGroup only allowing connections to the allow list."`
	Attach FirewallArgs `cmd:"" help:"Attach the firewall to the current CGroup, it will impact all processes in the current group."`
}

func main() {
	var attach bool
	var allowList []string
	var blockList []string
	var firewallMethod ebpf.FirewallMethod

	ctx := kong.Parse(&CmdOptions)
	fmt.Println(ctx.Command())
	switch ctx.Command() {
	case "run <command>":
		attach = false
		allowList = CmdOptions.Run.AllowList
		blockList = CmdOptions.Run.BlockList
	case "attach":
		attach = true
		allowList = CmdOptions.Attach.AllowList
		blockList = CmdOptions.Attach.BlockList
	default:
		panic("Command not implemented")
	}

	firewallList := make([]string, 0)
	if len(allowList) == 0 && len(blockList) == 0 {
		firewallMethod = ebpf.LogOnly
	} else if len(allowList) > 0 {
		firewallMethod = ebpf.AllowList
		firewallList = allowList
	} else {
		firewallMethod = ebpf.BlockList
		firewallList = blockList
	}

	firewallIps, firewallDomains := splitDomainAndIPListByType(firewallList)

	fmt.Println("Let's have a peak at what DNS requests are made by this process on port 53!")

	// Actions should already be running the worker in a cgroup so we can just attach to that
	// first find it:
	var pathToCGroupToRunIn string
	if attach {
		pathToCGroupToRunIn = GetCGroupForCurrentProcess()
	} else {
		panic("not implemented")
	}
	fmt.Println("Attaching to cgroup: ", pathToCGroupToRunIn)

	// get a port for the DNS server
	dnsPort, err := dns.FindUnusedPort()
	if err != nil {
		panic("No free ports")
	}

	// then attach the eBPF program to it
	ignoreCurrentPid := os.Getpid()
	ebpfFirewall, err := ebpf.AttachRedirectorToCGroup(pathToCGroupToRunIn, dnsPort, ignoreCurrentPid, firewallMethod)
	if err != nil {
		fmt.Printf("Failed to attach eBPF program to cgroup: %v\n", err)
		os.Exit(105)
	}

	dns, err := dns.StartDNSMonitoringProxy(
		dnsPort,
		firewallDomains,
		ebpfFirewall,
		CmdOptions.Attach.RefuseDNSRequest || CmdOptions.Run.RefuseDNSRequest,
	)
	if err != nil {
		fmt.Printf("Failed to start DNS blocking proxy: %v\n", err)
		os.Exit(101)
	}

	// Allow calls to localhost and upstream dns server
	// TODO: This is pretty permissive, probably this should be an option for uesrs to decide on
	if firewallMethod == ebpf.AllowList {
		err = ebpfFirewall.AddIPToFirewall("127.0.0.1", &ebpf.Reason{Kind: ebpf.UserSpecified, Comment: "Allow localhost"})
		if err != nil {
			fmt.Printf("Failed to allow IP: %v\n", err)
			os.Exit(108)
		}

		downstreamDnsIP := strings.Split(dns.BlockingDNSHandler.DownstreamServerAddr, ":")[0]
		err = ebpfFirewall.AddIPToFirewall(downstreamDnsIP, &ebpf.Reason{Kind: ebpf.UserSpecified, Comment: "Downstream dns server"})
		if err != nil {
			fmt.Printf("Failed to allow IP: %v\n", err)
			os.Exit(108)
		}
	}

	// Add explicitly allowed ips
	for _, ip := range firewallIps {
		if err := ebpfFirewall.AddIPToFirewall(ip, &ebpf.Reason{Kind: ebpf.UserSpecified, Comment: "Allowed by Allowlist"}); err != nil {
			fmt.Printf("Failed to allow IP: %v\n", err)
			os.Exit(108)
		}
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

func splitDomainAndIPListByType(allowList []string) ([]string, []string) {
	var ips []string
	var domains []string

	for _, item := range allowList {
		// Simple IP check - looks for dots and numbers
		if strings.Count(item, ".") == 3 {
			isIP := true
			for _, part := range strings.Split(item, ".") {
				if len(part) == 0 {
					isIP = false
					break
				}
				for _, c := range part {
					if c < '0' || c > '9' {
						isIP = false
						break
					}
				}
			}
			if isIP {
				ips = append(ips, item)
				continue
			}
		}
		domains = append(domains, item)
	}

	return ips, domains
}

func GetCGroupForCurrentProcess() string {
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
	return cgroupPathForCurrentProcess
}
