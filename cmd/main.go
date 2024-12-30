package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/containerd/cgroups"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/cgroup"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/dns"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/ebpf"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/logger"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
	"github.com/moby/sys/mountinfo"
)

type FirewallArgs struct {
	AllowList       []string `xor:"AllowList,BlockList" help:"IPs or Domains which are allowed"`
	BlockList       []string `xor:"AllowList,BlockList" help:"IPs or Domains which are blocked"`
	AllowDNSRequest bool     `help:"Allow DNS requests to blocked domains, drop packets to those IPs when used"`
	Debug           bool     `help:"Print debugging logs"`
}

type RunArgs struct {
	FirewallArgs
	Command string `arg:"" help:"The command to run" name:"command"`
}

var CmdOptions struct {
	Run    RunArgs      `cmd:"" help:"Run a command in a new CGroup only allowing connections to the allow list."`
	Attach FirewallArgs `cmd:"" help:"Attach the firewall to the current CGroup, it will impact all processes in the current group."`
}

func main() {
	var attach bool
	var allowList []string
	var blockList []string
	var firewallMethod models.FirewallMethod

	ctx := kong.Parse(&CmdOptions)
	switch ctx.Command() {
	case "run <command>":
		attach = false
		allowList = CmdOptions.Run.AllowList
		blockList = CmdOptions.Run.BlockList
		logger.ShowDebugLogs = CmdOptions.Run.Debug
	case "attach":
		attach = true
		allowList = CmdOptions.Attach.AllowList
		blockList = CmdOptions.Attach.BlockList
		logger.ShowDebugLogs = CmdOptions.Attach.Debug
	default:
		panic("Command not implemented")
	}

	if logger.ShowDebugLogs {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	} else {
		slog.SetLogLoggerLevel(slog.LevelInfo)
	}

	firewallList := make([]string, 0)
	if len(allowList) == 0 && len(blockList) == 0 {
		firewallMethod = models.LogOnly
	} else if len(allowList) > 0 {
		firewallMethod = models.AllowList
		firewallList = allowList
	} else {
		firewallMethod = models.BlockList
		firewallList = blockList
	}

	firewallIps, firewallDomains := splitDomainAndIPListByType(firewallList)

	// get a port for the DNS server
	dnsPort, err := dns.FindUnusedPort()
	if err != nil {
		panic("No free ports")
	}

	// Actions should already be running the worker in a cgroup so we can just attach to that
	// first find it:
	pathToCGroupToRunIn := GetCGroupForCurrentProcess()
	var ebpfFirewall *ebpf.DnsFirewall
	var wrapper *cgroup.CGroupWrapper
	if attach {
		// then attach the eBPF program to it
		ignoreCurrentPid := os.Getpid()
		ebpfFirewall, err = ebpf.AttachRedirectorToCGroup(
			pathToCGroupToRunIn, dnsPort, ignoreCurrentPid, firewallMethod)
		if err != nil {
			slog.Error("Failed to attach eBPF program to cgroup", logger.SlogError(err))
			os.Exit(105)
		}
	} else {
		stringCmd := CmdOptions.Run.Command
		splitCmd := strings.Split(stringCmd, " ")
		cmd := exec.Command(splitCmd[0], splitCmd[1:]...)
		wrapper, err = cgroup.NewCGroupWrapper(pathToCGroupToRunIn, cmd)
		if err != nil {
			slog.Error("Failed to create cgroup", logger.SlogError(err))
			os.Exit(302)
		}
		ebpfFirewall, err = ebpf.AttachRedirectorToCGroup(
			wrapper.Path, dnsPort, 0, firewallMethod)
		if err != nil {
			slog.Error("Failed to attach eBPF program to cgroup", logger.SlogError(err))
			os.Exit(105)
		}
	}

	dns, err := dns.StartDNSMonitoringProxy(
		dnsPort,
		firewallDomains,
		ebpfFirewall,
		CmdOptions.Attach.AllowDNSRequest || CmdOptions.Run.AllowDNSRequest,
	)
	if err != nil {
		slog.Error("Failed to start DNS blocking proxy", logger.SlogError(err))
		os.Exit(101)
	}

	// Allow calls to localhost and upstream dns server
	// TODO: This is pretty permissive, probably this should be an option for uesrs to decide on
	if firewallMethod == models.AllowList {
		err = ebpfFirewall.AddIPToFirewall("127.0.0.1", &ebpf.Reason{Kind: ebpf.UserSpecified, Comment: "Allow localhost"})
		if err != nil {
			slog.Error("Failed to allow localhost", logger.SlogError(err))
			os.Exit(108)
		}

		downstreamDnsIP := strings.Split(dns.BlockingDNSHandler.DownstreamServerAddr, ":")[0]
		err = ebpfFirewall.AddIPToFirewall(downstreamDnsIP, &ebpf.Reason{Kind: ebpf.UserSpecified, Comment: "Downstream dns server"})
		if err != nil {
			slog.Error("Failed to allow downstream dns server", logger.SlogError(err))
			os.Exit(108)
		}
	}

	// Add explicitly allowed ips
	for _, ip := range firewallIps {
		if err := ebpfFirewall.AddIPToFirewall(ip, &ebpf.Reason{Kind: ebpf.UserSpecified, Comment: "Allowed by Allowlist"}); err != nil {
			slog.Error("Failed to allow IP", ip, logger.SlogError(err))
			os.Exit(108)
		}
	}

	slog.Debug("DNS monitoring proxy started successfully")

	// If we're not attaching then we need to run the command in the cgroup
	if attach {
		// In the post hook we'll send a sigint and we can output the log
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		slog.Info("Sig int received, shutting down")
	} else {
		err, exitCode := wrapper.Run()
		if err != nil {
			if exitCode == -1 {
				slog.Error("Failed to run command in cgroup", logger.SlogError(err))
			} else {
				// Exit with the same exit code as the command
				slog.Debug("Command exited with non-zero exit code", "exitcode", exitCode)
				os.Exit(exitCode)
			}
		}
	}

	// Write DNS requests log to file
	requestsFile, err := os.Create("/tmp/dnsrequests.log")
	if err != nil {
		slog.Error("Failed to create requests log file", logger.SlogError(err))
		os.Exit(106)
	}
	defer requestsFile.Close()
	blockedFile, err := os.Create("/tmp/dnsblocked.log")
	if err != nil {
		slog.Error("Failed to create blocked log file", logger.SlogError(err))
		os.Exit(107)
	}
	defer blockedFile.Close()

	for _, logEntry := range dns.BlockingDNSHandler.BlockLog {
		fmt.Fprintf(blockedFile, "%v\n", logEntry)
	}
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
		slog.Error("Failed to get cgroup path", logger.SlogError(err))
		os.Exit(102)
	}

	mounts, err := mountinfo.GetMounts(mountinfo.FSTypeFilter("cgroup2"))
	if err != nil {
		slog.Error("Failed to get cgroup2 mounts", logger.SlogError(err))
		os.Exit(103)
	}
	if len(mounts) == 0 {
		slog.Error("No cgroup2 mounts found")
		os.Exit(104)
	}
	cgroup2Mount := mounts[0]

	cgroupPathForCurrentProcess = path.Join(cgroup2Mount.Mountpoint, cgroupPathForCurrentProcess)
	return cgroupPathForCurrentProcess
}
