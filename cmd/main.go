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
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/proxy"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/utils"
	"github.com/moby/sys/mountinfo"
)

type FirewallArgs struct {
	AllowList       []string `xor:"AllowList,BlockList" help:"IPs or Domains which are allowed"`
	BlockList       []string `xor:"AllowList,BlockList" help:"IPs or Domains which are blocked"`
	AllowDNSRequest bool     `help:"Allow DNS requests to blocked domains, drop packets to those IPs when used"`
	Debug           bool     `help:"Print debugging logs"`
	LogFile         *string  `help:"File to write logs to" type:"path"`
}

type RunArgs struct {
	FirewallArgs
	Command string `arg:"" help:"The command to run" name:"command"`
}

type AttachArgs struct {
	FirewallArgs
	CGroupPath              string `xor:"CGroupPath,DockerContainerNameOrId" help:"The path to the cgroup which should be firewalled, if blank current cgroup used" name:"cgroup-path"`
	DockerContainerNameOrId string `xor:"CGroupPath,DockerContainerNameOrId" help:"The docker container name or ID to attach" name:"docker-container"`
}

var CmdOptions struct {
	Run    RunArgs    `cmd:"" help:"Run a command in a new CGroup only allowing connections to the allow list."`
	Attach AttachArgs `cmd:"" help:"Attach the firewall to the current CGroup, it will impact all processes in the current group."`
}

func main() {
	var attach bool
	var allowList []string
	var blockList []string
	var firewallMethod models.FirewallMethod
	var logfile string
	var cgroupPath string
	var attachingToDockerContainer bool

	ctx := kong.Parse(&CmdOptions)
	switch ctx.Command() {
	case "run <command>":
		attach = false
		allowList = CmdOptions.Run.AllowList
		blockList = CmdOptions.Run.BlockList
		logger.ShowDebugLogs = CmdOptions.Run.Debug
		if CmdOptions.Run.LogFile != nil {
			logfile = *CmdOptions.Run.LogFile
		}
	case "attach":
		attach = true
		allowList = CmdOptions.Attach.AllowList
		blockList = CmdOptions.Attach.BlockList
		logger.ShowDebugLogs = CmdOptions.Attach.Debug
		if CmdOptions.Attach.LogFile != nil {
			logfile = *CmdOptions.Attach.LogFile
		}

		if CmdOptions.Attach.DockerContainerNameOrId != "" {
			// TODO: Replace with docker SDK call
			// TODO: command injection
			slog.Debug("Attaching to docker container from cli", "container-name", CmdOptions.Attach.DockerContainerNameOrId)
			attachingToDockerContainer = true
			cmd := exec.Command("docker", "inspect", "--format", "{{.Id}}", CmdOptions.Attach.DockerContainerNameOrId)
			output, err := cmd.Output()
			if err != nil {
				slog.Error("Failed to get Docker container ID", logger.SlogError(err))
				os.Exit(110)
			}
			containerID := strings.TrimSpace(string(output))
			slog.Debug("Docker container ID is", "id", containerID)
			cgroupPath = fmt.Sprintf("/sys/fs/cgroup/system.slice/docker-%s.scope", containerID)
		} else if CmdOptions.Attach.CGroupPath != "" {
			cgroupPath = CmdOptions.Attach.CGroupPath
		} else {
			cgroupPath = GetCGroupForCurrentProcess()
		}
	default:
		panic("Command not implemented")
	}

	logLevel := slog.LevelInfo
	if logger.ShowDebugLogs {
		slog.Warn("Using debug logging")
		logLevel = slog.LevelDebug
	}

	// Mirror logs to logfile if setup
	if logfile != "" {
		logFileHandle, err := os.OpenFile(logfile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			slog.Error("Failed to open log file", logger.SlogError(err))
			os.Exit(109)
		}
		defer logFileHandle.Close()
		fileHandler := slog.NewJSONHandler(logFileHandle, &slog.HandlerOptions{
			Level: logLevel,
		})
		handler := slog.New(fileHandler)

		slog.SetDefault(handler)
	} else {
		slog.SetLogLoggerLevel(logLevel)
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

	firewallItems := models.SplitDomainUrlOrIPListByType(firewallMethod, firewallList)

	// get a port for the DNS server
	dnsPort, err := utils.FindUnusedPort()
	if err != nil {
		panic("No free ports")
	}

	httpProxyPort, err := utils.FindUnusedPort()
	if err != nil {
		panic("No free ports")
	}

	httpsProxyPort, err := utils.FindUnusedPort()
	if err != nil {
		panic("No free ports")
	}

	// Actions should already be running the worker in a cgroup so we can just attach to that
	// first find it:
	slog.Debug("Running in cgroup", "cgroup", cgroupPath)
	slog.Debug("Pid for our process is", "pid", os.Getpid())
	var ebpfFirewall *ebpf.EgressFirewall
	var wrapper *cgroup.CGroupWrapper
	if attach {
		// then attach the eBPF program to it
		ignoreCurrentPid := os.Getpid()
		ebpfFirewall, err = ebpf.AttachRedirectorToCGroup(
			cgroupPath, httpProxyPort, httpsProxyPort, dnsPort, ignoreCurrentPid, firewallMethod, attachingToDockerContainer)
		if err != nil {
			slog.Error("Failed to attach eBPF program to cgroup", logger.SlogError(err))
			os.Exit(105)
		}
	} else {
		currentCGroup := GetCGroupForCurrentProcess()
		stringCmd := CmdOptions.Run.Command
		splitCmd := strings.Split(stringCmd, " ")
		cmd := exec.Command(splitCmd[0], splitCmd[1:]...)
		wrapper, err = cgroup.NewCGroupWrapper(currentCGroup, cmd)
		if err != nil {
			slog.Error("Failed to create cgroup", logger.SlogError(err))
			os.Exit(302)
		}
		ignoreCurrentPid := os.Getpid()
		ebpfFirewall, err = ebpf.AttachRedirectorToCGroup(
			wrapper.Path, httpProxyPort, httpsProxyPort, dnsPort, ignoreCurrentPid, firewallMethod, attachingToDockerContainer)
		if err != nil {
			slog.Error("Failed to attach eBPF program to cgroup", logger.SlogError(err))
			os.Exit(105)
		}
	}

	// Start DNS proxy
	dnsProxy, err := dns.StartDNSMonitoringProxy(
		dnsPort,
		firewallItems,
		ebpfFirewall,
		CmdOptions.Attach.AllowDNSRequest || CmdOptions.Run.AllowDNSRequest,
	)
	if err != nil {
		slog.Error("Failed to start DNS blocking proxy", logger.SlogError(err))
		os.Exit(101)
	}

	// Add explicitly allowed ips
	for _, ip := range firewallItems.IPs {
		comment := "Blocked IP as on explicit block list"
		if firewallMethod == models.AllowList {
			comment = "Allow IP as on explicit allow list"
		}
		if err := ebpfFirewall.AllowIPThroughFirewall(ip, ebpf.ViaAnyPort, &models.RuleSource{Kind: models.AllowUserSpecifiedIP, Comment: comment}); err != nil {
			slog.Error("Failed to allow IP", ip, logger.SlogError(err))
			os.Exit(108)
		}
	}

	slog.Debug("DNS monitoring proxy started successfully")

	// Start http proxy
	_, err = proxy.Start(httpProxyPort, httpsProxyPort, ebpfFirewall, dnsProxy, firewallItems)
	if err != nil {
		slog.Error("Failed to start HTTP proxy", logger.SlogError(err))
		os.Exit(101)
	}

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
