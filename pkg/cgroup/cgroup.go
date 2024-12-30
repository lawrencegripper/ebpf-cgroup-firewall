package cgroup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/containerd/cgroups/v3/cgroup2"
	"golang.org/x/sys/unix"
)

type CGroupWrapper struct {
	Path          string
	CGroupManager *cgroup2.Manager
	Cmd           *exec.Cmd
}

func NewCGroupWrapper(path string, cmd *exec.Cmd) (*CGroupWrapper, error) {
	groupName := "/ebpf-cgroup-firewall"
	cgroupMan, err := cgroup2.NewManager(path, groupName, &cgroup2.Resources{})
	if err != nil {
		return nil, fmt.Errorf("failed to create cgroup at %s with name %s: %w", path, groupName, err)
	}

	return &CGroupWrapper{
		Path:          filepath.Join(path, groupName),
		CGroupManager: cgroupMan,
		Cmd:           cmd,
	}, nil
}

func (c *CGroupWrapper) Run() (error, int) {
	cleanup, err := c.attachCmdToCGroup()
	if err != nil {
		return fmt.Errorf("failed to attach command to cgroup: %w", err), -1
	}
	defer cleanup()

	c.Cmd.Stdout = os.Stdout
	c.Cmd.Stderr = os.Stderr

	// Ensure command runs in the same directory as the current process
	c.Cmd.Dir, _ = os.Getwd()
	// Ensure envs like PATH are taken from current process
	c.Cmd.Env = os.Environ()

	if err := c.Cmd.Run(); err != nil {
		exitCode := c.Cmd.ProcessState.ExitCode()
		if exitCode != 0 {
			return fmt.Errorf("command exited with code %d", exitCode), exitCode
		}
	}

	return nil, 0
}

// statCG returns a file descriptor for the cgroup, this is used when attaching a cmd to the cgroup
func (c *CGroupWrapper) statCG() (int, func(), error) {
	fd, err := unix.Open(c.Path, unix.O_PATH, 0)
	cleanup := func() {
		_ = unix.Close(fd)
	}
	return fd, cleanup, err
}

// attachCmdToCGroup configures the command via syscall.SysProcAttr to run in the cgroup
// this can be setup before the command is started to ensure all processes spawned by the
// command are inside the group
func (c *CGroupWrapper) attachCmdToCGroup() (func(), error) {
	if c.Cmd.SysProcAttr == nil {
		c.Cmd.SysProcAttr = new(syscall.SysProcAttr)
	}

	fd, cleanup, err := c.statCG()
	if err != nil {
		wrappedError := fmt.Errorf("failed to get file descriptor for cgroup: %w", err)
		return cleanup, wrappedError
	}

	c.Cmd.SysProcAttr.UseCgroupFD = true
	c.Cmd.SysProcAttr.CgroupFD = fd

	return cleanup, nil
}
