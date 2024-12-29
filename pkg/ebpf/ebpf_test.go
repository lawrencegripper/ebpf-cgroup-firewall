// Package dnsredirector is used to redirect DNS requests to a local proxy. It loads the eBPF program and attaches it to a cgroup.
// the programs redirect DNS requests to a local proxy server.
package ebpf

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/cgroups"
	"github.com/containerd/cgroups/v3/cgroup2"
	"github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
	"github.com/moby/sys/mountinfo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestAttachRedirectorToCGroup_InvalidInputs(t *testing.T) {
	tests := []struct {
		name          string
		cGroupPath    string
		dnsProxyPort  int
		expectedError string
	}{
		{
			name:          "Invalid dnsProxyPort",
			cGroupPath:    "/sys/fs/cgroup/unified",
			dnsProxyPort:  -1,
			expectedError: "dnsProxyPort value -1 out of range for uint32",
		},
		{
			name:          "Invalid cGroupPath",
			cGroupPath:    "/invalid/path",
			dnsProxyPort:  5353,
			expectedError: "opening cgroup path /invalid/path: open /invalid/path: no such file or directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := AttachRedirectorToCGroup(tt.cGroupPath, tt.dnsProxyPort, 0, models.LogOnly)
			assert.EqualError(t, err, tt.expectedError)
		})
	}
}

func TestAttachRedirectorToCGroup_IPFirewall(t *testing.T) {
	tests := []struct {
		name                     string
		firewallMode             models.FirewallMethod
		firewallIPs              string
		expectedLocalhostAllowed bool
	}{
		// Each test will request 127.0.0.1:5000 http
		// server we're running
		{
			name:                     "AllowList: Allows Request to allowed IP",
			firewallMode:             models.AllowList,
			firewallIPs:              "127.0.0.1",
			expectedLocalhostAllowed: true,
		},
		{
			name:                     "AllowList: Blocks Request to other IP",
			firewallMode:             models.AllowList,
			firewallIPs:              "172.1.1.1",
			expectedLocalhostAllowed: false,
		},
		{
			name:                     "BlockList: Allows Request to other IP",
			firewallMode:             models.BlockList,
			firewallIPs:              "172.1.1.1",
			expectedLocalhostAllowed: true,
		},
		{
			name:                     "BlockList: Blocks Request to blocked IP",
			firewallMode:             models.BlockList,
			firewallIPs:              "127.0.0.1",
			expectedLocalhostAllowed: false,
		},
		{
			name:                     "LogMode: Requests allowed",
			firewallMode:             models.LogOnly,
			firewallIPs:              "127.0.0.1",
			expectedLocalhostAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cgroupMan, cgroupPath := createTestCGroup(t)

			redirectDNSToPort := 55555
			firewall, err := AttachRedirectorToCGroup(cgroupPath, redirectDNSToPort, 0, tt.firewallMode)
			require.NoError(t, err)

			// Start a http server to validate normal requests are not impacted
			httpServer := &http.Server{
				Addr: ":5000",
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if _, err := fmt.Fprintln(w, "hi"); err != nil {
						http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					}
				}),
			}
			go func() {
				if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					assert.Error(t, err)
				}
			}()
			defer httpServer.Close()

			err = firewall.AddIPToFirewall(tt.firewallIPs, nil)
			require.NoError(t, err)

			cGroupFD, cleanup, err := fileDescriptorForCGroupPath(cgroupPath)
			require.NoError(t, err)
			defer cleanup()

			cmd := exec.Command("sh", "-c", "curl -sL --connect-timeout 1 http://127.0.0.1:5000")
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			cmd.SysProcAttr = &syscall.SysProcAttr{
				UseCgroupFD: true,
				CgroupFD:    cGroupFD,
			}

			if err := cmd.Start(); err != nil {
				assert.Error(t, err)
			}

			err = cgroupMan.AddProc(uint64(cmd.Process.Pid))
			if err != nil {
				assert.Error(t, err)
			}

			cmdChan := make(chan error, 1)
			go func() {
				err := cmd.Wait()
				cmdChan <- err
			}()

			select {
			case <-time.After(5 * time.Second):
				if tt.expectedLocalhostAllowed {
					t.Fatal("Timeout waiting for command to finish")
				}
			case err := <-cmdChan:
				if tt.expectedLocalhostAllowed {
					require.NoError(t, err)
				} else {
					require.Error(t, err)
				}
			}

			if tt.expectedLocalhostAllowed {
				assert.Empty(t, firewall.BlockedEvents)
			} else {
				assert.Len(t, firewall.BlockedEvents, 1)
				blockedEvent := firewall.BlockedEvents[0]
				assert.False(t, blockedEvent.Allowed)
				// 127.0.0.1 as int
				localhostIP := uint32(0x100007f)
				assert.Equal(t, localhostIP, blockedEvent.Ip)
			}
		})
	}
}

func TestAttachRedirectorToCGroup_IPv6(t *testing.T) {
	cgroupMan, cgroupPath := createTestCGroup(t)

	redirectDNSToPort := 55555
	firewall, err := AttachRedirectorToCGroup(cgroupPath, redirectDNSToPort, 0, models.AllowList)
	require.NoError(t, err)

	// Start a http server on IPv6
	httpServer := &http.Server{
		Addr: "[::1]:5000",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintln(w, "hi")
		}),
	}
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("HTTP server error: %v", err)
		}
	}()
	defer httpServer.Close()

	time.Sleep(time.Second) // Give server time to start

	cGroupFD, cleanup, err := fileDescriptorForCGroupPath(cgroupPath)
	require.NoError(t, err)
	defer cleanup()

	// Try to connect using IPv6
	cmd := exec.Command("sh", "-c", "curl -sL --connect-timeout 1 http://[::1]:5000")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    cGroupFD,
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	err = cgroupMan.AddProc(uint64(cmd.Process.Pid))
	require.NoError(t, err)

	err = cmd.Wait()
	require.Error(t, err)

	assert.GreaterOrEqual(t, len(firewall.BlockedEvents), 1)
}

func createTestCGroup(t *testing.T) (*cgroup2.Manager, string) {
	cgroupDefault := "/sys/fs/cgroup/unified"
	cgroupName := fmt.Sprintf("/test-cgroup-name-%d", time.Now().UnixNano())
	cgroupMan, err := cgroup2.NewManager(cgroupDefault, cgroupName, &cgroup2.Resources{})
	require.NoError(t, err)

	cgroupPath := path.Join(cgroupDefault, cgroupName)
	return cgroupMan, cgroupPath
}

func TestAttachRedirectorToCGroup_RedirectDNS(t *testing.T) {
	cgroupPathForCurrentProcess := getCurrentCGroup()

	redirectDNSToPort := 55555
	firewall, err := AttachRedirectorToCGroup(cgroupPathForCurrentProcess, redirectDNSToPort, 0, models.AllowList)
	require.NoError(t, err)

	err = firewall.AddIPToFirewall("127.0.0.1", nil)
	require.NoError(t, err)

	cGroupFD, cleanup, err := fileDescriptorForCGroupPath(cgroupPathForCurrentProcess)
	require.NoError(t, err)
	defer cleanup()

	// Start a listener on the port that the DNS requests are being redirected to 55555
	listener, err := net.ListenPacket("udp", fmt.Sprintf(":%d", redirectDNSToPort))
	require.NoError(t, err)
	defer listener.Close()

	// Valdiate that the `nslookup api.github.com` command is redirected is redirect to the listener
	connChan := make(chan error)
	go func() {
		packet := make([]byte, 1024)
		_, _, err := listener.ReadFrom(packet)
		if err != nil {
			connChan <- err
		}
		// Validate that the packet is a DNS request for api.github.com
		if len(packet) < 12 {
			connChan <- fmt.Errorf("Packet too short to be a valid DNS request")
		}

		// DNS header is 12 bytes, question section follows
		question := packet[12:]
		expectedQuestion := "\x03api\x06github\x03com\x00"
		if !bytes.Contains(question, []byte(expectedQuestion)) {
			connChan <- fmt.Errorf("Expected DNS question for api.github.com, got %v", string(question))
		}

		// It was a DNS request for api.github.com!
		connChan <- nil
	}()

	cmdFinished := make(chan struct{})

	go func() {
		cmd := exec.Command("sh", "-ce", "nslookup api.github.com")
		// Set the new process to have no ambient capabilities
		cmd.SysProcAttr = &syscall.SysProcAttr{
			UseCgroupFD: true,
			CgroupFD:    cGroupFD,
		}
		output, err := cmd.CombinedOutput()

		// The nslookup command should fail as our udp listener doesn't return valid dns response
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exit status 1")
		fmt.Println(string(output))

		cmdFinished <- struct{}{}
	}()

	select {
	case err := <-connChan:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Timeout waiting for connection")
	case <-cmdFinished:
		t.Fatal("NSLookup command ran but not dns query intercepted")
	}
}

func getCurrentCGroup() string {
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

// fileDescriptorForCGroupPath returns a file descriptor for the cgroup, this is used when attaching a cmd to the cgroup
func fileDescriptorForCGroupPath(path string) (int, func(), error) {
	fd, err := unix.Open(path, unix.O_PATH, 0)
	cleanup := func() {
		_ = unix.Close(fd)
	}
	return fd, cleanup, err
}
