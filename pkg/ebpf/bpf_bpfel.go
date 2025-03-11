// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfEvent struct {
	Pid               uint32
	Port              uint16
	Allowed           bool
	_                 [1]byte
	Ip                uint32
	OriginalIp        uint32
	ByPassType        uint16
	DnsTransactionId  uint16
	PidResolved       bool
	HasBeenRedirected bool
	_                 [2]byte
}

// loadBpf returns the embedded CollectionSpec for bpf.
func loadBpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_BpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load bpf: %w", err)
	}

	return spec, err
}

// loadBpfObjects loads bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*bpfObjects
//	*bpfPrograms
//	*bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadBpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadBpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfSpecs struct {
	bpfProgramSpecs
	bpfMapSpecs
}

// bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfProgramSpecs struct {
	CgSockOps       *ebpf.ProgramSpec `ebpf:"cg_sock_ops"`
	CgroupSkbEgress *ebpf.ProgramSpec `ebpf:"cgroup_skb_egress"`
	Connect4        *ebpf.ProgramSpec `ebpf:"connect4"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	Events                   *ebpf.MapSpec `ebpf:"events"`
	FirewallIpMap            *ebpf.MapSpec `ebpf:"firewall_ip_map"`
	SockClientToOriginalIp   *ebpf.MapSpec `ebpf:"sock_client_to_original_ip"`
	SockClientToOriginalPort *ebpf.MapSpec `ebpf:"sock_client_to_original_port"`
	SocketPidMap             *ebpf.MapSpec `ebpf:"socket_pid_map"`
	SrcPortToSockClient      *ebpf.MapSpec `ebpf:"src_port_to_sock_client"`
}

// bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return _BpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

// bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfMaps struct {
	Events                   *ebpf.Map `ebpf:"events"`
	FirewallIpMap            *ebpf.Map `ebpf:"firewall_ip_map"`
	SockClientToOriginalIp   *ebpf.Map `ebpf:"sock_client_to_original_ip"`
	SockClientToOriginalPort *ebpf.Map `ebpf:"sock_client_to_original_port"`
	SocketPidMap             *ebpf.Map `ebpf:"socket_pid_map"`
	SrcPortToSockClient      *ebpf.Map `ebpf:"src_port_to_sock_client"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.Events,
		m.FirewallIpMap,
		m.SockClientToOriginalIp,
		m.SockClientToOriginalPort,
		m.SocketPidMap,
		m.SrcPortToSockClient,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	CgSockOps       *ebpf.Program `ebpf:"cg_sock_ops"`
	CgroupSkbEgress *ebpf.Program `ebpf:"cgroup_skb_egress"`
	Connect4        *ebpf.Program `ebpf:"connect4"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.CgSockOps,
		p.CgroupSkbEgress,
		p.Connect4,
	)
}

func _BpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed bpf_bpfel.o
var _BpfBytes []byte
