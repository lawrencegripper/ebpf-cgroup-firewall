// Code generated by bpf2go; DO NOT EDIT.
//go:build mips || mips64 || ppc64 || s390x

package ebpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type bpfEvent struct {
	Pid        uint32
	Port       uint16
	Allowed    bool
	_          [1]byte
	Ip         uint32
	OriginalIp uint32
	IsDns      bool
	_          [3]byte
}

type bpfSvcAddr struct {
	Addr uint32
	Port uint16
	_    [2]byte
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
	CgroupSkbEgress *ebpf.ProgramSpec `ebpf:"cgroup_skb_egress"`
	Connect4        *ebpf.ProgramSpec `ebpf:"connect4"`
	Getpeername4    *ebpf.ProgramSpec `ebpf:"getpeername4"`
}

// bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type bpfMapSpecs struct {
	AllowedIpsMap  *ebpf.MapSpec `ebpf:"allowed_ips_map"`
	Events         *ebpf.MapSpec `ebpf:"events"`
	ServiceMapping *ebpf.MapSpec `ebpf:"service_mapping"`
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
	AllowedIpsMap  *ebpf.Map `ebpf:"allowed_ips_map"`
	Events         *ebpf.Map `ebpf:"events"`
	ServiceMapping *ebpf.Map `ebpf:"service_mapping"`
}

func (m *bpfMaps) Close() error {
	return _BpfClose(
		m.AllowedIpsMap,
		m.Events,
		m.ServiceMapping,
	)
}

// bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadBpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type bpfPrograms struct {
	CgroupSkbEgress *ebpf.Program `ebpf:"cgroup_skb_egress"`
	Connect4        *ebpf.Program `ebpf:"connect4"`
	Getpeername4    *ebpf.Program `ebpf:"getpeername4"`
}

func (p *bpfPrograms) Close() error {
	return _BpfClose(
		p.CgroupSkbEgress,
		p.Connect4,
		p.Getpeername4,
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
//go:embed bpf_bpfeb.o
var _BpfBytes []byte
