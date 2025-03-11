// Code generated by mockery. DO NOT EDIT.

package ebpf

import (
	models "github.com/lawrencegripper/actions-dns-monitoring/pkg/models"
	mock "github.com/stretchr/testify/mock"
)

// MockDnsFirewall is an autogenerated mock type for the DnsFirewall type
type MockDnsFirewall struct {
	mock.Mock
}

type MockDnsFirewall_Expecter struct {
	mock *mock.Mock
}

func (_m *MockDnsFirewall) EXPECT() *MockDnsFirewall_Expecter {
	return &MockDnsFirewall_Expecter{mock: &_m.Mock}
}

// AllowIPThroughFirewall provides a mock function with given fields: ip, reason
func (_m *MockDnsFirewall) AllowIPThroughFirewall(ip string, reason *Reason) error {
	ret := _m.Called(ip, reason)

	if len(ret) == 0 {
		panic("no return value specified for AllowIPThroughFirewall")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(string, *Reason) error); ok {
		r0 = rf(ip, reason)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockDnsFirewall_AllowIPThroughFirewall_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'AllowIPThroughFirewall'
type MockDnsFirewall_AllowIPThroughFirewall_Call struct {
	*mock.Call
}

// AllowIPThroughFirewall is a helper method to define mock.On call
//   - ip string
//   - reason *Reason
func (_e *MockDnsFirewall_Expecter) AllowIPThroughFirewall(ip interface{}, reason interface{}) *MockDnsFirewall_AllowIPThroughFirewall_Call {
	return &MockDnsFirewall_AllowIPThroughFirewall_Call{Call: _e.mock.On("AllowIPThroughFirewall", ip, reason)}
}

func (_c *MockDnsFirewall_AllowIPThroughFirewall_Call) Run(run func(ip string, reason *Reason)) *MockDnsFirewall_AllowIPThroughFirewall_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(*Reason))
	})
	return _c
}

func (_c *MockDnsFirewall_AllowIPThroughFirewall_Call) Return(_a0 error) *MockDnsFirewall_AllowIPThroughFirewall_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockDnsFirewall_AllowIPThroughFirewall_Call) RunAndReturn(run func(string, *Reason) error) *MockDnsFirewall_AllowIPThroughFirewall_Call {
	_c.Call.Return(run)
	return _c
}

// GetFirewallMethod provides a mock function with no fields
func (_m *MockDnsFirewall) GetFirewallMethod() models.FirewallMethod {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for GetFirewallMethod")
	}

	var r0 models.FirewallMethod
	if rf, ok := ret.Get(0).(func() models.FirewallMethod); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(models.FirewallMethod)
	}

	return r0
}

// MockDnsFirewall_GetFirewallMethod_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetFirewallMethod'
type MockDnsFirewall_GetFirewallMethod_Call struct {
	*mock.Call
}

// GetFirewallMethod is a helper method to define mock.On call
func (_e *MockDnsFirewall_Expecter) GetFirewallMethod() *MockDnsFirewall_GetFirewallMethod_Call {
	return &MockDnsFirewall_GetFirewallMethod_Call{Call: _e.mock.On("GetFirewallMethod")}
}

func (_c *MockDnsFirewall_GetFirewallMethod_Call) Run(run func()) *MockDnsFirewall_GetFirewallMethod_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockDnsFirewall_GetFirewallMethod_Call) Return(_a0 models.FirewallMethod) *MockDnsFirewall_GetFirewallMethod_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockDnsFirewall_GetFirewallMethod_Call) RunAndReturn(run func() models.FirewallMethod) *MockDnsFirewall_GetFirewallMethod_Call {
	_c.Call.Return(run)
	return _c
}

// GetPidAndCommandFromDNSTransactionId provides a mock function with given fields: dnsTransactionId
func (_m *MockDnsFirewall) GetPidAndCommandFromDNSTransactionId(dnsTransactionId uint16) (uint32, string, error) {
	ret := _m.Called(dnsTransactionId)

	if len(ret) == 0 {
		panic("no return value specified for GetPidAndCommandFromDNSTransactionId")
	}

	var r0 uint32
	var r1 string
	var r2 error
	if rf, ok := ret.Get(0).(func(uint16) (uint32, string, error)); ok {
		return rf(dnsTransactionId)
	}
	if rf, ok := ret.Get(0).(func(uint16) uint32); ok {
		r0 = rf(dnsTransactionId)
	} else {
		r0 = ret.Get(0).(uint32)
	}

	if rf, ok := ret.Get(1).(func(uint16) string); ok {
		r1 = rf(dnsTransactionId)
	} else {
		r1 = ret.Get(1).(string)
	}

	if rf, ok := ret.Get(2).(func(uint16) error); ok {
		r2 = rf(dnsTransactionId)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// MockDnsFirewall_GetPidAndCommandFromDNSTransactionId_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetPidAndCommandFromDNSTransactionId'
type MockDnsFirewall_GetPidAndCommandFromDNSTransactionId_Call struct {
	*mock.Call
}

// GetPidAndCommandFromDNSTransactionId is a helper method to define mock.On call
//   - dnsTransactionId uint16
func (_e *MockDnsFirewall_Expecter) GetPidAndCommandFromDNSTransactionId(dnsTransactionId interface{}) *MockDnsFirewall_GetPidAndCommandFromDNSTransactionId_Call {
	return &MockDnsFirewall_GetPidAndCommandFromDNSTransactionId_Call{Call: _e.mock.On("GetPidAndCommandFromDNSTransactionId", dnsTransactionId)}
}

func (_c *MockDnsFirewall_GetPidAndCommandFromDNSTransactionId_Call) Run(run func(dnsTransactionId uint16)) *MockDnsFirewall_GetPidAndCommandFromDNSTransactionId_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(uint16))
	})
	return _c
}

func (_c *MockDnsFirewall_GetPidAndCommandFromDNSTransactionId_Call) Return(_a0 uint32, _a1 string, _a2 error) *MockDnsFirewall_GetPidAndCommandFromDNSTransactionId_Call {
	_c.Call.Return(_a0, _a1, _a2)
	return _c
}

func (_c *MockDnsFirewall_GetPidAndCommandFromDNSTransactionId_Call) RunAndReturn(run func(uint16) (uint32, string, error)) *MockDnsFirewall_GetPidAndCommandFromDNSTransactionId_Call {
	_c.Call.Return(run)
	return _c
}

// TrackIPToDomain provides a mock function with given fields: ip, domain
func (_m *MockDnsFirewall) TrackIPToDomain(ip string, domain string) {
	_m.Called(ip, domain)
}

// MockDnsFirewall_TrackIPToDomain_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'TrackIPToDomain'
type MockDnsFirewall_TrackIPToDomain_Call struct {
	*mock.Call
}

// TrackIPToDomain is a helper method to define mock.On call
//   - ip string
//   - domain string
func (_e *MockDnsFirewall_Expecter) TrackIPToDomain(ip interface{}, domain interface{}) *MockDnsFirewall_TrackIPToDomain_Call {
	return &MockDnsFirewall_TrackIPToDomain_Call{Call: _e.mock.On("TrackIPToDomain", ip, domain)}
}

func (_c *MockDnsFirewall_TrackIPToDomain_Call) Run(run func(ip string, domain string)) *MockDnsFirewall_TrackIPToDomain_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string), args[1].(string))
	})
	return _c
}

func (_c *MockDnsFirewall_TrackIPToDomain_Call) Return() *MockDnsFirewall_TrackIPToDomain_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockDnsFirewall_TrackIPToDomain_Call) RunAndReturn(run func(string, string)) *MockDnsFirewall_TrackIPToDomain_Call {
	_c.Run(run)
	return _c
}

// NewMockDnsFirewall creates a new instance of MockDnsFirewall. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockDnsFirewall(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockDnsFirewall {
	mock := &MockDnsFirewall{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
