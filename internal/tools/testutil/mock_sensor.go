package testutil

import (
	"time"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// MockSensor is a mock implementation of lc.Sensor for testing
// It allows tests to specify behavior for each method via function fields
type MockSensor struct {
	// Sensor Fields
	SID        string
	IsIsolated bool
	LastError  error
	Hostname   string
	Platform   string
	Tags       []string

	// Method Functions
	IsolateFromNetworkFunc func() error
	RejoinNetworkFunc      func() error
	UpdateFunc             func() *lc.Sensor
	AddTagFunc             func(tag string, ttl time.Duration) error
	RemoveTagFunc          func(tag string) error
	DeleteFunc             func() error
	SimpleRequestFunc      func(command string, opts lc.SimpleRequestOptions) (lc.Dict, error)
}

// IsolateFromNetwork mocks network isolation
func (m *MockSensor) IsolateFromNetwork() error {
	if m.IsolateFromNetworkFunc != nil {
		return m.IsolateFromNetworkFunc()
	}
	m.IsIsolated = true
	return nil
}

// RejoinNetwork mocks network rejoin
func (m *MockSensor) RejoinNetwork() error {
	if m.RejoinNetworkFunc != nil {
		return m.RejoinNetworkFunc()
	}
	m.IsIsolated = false
	return nil
}

// Update mocks sensor update
func (m *MockSensor) Update() *lc.Sensor {
	if m.UpdateFunc != nil {
		return m.UpdateFunc()
	}
	// Return a real lc.Sensor with fields populated from mock
	return &lc.Sensor{
		SID:        m.SID,
		IsIsolated: m.IsIsolated,
		LastError:  m.LastError,
	}
}

// AddTag mocks tag addition
func (m *MockSensor) AddTag(tag string, ttl time.Duration) error {
	if m.AddTagFunc != nil {
		return m.AddTagFunc(tag, ttl)
	}
	// Add tag to internal list if not already present
	for _, t := range m.Tags {
		if t == tag {
			return nil
		}
	}
	m.Tags = append(m.Tags, tag)
	return nil
}

// RemoveTag mocks tag removal
func (m *MockSensor) RemoveTag(tag string) error {
	if m.RemoveTagFunc != nil {
		return m.RemoveTagFunc(tag)
	}
	// Remove tag from internal list
	for i, t := range m.Tags {
		if t == tag {
			m.Tags = append(m.Tags[:i], m.Tags[i+1:]...)
			return nil
		}
	}
	return nil
}

// Delete mocks sensor deletion
func (m *MockSensor) Delete() error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc()
	}
	return nil
}

// SimpleRequest mocks sensor command execution
func (m *MockSensor) SimpleRequest(command string, opts lc.SimpleRequestOptions) (lc.Dict, error) {
	if m.SimpleRequestFunc != nil {
		return m.SimpleRequestFunc(command, opts)
	}
	// Return empty response by default
	return lc.Dict{}, nil
}

// NewMockSensor creates a new MockSensor with default values
func NewMockSensor(sid string) *MockSensor {
	return &MockSensor{
		SID:        sid,
		IsIsolated: false,
		LastError:  nil,
		Hostname:   "test-host",
		Platform:   "windows",
		Tags:       []string{},
	}
}
