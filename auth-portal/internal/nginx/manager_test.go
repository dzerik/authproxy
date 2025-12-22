package nginx

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManager(t *testing.T) {
	t.Run("with custom pid file", func(t *testing.T) {
		m := NewManager("/etc/nginx/nginx.conf", "/custom/nginx.pid")
		require.NotNil(t, m)
		assert.Equal(t, "/etc/nginx/nginx.conf", m.configPath)
		assert.Equal(t, "/custom/nginx.pid", m.pidFile)
		assert.False(t, m.running)
	})

	t.Run("with empty pid file uses default", func(t *testing.T) {
		m := NewManager("/etc/nginx/nginx.conf", "")
		assert.Equal(t, "/var/run/nginx.pid", m.pidFile)
	})
}

func TestManager_IsRunning(t *testing.T) {
	m := NewManager("/etc/nginx/nginx.conf", "/var/run/nginx.pid")

	// Initially not running
	assert.False(t, m.IsRunning())

	// Manually set running state for testing
	m.running = true
	assert.True(t, m.IsRunning())

	m.running = false
	assert.False(t, m.IsRunning())
}

func TestManager_Reload_NotRunning(t *testing.T) {
	m := NewManager("/etc/nginx/nginx.conf", "/var/run/nginx.pid")

	err := m.Reload()
	require.Error(t, err)

	expectedMsg := "nginx is not running"
	assert.Equal(t, expectedMsg, err.Error())
}

func TestManager_Reopen_NotRunning(t *testing.T) {
	m := NewManager("/etc/nginx/nginx.conf", "/var/run/nginx.pid")

	err := m.Reopen()
	require.Error(t, err)

	expectedMsg := "nginx is not running"
	assert.Equal(t, expectedMsg, err.Error())
}

func TestManager_HealthCheck_NotRunning(t *testing.T) {
	m := NewManager("/etc/nginx/nginx.conf", "/var/run/nginx.pid")

	err := m.HealthCheck()
	require.Error(t, err)

	expectedMsg := "nginx is not running"
	assert.Equal(t, expectedMsg, err.Error())
}

func TestManager_GetPID_NoProcess(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "nginx.pid")

	m := NewManager("/etc/nginx/nginx.conf", pidFile)

	// No PID file exists
	_, err := m.GetPID()
	require.Error(t, err)
}

func TestManager_GetPID_FromPIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "nginx.pid")

	// Create PID file with valid content
	err := os.WriteFile(pidFile, []byte("12345"), 0644)
	require.NoError(t, err)

	m := NewManager("/etc/nginx/nginx.conf", pidFile)

	pid, err := m.GetPID()
	require.NoError(t, err)
	assert.Equal(t, 12345, pid)
}

func TestManager_GetPID_InvalidPIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "nginx.pid")

	// Create PID file with invalid content
	err := os.WriteFile(pidFile, []byte("not-a-number"), 0644)
	require.NoError(t, err)

	m := NewManager("/etc/nginx/nginx.conf", pidFile)

	_, err = m.GetPID()
	require.Error(t, err)
}

func TestManager_readPID(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("valid PID file", func(t *testing.T) {
		pidFile := filepath.Join(tmpDir, "valid.pid")
		err := os.WriteFile(pidFile, []byte("99999\n"), 0644)
		require.NoError(t, err)

		m := NewManager("/etc/nginx/nginx.conf", pidFile)
		pid, err := m.readPID()
		require.NoError(t, err)
		assert.Equal(t, 99999, pid)
	})

	t.Run("PID with whitespace", func(t *testing.T) {
		pidFile := filepath.Join(tmpDir, "whitespace.pid")
		err := os.WriteFile(pidFile, []byte("  42  \n"), 0644)
		require.NoError(t, err)

		m := NewManager("/etc/nginx/nginx.conf", pidFile)
		pid, err := m.readPID()
		require.NoError(t, err)
		assert.Equal(t, 42, pid)
	})

	t.Run("nonexistent PID file", func(t *testing.T) {
		pidFile := filepath.Join(tmpDir, "nonexistent.pid")
		m := NewManager("/etc/nginx/nginx.conf", pidFile)
		_, err := m.readPID()
		require.Error(t, err)
	})

	t.Run("empty PID file", func(t *testing.T) {
		pidFile := filepath.Join(tmpDir, "empty.pid")
		err := os.WriteFile(pidFile, []byte(""), 0644)
		require.NoError(t, err)

		m := NewManager("/etc/nginx/nginx.conf", pidFile)
		_, err = m.readPID()
		require.Error(t, err)
	})
}

func TestManager_signal_NoProcess(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "nginx.pid")

	m := NewManager("/etc/nginx/nginx.conf", pidFile)
	// cmd is nil and no PID file

	err := m.signal(0) // Signal 0 is used for checking if process exists
	require.Error(t, err)
}

func TestManager_Concurrency(t *testing.T) {
	m := NewManager("/etc/nginx/nginx.conf", "/var/run/nginx.pid")

	// Test concurrent access to IsRunning
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			_ = m.IsRunning()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func BenchmarkManager_IsRunning(b *testing.B) {
	m := NewManager("/etc/nginx/nginx.conf", "/var/run/nginx.pid")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.IsRunning()
	}
}
