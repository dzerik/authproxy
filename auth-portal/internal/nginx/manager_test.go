package nginx

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewManager(t *testing.T) {
	t.Run("with custom pid file", func(t *testing.T) {
		m := NewManager("/etc/nginx/nginx.conf", "/custom/nginx.pid")
		if m == nil {
			t.Fatal("NewManager returned nil")
		}
		if m.configPath != "/etc/nginx/nginx.conf" {
			t.Errorf("configPath = %s, want /etc/nginx/nginx.conf", m.configPath)
		}
		if m.pidFile != "/custom/nginx.pid" {
			t.Errorf("pidFile = %s, want /custom/nginx.pid", m.pidFile)
		}
		if m.running {
			t.Error("running should be false initially")
		}
	})

	t.Run("with empty pid file uses default", func(t *testing.T) {
		m := NewManager("/etc/nginx/nginx.conf", "")
		if m.pidFile != "/var/run/nginx.pid" {
			t.Errorf("pidFile = %s, want /var/run/nginx.pid", m.pidFile)
		}
	})
}

func TestManager_IsRunning(t *testing.T) {
	m := NewManager("/etc/nginx/nginx.conf", "/var/run/nginx.pid")

	// Initially not running
	if m.IsRunning() {
		t.Error("IsRunning should return false initially")
	}

	// Manually set running state for testing
	m.running = true
	if !m.IsRunning() {
		t.Error("IsRunning should return true when running is set")
	}

	m.running = false
	if m.IsRunning() {
		t.Error("IsRunning should return false when running is false")
	}
}

func TestManager_Reload_NotRunning(t *testing.T) {
	m := NewManager("/etc/nginx/nginx.conf", "/var/run/nginx.pid")

	err := m.Reload()
	if err == nil {
		t.Error("Reload should return error when nginx is not running")
	}

	expectedMsg := "nginx is not running"
	if err.Error() != expectedMsg {
		t.Errorf("error = %q, want %q", err.Error(), expectedMsg)
	}
}

func TestManager_Reopen_NotRunning(t *testing.T) {
	m := NewManager("/etc/nginx/nginx.conf", "/var/run/nginx.pid")

	err := m.Reopen()
	if err == nil {
		t.Error("Reopen should return error when nginx is not running")
	}

	expectedMsg := "nginx is not running"
	if err.Error() != expectedMsg {
		t.Errorf("error = %q, want %q", err.Error(), expectedMsg)
	}
}

func TestManager_HealthCheck_NotRunning(t *testing.T) {
	m := NewManager("/etc/nginx/nginx.conf", "/var/run/nginx.pid")

	err := m.HealthCheck()
	if err == nil {
		t.Error("HealthCheck should return error when nginx is not running")
	}

	expectedMsg := "nginx is not running"
	if err.Error() != expectedMsg {
		t.Errorf("error = %q, want %q", err.Error(), expectedMsg)
	}
}

func TestManager_GetPID_NoProcess(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "nginx.pid")

	m := NewManager("/etc/nginx/nginx.conf", pidFile)

	// No PID file exists
	_, err := m.GetPID()
	if err == nil {
		t.Error("GetPID should return error when no PID file exists")
	}
}

func TestManager_GetPID_FromPIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "nginx.pid")

	// Create PID file with valid content
	err := os.WriteFile(pidFile, []byte("12345"), 0644)
	if err != nil {
		t.Fatalf("failed to create PID file: %v", err)
	}

	m := NewManager("/etc/nginx/nginx.conf", pidFile)

	pid, err := m.GetPID()
	if err != nil {
		t.Fatalf("GetPID failed: %v", err)
	}

	if pid != 12345 {
		t.Errorf("PID = %d, want 12345", pid)
	}
}

func TestManager_GetPID_InvalidPIDFile(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "nginx.pid")

	// Create PID file with invalid content
	err := os.WriteFile(pidFile, []byte("not-a-number"), 0644)
	if err != nil {
		t.Fatalf("failed to create PID file: %v", err)
	}

	m := NewManager("/etc/nginx/nginx.conf", pidFile)

	_, err = m.GetPID()
	if err == nil {
		t.Error("GetPID should return error for invalid PID file content")
	}
}

func TestManager_readPID(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("valid PID file", func(t *testing.T) {
		pidFile := filepath.Join(tmpDir, "valid.pid")
		err := os.WriteFile(pidFile, []byte("99999\n"), 0644)
		if err != nil {
			t.Fatalf("failed to create PID file: %v", err)
		}

		m := NewManager("/etc/nginx/nginx.conf", pidFile)
		pid, err := m.readPID()
		if err != nil {
			t.Fatalf("readPID failed: %v", err)
		}
		if pid != 99999 {
			t.Errorf("PID = %d, want 99999", pid)
		}
	})

	t.Run("PID with whitespace", func(t *testing.T) {
		pidFile := filepath.Join(tmpDir, "whitespace.pid")
		err := os.WriteFile(pidFile, []byte("  42  \n"), 0644)
		if err != nil {
			t.Fatalf("failed to create PID file: %v", err)
		}

		m := NewManager("/etc/nginx/nginx.conf", pidFile)
		pid, err := m.readPID()
		if err != nil {
			t.Fatalf("readPID failed: %v", err)
		}
		if pid != 42 {
			t.Errorf("PID = %d, want 42", pid)
		}
	})

	t.Run("nonexistent PID file", func(t *testing.T) {
		pidFile := filepath.Join(tmpDir, "nonexistent.pid")
		m := NewManager("/etc/nginx/nginx.conf", pidFile)
		_, err := m.readPID()
		if err == nil {
			t.Error("readPID should return error for nonexistent file")
		}
	})

	t.Run("empty PID file", func(t *testing.T) {
		pidFile := filepath.Join(tmpDir, "empty.pid")
		err := os.WriteFile(pidFile, []byte(""), 0644)
		if err != nil {
			t.Fatalf("failed to create PID file: %v", err)
		}

		m := NewManager("/etc/nginx/nginx.conf", pidFile)
		_, err = m.readPID()
		if err == nil {
			t.Error("readPID should return error for empty file")
		}
	})
}

func TestManager_signal_NoProcess(t *testing.T) {
	tmpDir := t.TempDir()
	pidFile := filepath.Join(tmpDir, "nginx.pid")

	m := NewManager("/etc/nginx/nginx.conf", pidFile)
	// cmd is nil and no PID file

	err := m.signal(0) // Signal 0 is used for checking if process exists
	if err == nil {
		t.Error("signal should return error when no process exists")
	}
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
