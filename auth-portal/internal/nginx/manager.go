package nginx

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Manager manages the nginx process lifecycle
type Manager struct {
	configPath string
	pidFile    string
	cmd        *exec.Cmd
	mu         sync.RWMutex
	running    bool
}

// NewManager creates a new nginx manager
func NewManager(configPath, pidFile string) *Manager {
	if pidFile == "" {
		pidFile = "/var/run/nginx.pid"
	}
	return &Manager{
		configPath: configPath,
		pidFile:    pidFile,
	}
}

// Start starts the nginx process
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("nginx is already running")
	}

	// Validate config before starting
	if err := m.validateConfig(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Start nginx
	m.cmd = exec.CommandContext(ctx, "nginx", "-c", m.configPath, "-g", "daemon off;")
	m.cmd.Stdout = os.Stdout
	m.cmd.Stderr = os.Stderr

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start nginx: %w", err)
	}

	m.running = true

	// Wait for nginx in background
	go func() {
		m.cmd.Wait()
		m.mu.Lock()
		m.running = false
		m.mu.Unlock()
	}()

	// Wait for nginx to be ready
	return m.waitForReady(5 * time.Second)
}

// Stop stops the nginx process gracefully
func (m *Manager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	// Send SIGQUIT for graceful shutdown
	if err := m.signal(syscall.SIGQUIT); err != nil {
		// Fallback to SIGTERM
		if err := m.signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("failed to stop nginx: %w", err)
		}
	}

	// Wait for process to exit
	done := make(chan struct{})
	go func() {
		if m.cmd != nil && m.cmd.Process != nil {
			m.cmd.Wait()
		}
		close(done)
	}()

	select {
	case <-done:
		m.running = false
		return nil
	case <-ctx.Done():
		// Force kill
		m.signal(syscall.SIGKILL)
		m.running = false
		return ctx.Err()
	}
}

// Reload reloads the nginx configuration
func (m *Manager) Reload() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return fmt.Errorf("nginx is not running")
	}

	// Validate config before reloading
	if err := m.validateConfig(); err != nil {
		return fmt.Errorf("config validation failed: %w", err)
	}

	// Send SIGHUP to reload
	if err := m.signal(syscall.SIGHUP); err != nil {
		return fmt.Errorf("failed to reload nginx: %w", err)
	}

	return nil
}

// Reopen reopens log files
func (m *Manager) Reopen() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return fmt.Errorf("nginx is not running")
	}

	// Send SIGUSR1 to reopen logs
	return m.signal(syscall.SIGUSR1)
}

// IsRunning returns true if nginx is running
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// TestConfig tests the nginx configuration
func (m *Manager) TestConfig() error {
	return m.validateConfig()
}

// validateConfig validates the nginx configuration file
func (m *Manager) validateConfig() error {
	cmd := exec.Command("nginx", "-t", "-c", m.configPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx config test failed: %s", string(output))
	}
	return nil
}

// signal sends a signal to the nginx process
func (m *Manager) signal(sig syscall.Signal) error {
	if m.cmd == nil || m.cmd.Process == nil {
		// Try to find process by PID file
		pid, err := m.readPID()
		if err != nil {
			return fmt.Errorf("no nginx process found")
		}
		process, err := os.FindProcess(pid)
		if err != nil {
			return fmt.Errorf("failed to find process: %w", err)
		}
		return process.Signal(sig)
	}

	return m.cmd.Process.Signal(sig)
}

// readPID reads the nginx PID from the PID file
func (m *Manager) readPID() (int, error) {
	data, err := os.ReadFile(m.pidFile)
	if err != nil {
		return 0, err
	}

	var pid int
	_, err = fmt.Sscanf(string(data), "%d", &pid)
	if err != nil {
		return 0, err
	}

	return pid, nil
}

// waitForReady waits for nginx to be ready
func (m *Manager) waitForReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		// Check if process is still running
		if m.cmd != nil && m.cmd.Process != nil {
			if err := m.cmd.Process.Signal(syscall.Signal(0)); err != nil {
				return fmt.Errorf("nginx process died: %w", err)
			}
		}

		// Check if PID file exists
		if _, err := os.Stat(m.pidFile); err == nil {
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	return fmt.Errorf("nginx failed to start within %v", timeout)
}

// HealthCheck performs a health check on nginx
func (m *Manager) HealthCheck() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.running {
		return fmt.Errorf("nginx is not running")
	}

	// Check if process is alive
	if m.cmd != nil && m.cmd.Process != nil {
		if err := m.cmd.Process.Signal(syscall.Signal(0)); err != nil {
			m.mu.RUnlock()
			m.mu.Lock()
			m.running = false
			m.mu.Unlock()
			m.mu.RLock()
			return fmt.Errorf("nginx process is dead")
		}
	}

	return nil
}

// GetPID returns the nginx process ID
func (m *Manager) GetPID() (int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.cmd != nil && m.cmd.Process != nil {
		return m.cmd.Process.Pid, nil
	}

	return m.readPID()
}
