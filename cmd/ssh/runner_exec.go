package ssh

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/creack/pty"
	"github.com/mattn/go-isatty"
	"golang.org/x/term"
)

// execSSHSearchPaths are fallback locations for the ssh executable when not in PATH.
var execSSHSearchPaths = []string{
	"/usr/bin/ssh",
	"/usr/local/bin/ssh",
	`C:\Windows\System32\OpenSSH\ssh.exe`,
}

func findExecSSHPath() (string, error) {
	if path, err := exec.LookPath("ssh"); err == nil {
		return path, nil
	}
	for _, p := range execSSHSearchPaths {
		if isExecutable(p) {
			return p, nil
		}
	}
	return "", errors.New("ssh executable not found in PATH or in common locations")
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode()&0o111 != 0
}

func execExitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}

// RunOpts is shared by both the exec and native SSH runners.
type RunOpts struct {
	User        string
	Hostname    string
	Identity    string // path to identity/private key (alias for private key)
	PrivateKey  string // path to private key file
	Certificate string // path to certificate file (optional)
	PassThrough []string
}

// RunExec runs an interactive SSH session by executing the system ssh binary
// (with a PTY when stdin is a terminal on Unix). Requires ssh to be installed.
func RunExec(opts RunOpts) (int, error) {
	sshPath, err := findExecSSHPath()
	if err != nil {
		return 1, err
	}

	argv := buildExecSSHArgs(sshPath, opts)
	cmd := exec.Command(argv[0], argv[1:]...)

	usePTY := runtime.GOOS != "windows" && isatty.IsTerminal(os.Stdin.Fd())

	if usePTY {
		return runExecWithPTY(cmd)
	}
	return runExecWithoutPTY(cmd)
}

func buildExecSSHArgs(sshPath string, opts RunOpts) []string {
	args := []string{sshPath}
	if opts.User != "" {
		args = append(args, "-l", opts.User)
	}
	keyPath := opts.PrivateKey
	if keyPath == "" {
		keyPath = opts.Identity
	}
	if keyPath != "" {
		args = append(args, "-i", keyPath)
	}
	if opts.Certificate != "" {
		args = append(args, "-o", "CertificateFile="+opts.Certificate)
	}
	args = append(args, opts.Hostname)
	args = append(args, opts.PassThrough...)
	return args
}

func runExecWithPTY(cmd *exec.Cmd) (int, error) {
	// Put local terminal in raw mode so Ctrl+C and Tab are sent as bytes to the
	// remote instead of triggering SIGINT or local completion.
	stdinFd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(stdinFd)
	if err != nil {
		return 1, err
	}
	defer func() { _ = term.Restore(stdinFd, oldState) }()

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return 1, err
	}
	defer ptmx.Close()

	// Initial terminal size from our stdin
	if err := pty.InheritSize(os.Stdin, ptmx); err != nil {
		// Non-fatal: continue without initial size
	}

	// Resize PTY on SIGWINCH
	winchCh := make(chan os.Signal, 1)
	signal.Notify(winchCh, syscall.SIGWINCH)
	go func() {
		for range winchCh {
			_ = pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	defer signal.Stop(winchCh)
	// Trigger initial resize (in case InheritSize failed above)
	winchCh <- syscall.SIGWINCH

	// Forward only SIGTERM to the child (e.g. from kill). Ctrl+C is sent as a
	// byte in raw mode and goes through the PTY to the remote.
	forwardCh := make(chan os.Signal, 1)
	signal.Notify(forwardCh, syscall.SIGTERM)
	go func() {
		for sig := range forwardCh {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()
	defer signal.Stop(forwardCh)

	// Copy stdin -> pty and pty -> stdout
	go func() { _, _ = io.Copy(ptmx, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, ptmx)

	if err := cmd.Wait(); err != nil {
		return execExitCode(err), nil
	}
	return 0, nil
}

func runExecWithoutPTY(cmd *exec.Cmd) (int, error) {
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return execExitCode(err), nil
	}
	return 0, nil
}
