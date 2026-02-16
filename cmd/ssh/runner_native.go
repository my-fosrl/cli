package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/mattn/go-isatty"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const nativeDefaultSSHPort = "22"

// RunNative runs an interactive SSH session using the pure-Go client (golang.org/x/crypto/ssh).
// It does not use the system ssh binary. Requires a private key (opts.Identity or opts.PrivateKey); opts.Certificate is optional.
func RunNative(opts RunOpts) (int, error) {
	addr, err := nativeSSHAddress(opts.Hostname)
	if err != nil {
		return 1, err
	}

	config, err := nativeSSHClientConfig(opts)
	if err != nil {
		return 1, err
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return 1, fmt.Errorf("ssh dial: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return 1, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	stdinFd := int(os.Stdin.Fd())
	useRaw := isatty.IsTerminal(uintptr(stdinFd)) && runtime.GOOS != "windows"
	if useRaw {
		oldState, err := term.MakeRaw(stdinFd)
		if err != nil {
			return 1, err
		}
		defer func() { _ = term.Restore(stdinFd, oldState) }()
	}

	width, height := 80, 24
	if useRaw {
		if w, h, err := term.GetSize(stdinFd); err == nil {
			width, height = w, h
		}
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return 1, fmt.Errorf("request pty: %w", err)
	}

	// Resize on SIGWINCH (Unix, TTY only)
	if useRaw {
		winchCh := make(chan os.Signal, 1)
		signal.Notify(winchCh, syscall.SIGWINCH)
		go func() {
			for range winchCh {
				if w, h, err := term.GetSize(stdinFd); err == nil {
					_ = session.WindowChange(h, w)
				}
			}
		}()
		defer signal.Stop(winchCh)
		winchCh <- syscall.SIGWINCH
	}

	session.Stdin = os.Stdin
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Shell(); err != nil {
		return 1, fmt.Errorf("shell: %w", err)
	}

	if err := session.Wait(); err != nil {
		// Session ended with an error (e.g. exit 1 on remote). No numeric code in protocol.
		return 1, nil
	}
	return 0, nil
}

func looksLikeCertificate(data []byte) bool {
	s := string(data)
	return strings.Contains(s, "-cert-v01@openssh.com") || strings.Contains(s, "-cert@openssh.com") ||
		strings.Contains(s, "ssh-rsa-cert") || strings.Contains(s, "ssh-ed25519-cert") || strings.Contains(s, "ecdsa-sha2-nistp256-cert")
}

func nativeSSHAddress(hostname string) (string, error) {
	if hostname == "" {
		return "", errors.New("hostname is empty")
	}
	if _, _, err := net.SplitHostPort(hostname); err == nil {
		return hostname, nil
	}
	return net.JoinHostPort(hostname, nativeDefaultSSHPort), nil
}

func nativeSSHClientConfig(opts RunOpts) (*ssh.ClientConfig, error) {
	keyPath := opts.PrivateKey
	if keyPath == "" {
		keyPath = opts.Identity
	}
	if keyPath == "" {
		return nil, errors.New("private key path required (set -i or --private-key)")
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		if looksLikeCertificate(key) {
			return nil, fmt.Errorf("parse private key: %w (hint: %s looks like a certificate file; use --certificate for the cert and -i or --private-key for the private key file)", err, keyPath)
		}
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	authSigner := signer
	if opts.Certificate != "" {
		certBytes, err := os.ReadFile(opts.Certificate)
		if err != nil {
			return nil, fmt.Errorf("read certificate: %w", err)
		}
		// ParseAuthorizedKey handles OpenSSH cert format (single/multi-line, wrapped base64).
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			return nil, fmt.Errorf("certificate file is not an SSH certificate")
		}
		authSigner, err = ssh.NewCertSigner(cert, signer)
		if err != nil {
			return nil, fmt.Errorf("create cert signer: %w", err)
		}
	}

	user := opts.User
	if user == "" {
		user = os.Getenv("USER")
		if user == "" {
			user = os.Getenv("USERNAME")
		}
		if user == "" {
			user = "root"
		}
	}

	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(authSigner)},
		// Host key verification disabled for simplicity; can be enhanced with known_hosts later.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}
