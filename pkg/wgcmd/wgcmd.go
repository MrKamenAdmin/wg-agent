package wgcmd

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// WGCmd wraps WireGuard command-line operations
type WGCmd struct {
	wgPath      string
	wgQuickPath string
}

// PeerStatus represents runtime status of a peer
type PeerStatus struct {
	PublicKey           string
	Endpoint            string
	AllowedIPs          []string
	LatestHandshake     time.Time
	TransferRx          int64
	TransferTx          int64
	PersistentKeepalive int
}

// InterfaceStatus represents runtime status of the interface
type InterfaceStatus struct {
	PublicKey  string
	ListenPort int
	Peers      []PeerStatus
}

// New creates a new WGCmd instance
func New() *WGCmd {
	return &WGCmd{
		wgPath:      "/usr/bin/wg",
		wgQuickPath: "/usr/bin/wg-quick",
	}
}

// GenPSK generates a new preshared key
func (c *WGCmd) GenPSK() (string, error) {
	cmd := exec.Command(c.wgPath, "genpsk")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("wg genpsk: %s: %w", stderr.String(), err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// GenKey generates a new private key
func (c *WGCmd) GenKey() (string, error) {
	cmd := exec.Command(c.wgPath, "genkey")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("wg genkey: %s: %w", stderr.String(), err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// PubKey derives public key from private key
func (c *WGCmd) PubKey(privateKey string) (string, error) {
	cmd := exec.Command(c.wgPath, "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("wg pubkey: %s: %w", stderr.String(), err)
	}

	return strings.TrimSpace(stdout.String()), nil
}

// GenKeyPair generates a private/public key pair
func (c *WGCmd) GenKeyPair() (privateKey, publicKey string, err error) {
	privateKey, err = c.GenKey()
	if err != nil {
		return "", "", err
	}

	publicKey, err = c.PubKey(privateKey)
	if err != nil {
		return "", "", err
	}

	return privateKey, publicKey, nil
}

// Show returns the interface status
func (c *WGCmd) Show(iface string) (*InterfaceStatus, error) {
	cmd := exec.Command(c.wgPath, "show", iface, "dump")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("wg show %s dump: %s: %w", iface, stderr.String(), err)
	}

	return c.parseDump(stdout.String())
}

// parseDump parses the output of wg show <iface> dump
func (c *WGCmd) parseDump(output string) (*InterfaceStatus, error) {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty dump output")
	}

	status := &InterfaceStatus{
		Peers: make([]PeerStatus, 0),
	}

	// First line is interface info: private_key public_key listen_port fwmark
	ifaceParts := strings.Split(lines[0], "\t")
	if len(ifaceParts) >= 3 {
		status.PublicKey = ifaceParts[1]
		if port, err := strconv.Atoi(ifaceParts[2]); err == nil {
			status.ListenPort = port
		}
	}

	// Remaining lines are peers: public_key preshared_key endpoint allowed_ips latest_handshake transfer_rx transfer_tx persistent_keepalive
	for _, line := range lines[1:] {
		parts := strings.Split(line, "\t")
		if len(parts) < 8 {
			continue
		}

		peer := PeerStatus{
			PublicKey: parts[0],
			Endpoint:  parts[2],
		}

		// AllowedIPs
		if parts[3] != "(none)" {
			peer.AllowedIPs = strings.Split(parts[3], ",")
		}

		// Latest handshake (unix timestamp)
		if ts, err := strconv.ParseInt(parts[4], 10, 64); err == nil && ts > 0 {
			peer.LatestHandshake = time.Unix(ts, 0)
		}

		// Transfer RX
		if rx, err := strconv.ParseInt(parts[5], 10, 64); err == nil {
			peer.TransferRx = rx
		}

		// Transfer TX
		if tx, err := strconv.ParseInt(parts[6], 10, 64); err == nil {
			peer.TransferTx = tx
		}

		// Persistent keepalive
		if keepalive, err := strconv.Atoi(parts[7]); err == nil {
			peer.PersistentKeepalive = keepalive
		}

		status.Peers = append(status.Peers, peer)
	}

	return status, nil
}

// SetPeerRemove removes a peer from the runtime interface
func (c *WGCmd) SetPeerRemove(iface, publicKey string) error {
	cmd := exec.Command(c.wgPath, "set", iface, "peer", publicKey, "remove")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wg set %s peer remove: %s: %w", iface, stderr.String(), err)
	}

	return nil
}

// SetPeer adds or updates a peer in the runtime interface
func (c *WGCmd) SetPeer(iface string, peer SetPeerArgs) error {
	args := []string{"set", iface, "peer", peer.PublicKey}

	if len(peer.AllowedIPs) > 0 {
		args = append(args, "allowed-ips", strings.Join(peer.AllowedIPs, ","))
	}

	if peer.Endpoint != "" {
		args = append(args, "endpoint", peer.Endpoint)
	}

	if peer.PersistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(peer.PersistentKeepalive))
	}

	if peer.PresharedKey != "" {
		args = append(args, "preshared-key", "/dev/stdin")
	}

	cmd := exec.Command(c.wgPath, args...)
	if peer.PresharedKey != "" {
		cmd.Stdin = strings.NewReader(peer.PresharedKey)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wg set %s peer: %s: %w", iface, stderr.String(), err)
	}

	return nil
}

// SetPeerArgs represents arguments for SetPeer
type SetPeerArgs struct {
	PublicKey           string
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive int
	PresharedKey        string
}

// SyncConf applies config changes using wg syncconf
func (c *WGCmd) SyncConf(iface, configPath string) error {
	cmd := exec.Command(c.wgPath, "syncconf", iface, configPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wg syncconf %s: %s: %w", iface, stderr.String(), err)
	}

	return nil
}

// Down brings down a WireGuard interface using wg-quick
func (c *WGCmd) Down(iface string) error {
	cmd := exec.Command(c.wgQuickPath, "down", iface)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wg-quick down %s: %s: %w", iface, stderr.String(), err)
	}

	return nil
}

// Up brings up a WireGuard interface using wg-quick
func (c *WGCmd) Up(iface string) error {
	cmd := exec.Command(c.wgQuickPath, "up", iface)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wg-quick up %s: %s: %w", iface, stderr.String(), err)
	}

	return nil
}

// StripConfig strips wg-quick specific directives from config
func (c *WGCmd) StripConfig(configPath string) (string, error) {
	cmd := exec.Command(c.wgQuickPath, "strip", configPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("wg-quick strip %s: %s: %w", configPath, stderr.String(), err)
	}

	return stdout.String(), nil
}
