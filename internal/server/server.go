package server

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	pb "wg-agent/api/proto"
	"wg-agent/internal/config"
	"wg-agent/pkg/wgcmd"
)

const (
	// ChunkSize for streaming backup downloads (64KB)
	ChunkSize = 64 * 1024
)

// WGAgentServer implements the WGAgent gRPC service
type WGAgentServer struct {
	pb.UnimplementedWGAgentServer
	config    *config.Config
	wg        *wgcmd.WGCmd
	startTime time.Time
	hostname  string
}

// New creates a new WGAgentServer
func New(cfg *config.Config) (*WGAgentServer, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	return &WGAgentServer{
		config:    cfg,
		wg:        wgcmd.New(),
		startTime: time.Now(),
		hostname:  hostname,
	}, nil
}

// Health returns agent health information
func (s *WGAgentServer) Health(ctx context.Context, req *pb.HealthRequest) (*pb.HealthResponse, error) {
	interfaces, err := s.getAvailableInterfaces()
	if err != nil {
		interfaces = []string{}
	}

	return &pb.HealthResponse{
		Version:             "1.0.0",
		Hostname:            s.hostname,
		UptimeSeconds:       int64(time.Since(s.startTime).Seconds()),
		AvailableInterfaces: interfaces,
	}, nil
}

// Show returns WireGuard interface status
func (s *WGAgentServer) Show(ctx context.Context, req *pb.ShowRequest) (*pb.ShowResponse, error) {
	if !s.config.IsInterfaceAllowed(req.InterfaceName) {
		return nil, fmt.Errorf("interface %s is not in allowed list", req.InterfaceName)
	}

	status, err := s.wg.Show(req.InterfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface status: %w", err)
	}

	peers := make([]*pb.PeerStatus, 0, len(status.Peers))
	for _, p := range status.Peers {
		peers = append(peers, &pb.PeerStatus{
			PublicKey:           p.PublicKey,
			PresharedKeySet:     "false", // wg show dump doesn't expose PSK status directly
			Endpoint:            p.Endpoint,
			AllowedIps:          p.AllowedIPs,
			LatestHandshakeUnix: p.LatestHandshake.Unix(),
			TransferRx:          p.TransferRx,
			TransferTx:          p.TransferTx,
			PersistentKeepalive: int32(p.PersistentKeepalive),
		})
	}

	return &pb.ShowResponse{
		PublicKey:  status.PublicKey,
		ListenPort: int32(status.ListenPort),
		Fwmark:     0,
		Peers:      peers,
	}, nil
}

// SyncConf applies a stripped config to the interface
func (s *WGAgentServer) SyncConf(ctx context.Context, req *pb.SyncConfRequest) (*pb.SyncConfResponse, error) {
	if !s.config.IsInterfaceAllowed(req.InterfaceName) {
		return &pb.SyncConfResponse{
			Success: false,
			Error:   fmt.Sprintf("interface %s is not in allowed list", req.InterfaceName),
		}, nil
	}

	// Write stripped config to temp file
	tmpFile, err := os.CreateTemp("", "wg-syncconf-*.conf")
	if err != nil {
		return &pb.SyncConfResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create temp file: %v", err),
		}, nil
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(req.ConfigContent); err != nil {
		tmpFile.Close()
		return &pb.SyncConfResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to write temp file: %v", err),
		}, nil
	}
	tmpFile.Close()

	// Apply with syncconf
	if err := s.wg.SyncConf(req.InterfaceName, tmpFile.Name()); err != nil {
		return &pb.SyncConfResponse{
			Success: false,
			Error:   fmt.Sprintf("syncconf failed: %v", err),
		}, nil
	}

	return &pb.SyncConfResponse{Success: true}, nil
}

// SetPeer adds or updates a peer
func (s *WGAgentServer) SetPeer(ctx context.Context, req *pb.SetPeerRequest) (*pb.SetPeerResponse, error) {
	if !s.config.IsInterfaceAllowed(req.InterfaceName) {
		return &pb.SetPeerResponse{
			Success: false,
			Error:   fmt.Sprintf("interface %s is not in allowed list", req.InterfaceName),
		}, nil
	}

	args := wgcmd.SetPeerArgs{
		AllowedIPs: req.AllowedIps,
	}
	if req.Endpoint != nil {
		args.Endpoint = *req.Endpoint
	}
	if req.PersistentKeepalive != nil {
		args.PersistentKeepalive = int(*req.PersistentKeepalive)
	}
	if req.PresharedKey != nil {
		args.PresharedKey = *req.PresharedKey
	}

	args.PublicKey = req.PublicKey
	if err := s.wg.SetPeer(req.InterfaceName, args); err != nil {
		return &pb.SetPeerResponse{
			Success: false,
			Error:   fmt.Sprintf("set peer failed: %v", err),
		}, nil
	}

	return &pb.SetPeerResponse{Success: true}, nil
}

// RemovePeer removes a peer from the interface
func (s *WGAgentServer) RemovePeer(ctx context.Context, req *pb.RemovePeerRequest) (*pb.RemovePeerResponse, error) {
	if !s.config.IsInterfaceAllowed(req.InterfaceName) {
		return &pb.RemovePeerResponse{
			Success: false,
			Error:   fmt.Sprintf("interface %s is not in allowed list", req.InterfaceName),
		}, nil
	}

	if err := s.wg.SetPeerRemove(req.InterfaceName, req.PublicKey); err != nil {
		return &pb.RemovePeerResponse{
			Success: false,
			Error:   fmt.Sprintf("remove peer failed: %v", err),
		}, nil
	}

	return &pb.RemovePeerResponse{Success: true}, nil
}

// GenPSK generates a new preshared key
func (s *WGAgentServer) GenPSK(ctx context.Context, req *pb.GenPSKRequest) (*pb.GenPSKResponse, error) {
	psk, err := s.wg.GenPSK()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PSK: %w", err)
	}
	return &pb.GenPSKResponse{PresharedKey: psk}, nil
}

// GenKeyPair generates a new WireGuard keypair
func (s *WGAgentServer) GenKeyPair(ctx context.Context, req *pb.GenKeyPairRequest) (*pb.GenKeyPairResponse, error) {
	privKey, err := s.wg.GenKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	pubKey, err := s.wg.PubKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	return &pb.GenKeyPairResponse{
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}, nil
}

// ReadConfig reads the WireGuard config file
func (s *WGAgentServer) ReadConfig(ctx context.Context, req *pb.ReadConfigRequest) (*pb.ReadConfigResponse, error) {
	if !s.config.IsInterfaceAllowed(req.InterfaceName) {
		return nil, fmt.Errorf("interface %s is not in allowed list", req.InterfaceName)
	}

	configPath := s.config.GetConfigPath(req.InterfaceName)

	info, err := os.Stat(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat config file: %w", err)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	return &pb.ReadConfigResponse{
		Content:        content,
		ModifiedAtUnix: info.ModTime().Unix(),
	}, nil
}

// WriteConfig writes the WireGuard config file atomically
func (s *WGAgentServer) WriteConfig(ctx context.Context, req *pb.WriteConfigRequest) (*pb.WriteConfigResponse, error) {
	if !s.config.IsInterfaceAllowed(req.InterfaceName) {
		return &pb.WriteConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("interface %s is not in allowed list", req.InterfaceName),
		}, nil
	}

	configPath := s.config.GetConfigPath(req.InterfaceName)
	var backupName string

	// Create backup if requested
	if req.CreateBackup {
		backupName, _ = s.createBackup(req.InterfaceName)
	}

	// Write atomically: write to temp file, then rename
	tmpFile, err := os.CreateTemp(filepath.Dir(configPath), ".wg-*.conf.tmp")
	if err != nil {
		return &pb.WriteConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create temp file: %v", err),
		}, nil
	}
	tmpPath := tmpFile.Name()

	if _, err := tmpFile.Write(req.Content); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return &pb.WriteConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to write temp file: %v", err),
		}, nil
	}

	if err := tmpFile.Chmod(0600); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return &pb.WriteConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to set permissions: %v", err),
		}, nil
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return &pb.WriteConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to close temp file: %v", err),
		}, nil
	}

	if err := os.Rename(tmpPath, configPath); err != nil {
		os.Remove(tmpPath)
		return &pb.WriteConfigResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to rename temp file: %v", err),
		}, nil
	}

	return &pb.WriteConfigResponse{
		Success:    true,
		BackupName: backupName,
	}, nil
}

// ListBackups lists all backups
func (s *WGAgentServer) ListBackups(ctx context.Context, req *pb.ListBackupsRequest) (*pb.ListBackupsResponse, error) {
	entries, err := os.ReadDir(s.config.BackupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &pb.ListBackupsResponse{Backups: []*pb.BackupInfo{}}, nil
		}
		return nil, fmt.Errorf("failed to read backup dir: %w", err)
	}

	backups := make([]*pb.BackupInfo, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}

		// Filter by interface if specified
		if req.InterfaceName != "" {
			if !strings.HasPrefix(entry.Name(), req.InterfaceName+"_") {
				continue
			}
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		// Extract interface name from filename (format: interface_2006-01-02_15-04-05.conf)
		parts := strings.SplitN(entry.Name(), "_", 2)
		ifaceName := ""
		if len(parts) > 0 {
			ifaceName = parts[0]
		}

		backups = append(backups, &pb.BackupInfo{
			Name:          entry.Name(),
			InterfaceName: ifaceName,
			SizeBytes:     info.Size(),
			CreatedAtUnix: info.ModTime().Unix(),
		})
	}

	// Sort by creation time descending
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].CreatedAtUnix > backups[j].CreatedAtUnix
	})

	return &pb.ListBackupsResponse{Backups: backups}, nil
}

// CreateBackup creates a backup of the config file
func (s *WGAgentServer) CreateBackup(ctx context.Context, req *pb.CreateBackupRequest) (*pb.CreateBackupResponse, error) {
	if !s.config.IsInterfaceAllowed(req.InterfaceName) {
		return &pb.CreateBackupResponse{
			Success: false,
			Error:   fmt.Sprintf("interface %s is not in allowed list", req.InterfaceName),
		}, nil
	}

	backupName, err := s.createBackup(req.InterfaceName)
	if err != nil {
		return &pb.CreateBackupResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to create backup: %v", err),
		}, nil
	}

	backupPath := filepath.Join(s.config.BackupDir, backupName)
	info, err := os.Stat(backupPath)
	if err != nil {
		return &pb.CreateBackupResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to stat backup: %v", err),
		}, nil
	}

	return &pb.CreateBackupResponse{
		Success: true,
		Backup: &pb.BackupInfo{
			Name:          backupName,
			InterfaceName: req.InterfaceName,
			SizeBytes:     info.Size(),
			CreatedAtUnix: info.ModTime().Unix(),
		},
	}, nil
}

// GetBackup streams a backup file
func (s *WGAgentServer) GetBackup(req *pb.GetBackupRequest, stream pb.WGAgent_GetBackupServer) error {
	// Validate filename to prevent path traversal
	if strings.Contains(req.Name, "/") || strings.Contains(req.Name, "\\") || strings.Contains(req.Name, "..") {
		return fmt.Errorf("invalid backup name")
	}

	backupPath := filepath.Join(s.config.BackupDir, req.Name)

	file, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("failed to open backup: %w", err)
	}
	defer file.Close()

	buf := make([]byte, ChunkSize)
	for {
		n, err := file.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read backup: %w", err)
		}

		if err := stream.Send(&pb.BackupChunk{Data: buf[:n]}); err != nil {
			return fmt.Errorf("failed to send chunk: %w", err)
		}
	}

	return nil
}

// RestoreBackup restores a backup to the config file and applies it
func (s *WGAgentServer) RestoreBackup(ctx context.Context, req *pb.RestoreBackupRequest) (*pb.RestoreBackupResponse, error) {
	// Validate interface
	if !s.config.IsInterfaceAllowed(req.InterfaceName) {
		return &pb.RestoreBackupResponse{
			Success: false,
			Error:   fmt.Sprintf("interface %s is not allowed", req.InterfaceName),
		}, nil
	}

	// Validate filename to prevent path traversal
	if strings.Contains(req.Name, "/") || strings.Contains(req.Name, "\\") || strings.Contains(req.Name, "..") {
		return &pb.RestoreBackupResponse{
			Success: false,
			Error:   "invalid backup name",
		}, nil
	}

	backupPath := filepath.Join(s.config.BackupDir, req.Name)
	configPath := s.config.GetConfigPath(req.InterfaceName)

	// Read backup file
	backupContent, err := os.ReadFile(backupPath)
	if err != nil {
		if os.IsNotExist(err) {
			return &pb.RestoreBackupResponse{
				Success: false,
				Error:   "backup not found",
			}, nil
		}
		return &pb.RestoreBackupResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to read backup: %v", err),
		}, nil
	}

	// Create backup of current config before restoring
	_, _ = s.createBackup(req.InterfaceName)

	// Bring down the interface first
	if err := s.wg.Down(req.InterfaceName); err != nil {
		// Interface might not be running, continue anyway
		log.Printf("Warning: failed to bring down interface %s: %v", req.InterfaceName, err)
	}

	// Write backup content to config file
	if err := os.WriteFile(configPath, backupContent, 0600); err != nil {
		return &pb.RestoreBackupResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to write config: %v", err),
		}, nil
	}

	// Bring up the interface with new config
	if err := s.wg.Up(req.InterfaceName); err != nil {
		log.Printf("Error: failed to bring up interface %s: %v", req.InterfaceName, err)
		return &pb.RestoreBackupResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to bring up interface: %v", err),
		}, nil
	}

	log.Printf("Successfully restored backup and brought up interface %s", req.InterfaceName)
	return &pb.RestoreBackupResponse{Success: true}, nil
}

// DeleteBackup deletes a backup file
func (s *WGAgentServer) DeleteBackup(ctx context.Context, req *pb.DeleteBackupRequest) (*pb.DeleteBackupResponse, error) {
	// Validate filename to prevent path traversal
	if strings.Contains(req.Name, "/") || strings.Contains(req.Name, "\\") || strings.Contains(req.Name, "..") {
		return &pb.DeleteBackupResponse{
			Success: false,
			Error:   "invalid backup name",
		}, nil
	}

	backupPath := filepath.Join(s.config.BackupDir, req.Name)

	if err := os.Remove(backupPath); err != nil {
		if os.IsNotExist(err) {
			return &pb.DeleteBackupResponse{
				Success: false,
				Error:   "backup not found",
			}, nil
		}
		return &pb.DeleteBackupResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to delete backup: %v", err),
		}, nil
	}

	return &pb.DeleteBackupResponse{Success: true}, nil
}

// Helper methods

func (s *WGAgentServer) createBackup(iface string) (string, error) {
	configPath := s.config.GetConfigPath(iface)

	content, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read config: %w", err)
	}

	backupName := fmt.Sprintf("%s_%s.conf", iface, time.Now().Format("2006-01-02_15-04-05"))
	backupPath := filepath.Join(s.config.BackupDir, backupName)

	if err := os.WriteFile(backupPath, content, 0600); err != nil {
		return "", fmt.Errorf("failed to write backup: %w", err)
	}

	// Cleanup old backups
	s.cleanupOldBackups(iface)

	return backupName, nil
}

func (s *WGAgentServer) cleanupOldBackups(iface string) {
	entries, err := os.ReadDir(s.config.BackupDir)
	if err != nil {
		return
	}

	cutoff := time.Now().AddDate(0, 0, -s.config.BackupRetentionDays)
	prefix := iface + "_"

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(s.config.BackupDir, entry.Name()))
		}
	}
}

func (s *WGAgentServer) getAvailableInterfaces() ([]string, error) {
	entries, err := os.ReadDir(s.config.WGConfigDir)
	if err != nil {
		return nil, err
	}

	interfaces := make([]string, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		iface := strings.TrimSuffix(entry.Name(), ".conf")
		if s.config.IsInterfaceAllowed(iface) {
			interfaces = append(interfaces, iface)
		}
	}

	return interfaces, nil
}
