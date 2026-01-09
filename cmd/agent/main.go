package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	pb "wg-agent/api/proto"
	"wg-agent/internal/config"
	"wg-agent/internal/server"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting WG Agent...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Load TLS credentials
	tlsConfig, err := loadTLSConfig(cfg)
	if err != nil {
		log.Fatalf("Failed to load TLS config: %v", err)
	}

	// Create gRPC server with mTLS
	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
	)

	// Create and register WGAgent service
	agentServer, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create agent server: %v", err)
	}
	pb.RegisterWGAgentServer(grpcServer, agentServer)

	// Register gRPC health service
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("wgagent.WGAgent", healthpb.HealthCheckResponse_SERVING)

	// Start listening
	addr := fmt.Sprintf(":%d", cfg.GRPCPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", addr, err)
	}

	// Start server in goroutine
	go func() {
		log.Printf("gRPC server listening on %s (mTLS enabled)", addr)
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down...")
	grpcServer.GracefulStop()
	log.Println("Agent stopped")
}

func loadTLSConfig(cfg *config.Config) (*tls.Config, error) {
	// Load server certificate
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server cert: %w", err)
	}

	// Load CA certificate for client verification
	caCert, err := os.ReadFile(cfg.TLSCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
