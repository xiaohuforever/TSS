package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	eddsa_scheme "github.com/IBM/TSS/mpc/binance/eddsa"
	comm "github.com/IBM/TSS/net"
	"github.com/IBM/TSS/testutil/tlsgen"
	"github.com/IBM/TSS/threshold"
	. "github.com/IBM/TSS/types"
	"go.uber.org/zap"
)

const (
	totalParties  = 5
	signThreshold = 4 // Need 4 out of 5 parties to sign
)

func main() {
	log.Println("Starting EdDSA Threshold Signature Demo")
	log.Printf("Configuration: %d total parties, threshold %d\n", totalParties, signThreshold)

	// Set up logging
	logConfig := zap.NewDevelopmentConfig()
	baseLogger, err := logConfig.Build()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}

	// Create CA for TLS certificates
	ca, err := tlsgen.NewCA()
	if err != nil {
		log.Fatalf("Failed to create CA: %v", err)
	}

	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca.CertBytes())

	// Create parties with network communication
	parties, stopFuncs, err := createParties(ca, certPool, baseLogger)
	if err != nil {
		log.Fatalf("Failed to create parties: %v", err)
	}

	// Cleanup function
	defer func() {
		log.Println("Cleaning up...")
		for _, stop := range stopFuncs {
			stop()
		}
	}()

	// Step 1: Execute DKG (Distributed Key Generation)
	log.Println("Step 1: Starting DKG process...")
	shareData, err := executeDKG(parties)
	if err != nil {
		log.Fatalf("DKG failed: %v", err)
	}
	log.Println("DKG completed successfully!")

	// Step 2: Generate EdDSA signature
	log.Println("Step 2: Starting signature generation...")
	signature, publicKey, err := executeSigning(parties, shareData)
	if err != nil {
		log.Fatalf("Signing failed: %v", err)
	}
	log.Println("Signature generation completed successfully!")

	// Step 3: Verify the signature
	log.Println("Step 3: Verifying signature...")
	message := "Hello, Threshold EdDSA!"
	messageHash := sha256.Sum256([]byte(message))

	valid := ed25519.Verify(publicKey, messageHash[:], signature)
	if valid {
		log.Println("✓ Signature verification successful!")
		log.Printf("Message: %s\n", message)
		log.Printf("Public Key: %x\n", publicKey)
		log.Printf("Signature: %x\n", signature)
	} else {
		log.Println("✗ Signature verification failed!")
	}

	log.Println("Demo completed successfully!")
}

func createParties(ca tlsgen.CA, certPool *x509.CertPool, baseLogger *zap.Logger) ([]MpcParty, []func(), error) {
	var parties []MpcParty
	var stopFuncs []func()
	var listeners []net.Listener
	var commParties []*comm.Party
	var loggers []*commLogger
	var signers []*tlsgen.CertKeyPair

	// Membership mapping
	membership := make(map[UniversalID]PartyID)
	for i := 1; i <= totalParties; i++ {
		membership[UniversalID(i)] = PartyID(i)
	}

	membershipFunc := func() map[UniversalID]PartyID {
		return membership
	}

	// Create shared TLS certificate for all parties
	tlsCert, err := ca.NewServerCertKeyPair("127.0.0.1")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create shared TLS cert: %v", err)
	}

	// Pre-create all client certificates
	for id := 1; id <= totalParties; id++ {
		s := newSigner(ca)
		signers = append(signers, s)
	}

	// Create parties
	for id := 1; id <= totalParties; id++ {
		// Create logger for this party
		config := zap.NewDevelopmentConfig()
		logger := &commLogger{
			Logger: &loggerWithDebug{
				SugaredLogger: baseLogger.With(
					zap.String("party", fmt.Sprintf("%d", id)),
					zap.String("component", "eddsa-demo"),
				).Sugar(),
			},
			conf: &config,
		}
		loggers = append(loggers, logger)

		// Create network listener using shared TLS certificate
		listener := comm.Listen("127.0.0.1:0", tlsCert.Cert, tlsCert.Key)
		listeners = append(listeners, listener)

		// Create communication party
		commParty := &comm.Party{
			Logger:   logger,
			Address:  listener.Addr().String(),
			Identity: signers[id-1].Cert,
		}
		commParties = append(commParties, commParty)
	}

	// Create MPC parties with network communication
	for id := 1; id <= totalParties; id++ {
		party, stop, err := createMPCParty(
			uint16(id),
			loggers[id-1],
			signers[id-1],
			certPool,
			listeners,
			commParties,
			membershipFunc,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create MPC party %d: %v", id, err)
		}
		parties = append(parties, party)
		stopFuncs = append(stopFuncs, stop)
	}

	return parties, stopFuncs, nil
}

func createMPCParty(
	id uint16,
	logger *commLogger,
	signer *tlsgen.CertKeyPair,
	certPool *x509.CertPool,
	listeners []net.Listener,
	commParties []*comm.Party,
	membershipFunc func() map[UniversalID]PartyID,
) (MpcParty, func(), error) {
	// Set up remote parties communication
	remoteParties := make(comm.SocketRemoteParties)

	auth := func(tlsContext []byte) comm.Handshake {
		h := comm.Handshake{
			TLSBinding: tlsContext,
			Identity:   signer.Cert,
			Timestamp:  time.Now().Unix(),
		}

		sig, err := signer.Sign(rand.Reader, sha256Digest(h.Bytes()), nil)
		if err != nil {
			panic(fmt.Sprintf("failed signing: %v", err))
		}

		h.Signature = sig
		return h
	}

	// Connect to other parties
	for i := 1; i <= totalParties; i++ {
		if uint16(i) == id {
			continue
		}

		remoteParties[i] = comm.NewSocketRemoteParty(comm.PartyConnectionConfig{
			AuthFunc: auth,
			TlsCAs:   certPool,
			Id:       i,
			Endpoint: listeners[i-1].Addr().String(),
		}, logger)
	}

	commParties[id-1].SendMessage = remoteParties.Send

	// Set up party ID mapping
	p2id := make(map[string]uint16)
	for i, p := range commParties {
		p2id[hex.EncodeToString(sha256Digest(p.Identity))] = uint16(i + 1)
	}

	// Start message handling
	in, stop := comm.ServiceConnections(listeners[id-1], p2id, logger)
	commParties[id-1].InMessages = in

	// Create algorithm factories
	kgf := func(partyID uint16) KeyGenerator {
		return eddsa_scheme.NewParty(partyID, logger)
	}

	sf := func(partyID uint16) Signer {
		return eddsa_scheme.NewParty(partyID, logger)
	}

	// Create MPC scheme
	scheme := threshold.LoudScheme(id, logger, kgf, sf, len(commParties)-1, remoteParties.Send, membershipFunc)

	// Start message handler
	go func(in <-chan comm.InMsg) {
		for msg := range in {
			inMsg := &IncMessage{
				MsgType: msg.Type,
				Data:    msg.Data,
				Topic:   msg.Topic,
				Source:  msg.From,
			}
			scheme.HandleMessage(inMsg)
		}
	}(in)

	return scheme, stop, nil
}

func executeDKG(parties []MpcParty) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(parties))

	results := make([][]byte, len(parties))
	errors := make([]error, len(parties))

	start := time.Now()

	// Run DKG on all parties concurrently
	for i, party := range parties {
		go func(idx int, p MpcParty) {
			defer wg.Done()

			data, err := p.KeyGen(ctx, totalParties, signThreshold-1)
			if err != nil {
				errors[idx] = fmt.Errorf("party %d DKG failed: %v", idx+1, err)
				return
			}

			results[idx] = data
			p.SetStoredData(data)
		}(i, party)
	}

	wg.Wait()
	elapsed := time.Since(start)
	log.Printf("DKG completed in %v\n", elapsed)

	// Check for errors
	for i, err := range errors {
		if err != nil {
			return nil, err
		}
		if results[i] == nil {
			return nil, fmt.Errorf("party %d returned no data", i+1)
		}
	}

	return results, nil
}

func executeSigning(parties []MpcParty, shareData [][]byte) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(len(parties))

	message := "Hello, Threshold EdDSA!"
	messageHash := sha256.Sum256([]byte(message))
	topic := "test-signing-1"

	results := make([][]byte, len(parties))
	errors := make([]error, len(parties))
	publicKeys := make([][]byte, len(parties))

	start := time.Now()

	// Run signing on all parties concurrently
	for i, party := range parties {
		go func(idx int, p MpcParty) {
			defer wg.Done()

			// Set share data for signing
			p.SetStoredData(shareData[idx])

			// Get public key
			pk, err := p.ThresholdPK()
			if err != nil {
				errors[idx] = fmt.Errorf("party %d failed to get public key: %v", idx+1, err)
				return
			}
			publicKeys[idx] = pk

			// Sign the message
			signature, err := p.Sign(ctx, messageHash[:], topic)
			if err != nil {
				errors[idx] = fmt.Errorf("party %d signing failed: %v", idx+1, err)
				return
			}

			results[idx] = signature
		}(i, party)
	}

	wg.Wait()
	elapsed := time.Since(start)
	log.Printf("Signing completed in %v\n", elapsed)

	// Check for errors
	for i, err := range errors {
		if err != nil {
			return nil, nil, err
		}
		if results[i] == nil {
			return nil, nil, fmt.Errorf("party %d returned no signature", i+1)
		}
	}

	// Verify all signatures are the same
	for i := 1; i < len(results); i++ {
		if !equalBytes(results[0], results[i]) {
			return nil, nil, fmt.Errorf("signatures from parties do not match")
		}
	}

	// Verify all public keys are the same
	for i := 1; i < len(publicKeys); i++ {
		if !equalBytes(publicKeys[0], publicKeys[i]) {
			return nil, nil, fmt.Errorf("public keys from parties do not match")
		}
	}

	return results[0], publicKeys[0], nil
}

// Helper types and functions

type commLogger struct {
	conf *zap.Config
	Logger
}

type loggerWithDebug struct {
	*zap.SugaredLogger
}

func (lwd *loggerWithDebug) DebugEnabled() bool {
	return false
}

func (l *commLogger) DebugEnabled() bool {
	return false
}

func sha256Digest(data ...[]byte) []byte {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func newSigner(ca tlsgen.CA) *tlsgen.CertKeyPair {
	clientPair, err := ca.NewClientCertKeyPair()
	if err != nil {
		panic(fmt.Sprintf("failed to create client key pair: %v", err))
	}
	return clientPair
}
