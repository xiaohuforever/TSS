package test_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	mpcecdsa "github.com/IBM/TSS/mpc/binance/ecdsa" // Alias to avoid conflict
	tssnet "github.com/IBM/TSS/net"                 // Alias to avoid conflict
	"github.com/IBM/TSS/testutil/tlsgen"
	"github.com/stretchr/testify/assert"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"sync/atomic"
)

const (
	testDomain = "MPC_DKG_Test"
	numParties = 5
)

// sha256Digest computes SHA256 digest.
func sha256Digest(b ...[]byte) []byte {
	h := sha256.New()
	for _, bi := range b {
		h.Write(bi)
	}
	return h.Sum(nil)
}

// allocatePorts allocates a specified number of free TCP ports.
func allocatePorts(t *testing.T, count int) []int {
	t.Helper()
	ports := make([]int, count)
	for i := 0; i < count; i++ {
		addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
		if err != nil {
			t.Fatalf("resolve tcp addr: %v", err)
		}
		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			t.Fatalf("listen tcp: %v", err)
		}
		ports[i] = l.Addr().(*net.TCPAddr).Port
		if err := l.Close(); err != nil {
			t.Fatalf("close listener: %v", err)
		}
	}
	return ports
}

// logger creates a zap logger instance.
func logger(id string, testName string) tssnet.Logger {
	config := zap.NewDevelopmentConfig()
	config.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format("2006-01-02T15:04:05.000Z0700"))
	}
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	config.DisableStacktrace = true
	l, _ := config.Build()
	return l.Sugar().With("party", id, "test", testName)
}

type party struct {
	mpcParty        *mpcecdsa.Party
	netParty        *tssnet.Party
	remoteParties   tssnet.SocketRemoteParties
	address         string
	inMessages      <-chan tssnet.InMsg
	stop            context.CancelFunc
	signingIdentity *tlsgen.CertKeyPair
	serverTLSCert   *tlsgen.CertKeyPair
	id              uint16 // 1-based
	logger          tssnet.Logger
	mpcSender       mpcecdsa.Sender
}

type parties []*party

func (p parties) numericIDs() []*tss.PartyID {
	ids := make([]*tss.PartyID, len(p))
	for i, pi := range p {
		// Party IDs are 1-based
		ids[i] = tss.NewPartyID(strconv.Itoa(int(pi.id)), strconv.Itoa(int(pi.id)), new(big.Int).SetUint64(uint64(pi.id)))
	}
	return ids
}

func (p parties) init() error {
	partyIDs := p.numericIDs()
	for _, pi := range p {
		if err := pi.mpcParty.Init(partyIDs, pi.mpcSender); err != nil {
			return fmt.Errorf("party %d mpc init: %w", pi.id, err)
		}
	}
	return nil
}

func (p parties) setShareData(shareData [][]byte) {
	// Placeholder - will be implemented based on mpcecdsa.Party API
	// This method might not be needed if keygen produces shares that are internally managed
	// or if signing uses shares loaded differently.
	for i, pi := range p {
		// Example: pi.mpcParty.LoadShare(shareData[i])
		_ = pi
		_ = shareData
	}
}

func (p parties) keygen(ctx context.Context) ([][]byte, error) {
	var wg sync.WaitGroup
	var errValue atomic.Value

	num := len(p)
	shares := make([][]byte, num)

	for i, currentParty := range p {
		wg.Add(1)
		go func(idx int, partyInstance *party) {
			defer wg.Done()
			partyInstance.logger.Infof("Party %d starting KeyGen...", partyInstance.id)
			share, err := partyInstance.mpcParty.KeyGen(ctx)
			if err != nil {
				partyInstance.logger.Errorf("Party %d KeyGen error: %v", partyInstance.id, err)
				errValue.CompareAndSwap(nil, err) // Store only the first error
				return
			}
			shares[idx] = share
			partyInstance.logger.Infof("Party %d KeyGen completed.", partyInstance.id)
		}(i, currentParty)
	}

	wg.Wait()

	if err := errValue.Load(); err != nil {
		return nil, err.(error)
	}
	return shares, nil
}

func (p parties) sign(ctx context.Context, msg []byte) ([][]byte, error) {
	var wg sync.WaitGroup
	var errValue atomic.Value

	num := len(p)
	signatures := make([][]byte, num)

	for i, currentParty := range p {
		wg.Add(1)
		go func(idx int, partyInstance *party) {
			defer wg.Done()
			partyInstance.logger.Infof("Party %d starting Sign for msg: %s", partyInstance.id, hex.EncodeToString(msg))
			// Ensure the party has the DKG result loaded/available.
			// This is assumed to be handled internally by mpcParty after KeyGen.
			sig, err := partyInstance.mpcParty.Sign(ctx, msg)
			if err != nil {
				partyInstance.logger.Errorf("Party %d Sign error: %v", partyInstance.id, err)
				errValue.CompareAndSwap(nil, err) // Store only the first error
				return
			}
			signatures[idx] = sig
			partyInstance.logger.Infof("Party %d Sign completed.", partyInstance.id)
		}(i, currentParty)
	}

	wg.Wait()

	if err := errValue.Load(); err != nil {
		return nil, err.(error)
	}
	return signatures, nil
}

// remotePartiesForPeer creates a new SocketRemoteParties map for a specific peer.
// It clones allRemoteParties, removes the peer itself, and sets up authentication.
func remotePartiesForPeer(id uint16, allRemoteParties map[uint16]*tssnet.SocketRemoteParty, sID *tlsgen.CertKeyPair, domain string) tssnet.SocketRemoteParties {
	peerRemoteParties := make(tssnet.SocketRemoteParties, len(allRemoteParties)-1)
	for remoteID, rp := range allRemoteParties {
		if remoteID == id {
			continue // Don't add self
		}
		clonedRP := &tssnet.SocketRemoteParty{
			Endpoint: rp.Endpoint,
			CertPool: rp.CertPool,
			ID:       rp.ID,
		}
		clonedRP.SetAuthenticate(func(tlsBinding []byte) (tssnet.Handshake, error) {
			h := tssnet.HandshakeMsg{
				Domain:     domain,
				TLSBinding: tlsBinding,
				Identity:   sID.Cert,
				Timestamp:  time.Now().Unix(),
			}
			sig, err := sID.Sign(sha256Digest(h.BytesNoSig()))
			if err != nil {
				return nil, fmt.Errorf("sign handshake: %w", err)
			}
			h.Signature = sig
			return &h, nil
		})
		peerRemoteParties[remoteID] = clonedRP
	}
	return peerRemoteParties
}

func setupNetworkedTestParties(t *testing.T, n int, threshold int) (parties, []context.CancelFunc, error) {
	t.Helper()

	// 1. TLS Generation
	ca, err := tlsgen.NewCA()
	if err != nil {
		return nil, nil, fmt.Errorf("new ca: %w", err)
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(ca.Cert)

	serverCerts := make([]*tlsgen.CertKeyPair, n)
	signingIdentities := make([]*tlsgen.CertKeyPair, n)
	for i := 0; i < n; i++ {
		serverCerts[i], err = ca.NewServerCertKeyPair("127.0.0.1")
		if err != nil {
			return nil, nil, fmt.Errorf("server cert %d: %w", i, err)
		}
		signingIdentities[i], err = ca.NewClientCertKeyPair()
		if err != nil {
			return nil, nil, fmt.Errorf("signing identity %d: %w", i, err)
		}
	}

	// 2. Port Allocation
	ports := allocatePorts(t, n)

	// 3. Party Objects Creation
	createdParties := make(parties, n)
	netParties := make([]*tssnet.Party, n)
	stopFuncs := make([]context.CancelFunc, n)
	allNumericIDs := make([]*tss.PartyID, n) // To collect all numeric IDs first

	for i := 0; i < n; i++ {
		partyID := uint16(i + 1) // MPC parties are 1-based
		allNumericIDs[i] = tss.NewPartyID(strconv.Itoa(int(partyID)), strconv.Itoa(int(partyID)), new(big.Int).SetUint64(uint64(partyID)))
	}


	for i := 0; i < n; i++ {
		partyID := uint16(i + 1)
		partyLogger := logger(fmt.Sprintf("party-%d", partyID), t.Name())

		// Create MPC Party. Note: threshold and n (total parties) are important.
		// The `allNumericIDs` will be passed during Init.
		mpcParty := mpcecdsa.NewParty(partyID, partyLogger, threshold, n)

		netParties[i] = &tssnet.Party{
			Identity: signingIdentities[i].Cert,
			Logger:   partyLogger,
			Address:  fmt.Sprintf("127.0.0.1:%d", ports[i]),
			ID:       partyID,
		}

		createdParties[i] = &party{
			mpcParty:        mpcParty,
			netParty:        netParties[i],
			address:         netParties[i].Address,
			signingIdentity: signingIdentities[i],
			serverTLSCert:   serverCerts[i],
			id:              partyID,
			logger:          partyLogger,
		}
	}

	// 4. Remote Party Setup (allRemoteSocketParties map)
	allRemoteSocketParties := make(map[uint16]*tssnet.SocketRemoteParty)
	for j := 0; j < n; j++ {
		allRemoteSocketParties[createdParties[j].id] = tssnet.NewSocketRemoteParty(
			createdParties[j].address,
			certPool,
			createdParties[j].id,
		)
	}

	// 5. Participant to ID Mapping (p2id)
	p2id := make(map[string]uint16)
	for i := 0; i < n; i++ {
		p2idKey := hex.EncodeToString(sha256Digest([]byte(testDomain), netParties[i].Identity))
		p2id[p2idKey] = netParties[i].ID
	}

	// 6. Connect Parties and Set Senders
	for i := 0; i < n; i++ {
		p := createdParties[i]
		p.remoteParties = remotePartiesForPeer(p.id, allRemoteSocketParties, p.signingIdentity, testDomain)

		// Define the sender function for this party's MPC instance
		p.mpcSender = func(msg []byte, to uint16, broadcast bool) error {
			tssMsg := tssnet.Msg{
				Data:      msg,
				Broadcast: broadcast,
			}
			if broadcast {
				// Send will handle broadcast if To is nil
				// Iterate over all remote parties and send, or let Send handle it if it supports broadcast to all.
				// For now, assuming Send with nil To is broadcast.
				// If not, we'd iterate p.remoteParties and send individually if to == 0 (or special broadcast ID)
				// Or, if `to` is a specific ID for broadcast (e.g. 0), handle that.
				// Given `mpcecdsa.Sender` has `to uint16`, if broadcast is true, `to` might be ignored or a specific value.
				// Let's assume if broadcast is true, `to` is irrelevant for `tssnet.Msg` construction.
				// If `to` is a specific peer (not broadcast)
			} else {
				tssMsg.To = []uint16{to}
			}
			return p.remoteParties.Send(tssMsg, p.logger)
		}
		// p.mpcParty.SetSender(p.mpcSender) // This is done by Init now

		// Start listener
		listener, err := tssnet.Listen(p.netParty.Address, p.serverTLSCert.Cert, p.serverTLSCert.Key)
		if err != nil {
			for k := 0; k < i; k++ {
				if createdParties[k].stop != nil {
					createdParties[k].stop()
				}
			}
			return nil, nil, fmt.Errorf("party %d listen: %w", p.id, err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		stopFuncs[i] = cancel
		p.stop = cancel

		inMsgs, err := tssnet.ServiceConnections(ctx, listener, p2id, p.netParty.Identity, p.netParty.Logger, certPool, testDomain)
		if err != nil {
			for k := 0; k < i; k++ {
				if createdParties[k].stop != nil {
					createdParties[k].stop()
				}
			}
			cancel()
			return nil, nil, fmt.Errorf("party %d service connections: %w", p.id, err)
		}
		p.inMessages = inMsgs
	}

	return createdParties, stopFuncs, nil
}

func TestDKGWithNetworkCommunication(t *testing.T) {
	threshold := numParties - 1 

	allParties, stopFuncs, err := setupNetworkedTestParties(t, numParties, threshold)
	assert.NoError(t, err)
	assert.NotNil(t, allParties)
	assert.Len(t, allParties, numParties)
	assert.Len(t, stopFuncs, numParties)

	for _, p := range allParties {
		assert.NotNil(t, p.mpcParty)
		assert.NotNil(t, p.netParty)
		assert.NotNil(t, p.inMessages)
		assert.NotNil(t, p.stop)
		assert.NotNil(t, p.mpcSender, "Party %d mpcSender is nil", p.id)
	}

	// Defer stop functions
	for _, stop := range stopFuncs {
		if stop != nil {
			defer stop()
		}
	}

	// Initialize MPC parties
	err = allParties.init()
	assert.NoError(t, err, "MPC parties initialization failed")


	// Start message routing for each party
	var wg sync.WaitGroup
	for _, p := range allParties {
		wg.Add(1)
		go func(currentParty *party) {
			defer wg.Done()
			currentParty.logger.Infof("Starting message router for party %d", currentParty.id)
			for {
				select {
				case <-currentParty.stop: // context associated with this party
					currentParty.logger.Infof("Message router for party %d stopped via context", currentParty.id)
					return
				case inMsg, ok := <-currentParty.inMessages:
					if !ok {
						currentParty.logger.Infof("inMessages channel closed for party %d", currentParty.id)
						return
					}
					currentParty.logger.Debugf("Party %d received msg from %d, broadcast: %v, data len: %d",
						currentParty.id, inMsg.RemotePartyID, inMsg.Msg.Broadcast, len(inMsg.Msg.Data))

					// Pass message to MPC party's OnMsg method
					// OnMsg expects: msgBytes []byte, messageSource uint16, broadcast bool
					err := currentParty.mpcParty.OnMsg(inMsg.Msg.Data, inMsg.RemotePartyID, inMsg.Msg.Broadcast)
					if err != nil {
						currentParty.logger.Errorf("Party %d OnMsg error: %v", currentParty.id, err)
						// Depending on the error, might need to stop or handle
					}
				}
			}
		}(p)
	}

	// TODO: Start keygen on each party
	// TODO: Wait for keygen to complete or timeout
	// TODO: Check results

	t.Log("MPC Parties initialized and message routers started.")

	// 1. Perform DKG
	t.Log("Starting DKG...")
	dkgCtx, dkgCancel := context.WithTimeout(context.Background(), 60*time.Second) // Timeout for DKG
	defer dkgCancel()
	shares, err := allParties.keygen(dkgCtx)
	assert.NoError(t, err, "DKG failed")
	assert.NotNil(t, shares, "DKG shares are nil")
	assert.Len(t, shares, numParties, "DKG shares length mismatch")
	// Each share itself should not be nil, though its content depends on the MPC protocol
	for i, s := range shares {
		assert.NotNil(t, s, fmt.Sprintf("Share for party %d is nil", allParties[i].id))
	}
	t.Log("DKG completed successfully.")

	// 2. Prepare for Signing
	msgToSign := []byte("test message for distributed signing")
	digest := sha256.Sum256(msgToSign)
	t.Logf("Message to sign: \"%s\", Digest: %s", string(msgToSign), hex.EncodeToString(digest[:]))

	// 3. Perform Signing
	t.Log("Starting signing...")
	signCtx, signCancel := context.WithTimeout(context.Background(), 60*time.Second) // Timeout for Signing
	defer signCancel()
	signatures, err := allParties.sign(signCtx, digest[:])
	assert.NoError(t, err, "Signing failed")
	assert.NotNil(t, signatures, "Signatures are nil")
	assert.Len(t, signatures, numParties, "Signatures length mismatch")

	// Assert that all signatures are identical
	sigSet := make(map[string]struct{})
	for i, sig := range signatures {
		assert.NotNil(t, sig, fmt.Sprintf("Signature for party %d is nil", allParties[i].id))
		// Ensure all signatures are the same, as they are partial signatures contributing to a single threshold signature
		// In many threshold schemes, individual outputs might not be identical before reconstruction.
		// However, the binance/ecdsa Sign method returns the *final* signature from each party.
		// Let's verify they are all the same.
		if len(sig) > 0 { // only add non-empty signatures to the set
			sigSet[hex.EncodeToString(sig)] = struct{}{}
		} else {
			t.Errorf("Party %d returned an empty signature", allParties[i].id)
		}
	}
	assert.Len(t, sigSet, 1, "Not all parties produced the same signature")
	t.Log("Signing completed successfully. All parties produced the same signature.")

	// 4. Verify Signature
	t.Log("Verifying signature...")
	// Retrieve public key from one of the parties (they should all have the same TPubKey after DKG)
	// Assuming mpcParty.TPubKey() returns (*ecdsa.PublicKey, error)
	// Based on mpc/binance/ecdsa/party.go, TPubKey() returns *ecdsa.PublicKey (no error)
	// and DKGResult().ThresholdPubKey also returns *ecdsa.PublicKey
	// Let's use DKGResult().ThresholdPubKey for clarity if available, or TPubKey()
	// The current Party struct in mpcecdsa has DKGResult() *Response, and Response has ThresholdPubKey *ecdsa.PublicKey
	dkgResult := allParties[0].mpcParty.DKGResult()
	assert.NotNil(t, dkgResult, "DKGResult is nil for party 0")
	pk := dkgResult.ThresholdPubKey
	assert.NotNil(t, pk, "Threshold public key is nil")

	// Verify one of the signatures (e.g., signatures[0])
	// The message digest is `digest[:]`
	// The signature format from binance/ecdsa Sign is ASN.1 DER encoded.
	verified := ecdsa.VerifyASN1(pk, digest[:], signatures[0])
	assert.True(t, verified, "Failed to verify signature")
	t.Log("Signature verified successfully against the threshold public key.")

	// Stop party message routers and wait for them to finish
	t.Log("Stopping party message routers...")
	for _, stop := range stopFuncs {
		stop()
	}
	wg.Wait() // Wait for all message routers to shut down.
	t.Log("All party message routers shut down.")
}
