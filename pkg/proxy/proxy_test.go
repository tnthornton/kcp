package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"
	userinfo "k8s.io/apiserver/pkg/authentication/user"

	"github.com/kcp-dev/kcp/cmd/sharded-test-server/third_party/library-go/crypto"
)

// TestProxyClientCertRotation verifies that newTransport re-reads the client
// cert from disk on each new outbound connection, so a cert-manager renewal
// takes effect without a process restart.
//
// It issues a short-lived client cert, confirms requests succeed, waits for
// expiry, writes a fresh cert to the same files, then confirms requests still
// succeed.
func TestProxyClientCertRotation(t *testing.T) {
	dir := t.TempDir()
	certFile := filepath.Join(dir, "client.crt")
	keyFile := filepath.Join(dir, "client.key")
	caFile := filepath.Join(dir, "ca.crt")

	caCfg, err := crypto.MakeSelfSignedCAConfigForDuration("test-ca", time.Hour)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	caCertPEM, caKeyPEM, err := caCfg.GetPEMBytes()
	if err != nil {
		t.Fatalf("CA GetPEMBytes: %v", err)
	}
	if err := os.WriteFile(caFile, caCertPEM, 0600); err != nil {
		t.Fatalf("write CA file: %v", err)
	}
	ca, err := crypto.GetCAFromBytes(caCertPEM, caKeyPEM)
	if err != nil {
		t.Fatalf("load CA: %v", err)
	}

	server := newMTLSServer(t, ca)
	defer server.Close()

	writeClientCert(t, ca, certFile, keyFile, 3*time.Second)

	transport, err := newTransport(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("newTransport: %v", err)
	}
	client := &http.Client{Transport: transport}

	if err := doRequest(client, server.URL); err != nil {
		t.Fatalf("expected success with valid cert: %v", err)
	}

	time.Sleep(4 * time.Second)
	writeClientCert(t, ca, certFile, keyFile, time.Hour)
	transport.CloseIdleConnections()

	if err := doRequest(client, server.URL); err != nil {
		t.Fatalf("expected success after cert renewal (new cert on disk): %v", err)
	}
}

func newMTLSServer(t *testing.T, ca *crypto.CA) *httptest.Server {
	t.Helper()

	caCertPEM, _, err := ca.Config.GetPEMBytes()
	if err != nil {
		t.Fatalf("CA GetPEMBytes: %v", err)
	}
	clientCAPool := x509.NewCertPool()
	clientCAPool.AppendCertsFromPEM(caCertPEM)

	serverCertCfg, err := ca.MakeServerCertForDuration(sets.New("127.0.0.1"), 24*time.Hour)
	if err != nil {
		t.Fatalf("MakeServerCertForDuration: %v", err)
	}
	serverCertPEM, serverKeyPEM, err := serverCertCfg.GetPEMBytes()
	if err != nil {
		t.Fatalf("server cert GetPEMBytes: %v", err)
	}
	serverTLSCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "no client cert", http.StatusUnauthorized)
			return
		}
		opts := x509.VerifyOptions{
			Roots:     clientCAPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := r.TLS.PeerCertificates[0].Verify(opts); err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequestClientCert,
	}
	srv.StartTLS()
	return srv
}

func writeClientCert(t *testing.T, ca *crypto.CA, certFile, keyFile string, lifetime time.Duration) {
	t.Helper()
	cfg, err := ca.MakeClientCertificateForDuration(&userinfo.DefaultInfo{Name: "test-client"}, lifetime)
	if err != nil {
		t.Fatalf("MakeClientCertificateForDuration: %v", err)
	}
	certPEM, keyPEM, err := cfg.GetPEMBytes()
	if err != nil {
		t.Fatalf("GetPEMBytes: %v", err)
	}
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}

func doRequest(client *http.Client, url string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}
