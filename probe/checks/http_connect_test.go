package checks

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mwgg/libreping/pkg/protocol"
)

func testRoots(t *testing.T) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"example.com"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
	der, err = x509.CreateCertificate(rand.Reader, leaf, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return roots, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestHTTPConnectTLSBackends(t *testing.T) {
	t.Setenv("PROBE_BLOCK_PRIVATE", "false")
	reloadPolicy()
	t.Cleanup(reloadPolicy)
	roots, cert := testRoots(t)
	var hits [2]atomic.Int32
	var servers []*httptest.Server
	// Two addresses on the same port prove only the destination IP changes.
	for i, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		listener := ip + ":0"
		if i == 1 {
			_, port, _ := net.SplitHostPort(servers[0].Listener.Addr().String())
			listener = net.JoinHostPort(ip, port)
		}
		ln, err := net.Listen("tcp", listener)
		if err != nil {
			t.Fatal(err)
		}
		index := i
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits[index].Add(1)
			if !strings.HasPrefix(r.Host, "example.com:") || r.TLS.ServerName != "example.com" || r.URL.Path != "/health" || r.Method != "HEAD" {
				t.Errorf("wrong vhost: %s %+v", r.Host, r)
			}
			w.WriteHeader(204)
		}))
		srv.Listener.Close()
		srv.Listener = ln
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
		srv.StartTLS()
		t.Cleanup(srv.Close)
		servers = append(servers, srv)
	}
	_, port, _ := net.SplitHostPort(servers[0].Listener.Addr().String())
	spec := protocol.CheckSpec{Type: protocol.CheckHTTPConnect, Target: "https://example.com:" + port + "/health", Params: map[string]string{"method": "HEAD", "expect_status": "204"}}
	for _, ip := range []string{"127.0.0.1", "127.0.0.2"} {
		spec.Params["connect_address"] = ip
		out, _ := (HTTPConnectChecker{roots: roots}).Run(context.Background(), spec)
		if out.Status != protocol.StatusUp {
			t.Fatalf("%s: %+v", ip, out)
		}
	}
	for i := range hits {
		if hits[i].Load() != 1 {
			t.Fatalf("backend %d: %d", i, hits[i].Load())
		}
	}
	out, _ := (HTTPConnectChecker{}).Run(context.Background(), spec)
	if out.Status != protocol.StatusDown {
		t.Fatal("untrusted certificate accepted")
	}
	spec.Target = "https://wrong.example:" + port
	out, _ = (HTTPConnectChecker{roots: roots}).Run(context.Background(), spec)
	if out.Status != protocol.StatusDown {
		t.Fatal("wrong certificate hostname accepted")
	}
}

func TestHTTPConnectConfinementAndCompatibility(t *testing.T) {
	t.Setenv("PROBE_BLOCK_PRIVATE", "false")
	reloadPolicy()
	t.Cleanup(reloadPolicy)
	var escaped atomic.Int32
	dst := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { escaped.Add(1); w.Write([]byte("destination")) }))
	defer dst.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", dst.URL)
		w.WriteHeader(302)
		w.Write([]byte("redirect body"))
	}))
	defer srv.Close()
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	spec := protocol.CheckSpec{Type: protocol.CheckHTTPConnect, Target: "http://unresolvable.invalid:" + port, Params: map[string]string{"connect_address": "127.0.0.1", "keyword": "redirect body", "expect_status": "302"}}
	out, _ := (HTTPConnectChecker{}).Run(context.Background(), spec)
	if out.Status != protocol.StatusUp || escaped.Load() != 0 {
		t.Fatalf("redirect escaped: %+v", out)
	}
	spec.Params["keyword"] = "absent"
	out, _ = (HTTPConnectChecker{}).Run(context.Background(), spec)
	if out.Status != protocol.StatusDegraded {
		t.Fatalf("keyword: %+v", out)
	}
	delete(spec.Params, "keyword")
	spec.Params["expect_status"] = "200"
	out, _ = (HTTPConnectChecker{}).Run(context.Background(), spec)
	if out.Status != protocol.StatusDown {
		t.Fatalf("status: %+v", out)
	}
	// A reachable URL cannot rescue a bad or unreachable override.
	spec.Target = dst.URL
	for _, address := range []string{"bad", "127.0.0.2"} {
		spec.Params["connect_address"] = address
		out, _ = (HTTPConnectChecker{}).Run(context.Background(), spec)
		if out.Status != protocol.StatusDown || escaped.Load() != 0 {
			t.Fatalf("fallback for %s: %+v", address, out)
		}
	}
	t.Setenv("PROBE_BLOCK_PRIVATE", "true")
	reloadPolicy()
	spec.Params["connect_address"] = "127.0.0.1"
	out, _ = (HTTPConnectChecker{}).Run(context.Background(), spec)
	if out.Status != protocol.StatusDown || !strings.Contains(out.Detail["error"], "blocked") {
		t.Fatalf("policy: %+v", out)
	}
	t.Setenv("PROBE_BLOCK_PRIVATE", "false")
	reloadPolicy()
	spec.Type = protocol.CheckHTTP
	spec.Params = map[string]string{"connect_address": "bad"}
	out, _ = (HTTPChecker{}).Run(context.Background(), spec)
	if out.Status != protocol.StatusUp || escaped.Load() != 1 {
		t.Fatalf("ordinary HTTP changed: %+v", out)
	}
}
