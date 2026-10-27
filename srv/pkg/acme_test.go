package pkg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func testRequest() ACMERequest {
	return ACMERequest{ID: "testcert", Name: "Test", Email: "admin@example.com", Domains: []string{"example.com"}, AcceptTerms: true, ChallengeType: ACMEHTTP01}
}

func TestNormalizeACMERequest(t *testing.T) {
	req := testRequest()
	req.Domains = []string{" Example.COM. ", "example.com", "例子.中国"}
	got, err := normalizeACMERequest(req)
	if err != nil || !reflect.DeepEqual(got.Domains, []string{"example.com", "xn--fsqu00a.xn--fiqs8s"}) {
		t.Fatalf("normalization: %+v, %v", got, err)
	}
	for _, domain := range []string{"*.example.com", "https://example.com", "example.com:80", "example.com/path", "localhost", "127.0.0.1", "-bad.example", "bad..example", "example.com;"} {
		req := testRequest()
		req.Domains = []string{domain}
		if _, err := normalizeACMERequest(req); err == nil {
			t.Errorf("accepted invalid domain %q", domain)
		}
	}
	for _, change := range []func(*ACMERequest){
		func(r *ACMERequest) { r.AcceptTerms = false },
		func(r *ACMERequest) { r.ID = "../cert" },
		func(r *ACMERequest) { r.Email = "invalid" },
		func(r *ACMERequest) { r.Domains = nil },
		func(r *ACMERequest) { r.Name = " " },
	} {
		req := testRequest()
		change(&req)
		if _, err := normalizeACMERequest(req); err == nil {
			t.Errorf("accepted invalid request: %+v", req)
		}
	}
}

func TestChallengeIsolationAndCleanup(t *testing.T) {
	cleanup := putChallenge("test-token", "example.com", "test-response")
	defer cleanup()
	for _, tc := range []struct {
		method, path, host string
		status             int
	}{
		{"GET", ACMEChallengePrefix + "test-token", "EXAMPLE.com:80", 200},
		{"HEAD", ACMEChallengePrefix + "test-token", "example.com", 200},
		{"GET", ACMEChallengePrefix + "test-token", "other.example", 404},
		{"GET", ACMEChallengePrefix + "unknown", "example.com", 404},
		{"GET", "/test-token", "example.com", 404},
		{"POST", ACMEChallengePrefix + "test-token", "example.com", 405},
	} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		r.Host = tc.host
		w := httptest.NewRecorder()
		ServeACMEChallenge(w, r)
		if w.Code != tc.status {
			t.Errorf("%+v: status %d", tc, w.Code)
		}
		if w.Code == 200 && tc.method == "GET" && w.Body.String() != "test-response" {
			t.Fatal("wrong challenge response")
		}
	}
	cleanup()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://example.com"+ACMEChallengePrefix+"test-token", nil)
	ServeACMEChallenge(w, r)
	if w.Code != 404 {
		t.Fatal("expired challenge still exposed")
	}
}

func testCertEnvironment(t *testing.T) string {
	t.Helper()
	oldBase, oldCert, oldBin, oldConf := CfgBase, CertDir, NginxBin, NginxConfFile
	root := t.TempDir()
	CfgBase, CertDir = root, filepath.Join(root, "certs")
	NginxBin, NginxConfFile = filepath.Join(root, "nginx"), filepath.Join(root, "nginx.conf")
	// Controlled Nginx stand-in distinguishes syntax checking from reload failure.
	script := "#!/bin/sh\nif [ -e '" + root + "/fail-check' ] && [ \"$1\" = '-t' ]; then exit 1; fi\nif [ -e '" + root + "/fail-reload' ] && [ \"$1\" = '-s' ]; then exit 1; fi\nexit 0\n"
	if err := os.WriteFile(NginxBin, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { CfgBase, CertDir, NginxBin, NginxConfFile = oldBase, oldCert, oldBin, oldConf })
	return root
}

func testCertificate(t *testing.T, serial int64) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"example.com"}, Subject: pkix.Name{CommonName: "Test issuer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestIssueRenewAndRollback(t *testing.T) {
	root := testCertEnvironment(t)
	cert1, key1 := testCertificate(t, 1)
	cert2, key2 := testCertificate(t, 2)
	check := func(context.Context, ACMERequest) error { return nil }
	obtain := func(context.Context, ACMERequest) (string, string, error) { return cert1, key1, nil }
	config, _, err := issueACMECert(context.Background(), testRequest(), false, check, obtain)
	if err != nil {
		t.Fatal(err)
	}
	pemPath, keyPath, configPath := PathCert("testcert")
	for _, path := range []string{pemPath, keyPath, configPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("insecure permissions: %s %v", path, info.Mode())
		}
	}
	if _, _, err := issueACMECert(context.Background(), testRequest(), false, check, obtain); err == nil {
		t.Fatal("duplicate issuance accepted")
	}
	if _, err := SaveCert("testcert", map[string]any{"type": "custom"}, cert2, key2); err == nil {
		t.Fatal("manual replacement of managed certificate accepted")
	}
	before, _ := os.ReadFile(configPath)
	obtain = func(_ context.Context, r ACMERequest) (string, string, error) {
		if !reflect.DeepEqual(r, testRequest()) {
			t.Errorf("renewal trusted caller instead of saved config: %+v", r)
		}
		return cert2, key2, nil
	}
	for _, fail := range []string{"fail-check", "fail-reload"} {
		if err := os.WriteFile(filepath.Join(root, fail), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := issueACMECert(context.Background(), ACMERequest{ID: "testcert", Domains: []string{"attacker.example"}}, true, check, obtain); err == nil {
			t.Fatal("expected activation failure")
		}
		for path, expected := range map[string]string{pemPath: cert1, keyPath: key1, configPath: string(before)} {
			actual, err := os.ReadFile(path)
			if err != nil || string(actual) != expected {
				t.Errorf("rollback failed: %s %v", path, err)
			}
		}
		os.Remove(filepath.Join(root, fail))
	}
	renewed, _, err := issueACMECert(context.Background(), ACMERequest{ID: "testcert"}, true, check, obtain)
	if err != nil {
		t.Fatal(err)
	}
	if renewed["createdAt"] != config["createdAt"] || renewed["pemPath"] != config["pemPath"] || renewed["keyRaw"] != key2 {
		t.Fatalf("renewal did not preserve identity/update key: %+v", renewed["id"])
	}
	certMutationMu.Lock()
	if _, err := SaveCert("testcert", nil, "", ""); err == nil {
		t.Error("deletion raced with issuance")
	}
	if _, _, err := IssueACMECert(context.Background(), testRequest(), true); err == nil {
		t.Error("concurrent issuance accepted")
	}
	certMutationMu.Unlock()
	if _, err := SaveCert("testcert", nil, "", ""); err != nil {
		t.Fatal(err)
	}
}

func TestFailuresDoNotPersistCertificates(t *testing.T) {
	testCertEnvironment(t)
	checkFailure := errors.New("route unavailable")
	_, _, err := issueACMECert(context.Background(), testRequest(), false,
		func(context.Context, ACMERequest) error { return checkFailure },
		func(context.Context, ACMERequest) (string, string, error) {
			t.Fatal("CA called despite failed preflight")
			return "", "", nil
		})
	if !errors.Is(err, checkFailure) {
		t.Fatal(err)
	}
	_, _, err = issueACMECert(context.Background(), testRequest(), false,
		func(context.Context, ACMERequest) error { return nil },
		func(context.Context, ACMERequest) (string, string, error) {
			return "", "", errors.New("authorization failed")
		})
	if err == nil {
		t.Fatal("CA failure not returned")
	}
	list, err := ListCert()
	if err != nil || len(list) != 0 {
		t.Fatal("failed issuance persisted a certificate")
	}
	if _, err := SaveCert("invalid", map[string]any{}, "bad PEM", "bad key"); err == nil {
		t.Fatal("invalid keypair accepted")
	}
}

func TestAccountPersistenceAndEnvironmentIsolation(t *testing.T) {
	testCertEnvironment(t)
	key1, err := acmeAccountKey("admin@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	key2, err := acmeAccountKey("admin@example.com", false)
	if err != nil {
		t.Fatal(err)
	}
	key3, err := acmeAccountKey("admin@example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if !key1.Equal(key2) || key1.Equal(key3) {
		t.Fatal("account persistence/environment isolation failed")
	}
}

// Exercise the real ACME protocol client against a local CA, including existing
// account reuse, challenge selection, CSR signing and token cleanup.
func TestACMEOrderProtocol(t *testing.T) {
	for _, tc := range []struct {
		method string
		reject bool
	}{{ACMEHTTP01, false}, {ACMEHTTP01, true}, {ACMEDNS01, false}, {ACMEDNS01, true}} {
		t.Run(fmt.Sprintf("%s/reject=%t", tc.method, tc.reject), func(t *testing.T) {
			req := testRequest()
			req.ChallengeType = tc.method
			var dns *dnsFixture
			if tc.method == ACMEDNS01 {
				testCertEnvironment(t)
				dns = newDNSFixture(t)
				req.Domains = []string{"example.com", "*.example.com"}
				req.DNSServiceURL = dns.server.URL
				records, err := dns.client.delegations(context.Background(), req.DNSServiceURL, req.Domains, true)
				if err != nil {
					t.Fatal(err)
				}
				dns.setCNAME(records[0].Name, records[0].Target)
			}
			accountKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			var nonce atomic.Int64
			var base string
			accepted := make(map[string]bool)
			var chain []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce%d", nonce.Add(1)))
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/directory":
					json.NewEncoder(w).Encode(map[string]any{"newNonce": base + "/nonce", "newAccount": base + "/account", "newOrder": base + "/new-order"})
				case "/nonce":
					w.WriteHeader(200)
				case "/account":
					w.Header().Set("Location", base+"/account/1")
					// 200 means already registered: renewal must still proceed.
					fmt.Fprint(w, `{"status":"valid"}`)
				case "/new-order":
					w.Header().Set("Location", base+"/order/1")
					w.WriteHeader(201)
					auths := []string{base + "/auth/1"}
					if tc.method == ACMEDNS01 {
						auths = append(auths, base+"/auth/2")
					}
					json.NewEncoder(w).Encode(map[string]any{"status": "pending", "authorizations": auths, "finalize": base + "/finalize"})
				case "/auth/1", "/auth/2":
					id := strings.TrimPrefix(r.URL.Path, "/auth/")
					status := "pending"
					if accepted[id] {
						status = "valid"
						if tc.reject {
							status = "invalid"
						}
					}
					json.NewEncoder(w).Encode(map[string]any{"status": status, "wildcard": id == "2", "identifier": map[string]string{"type": "dns", "value": "example.com"}, "challenges": []map[string]string{
						{"type": "dns-01", "url": base + "/dns/" + id, "token": "protocol-token-" + id, "status": status},
						{"type": "http-01", "url": base + "/challenge/" + id, "token": "protocol-token-" + id, "status": status},
					}})
				case "/challenge/1":
					if tc.method != ACMEHTTP01 {
						t.Error("DNS issuance selected HTTP challenge")
					}
					challengeReq := httptest.NewRequest("GET", "http://example.com"+ACMEChallengePrefix+"protocol-token-1", nil)
					result := httptest.NewRecorder()
					ServeACMEChallenge(result, challengeReq)
					client := acme.Client{Key: accountKey}
					expected, _ := client.HTTP01ChallengeResponse("protocol-token-1")
					if result.Code != 200 || result.Body.String() != expected {
						t.Errorf("HTTP validation response: %s", result.Body.String())
					}
					accepted["1"] = true
					fmt.Fprint(w, `{"type":"http-01","status":"pending"}`)
				case "/dns/1", "/dns/2":
					if dns == nil {
						t.Error("HTTP issuance selected DNS challenge")
						w.WriteHeader(400)
						return
					}
					id := strings.TrimPrefix(r.URL.Path, "/dns/")
					client := acme.Client{Key: accountKey}
					expected, _ := client.DNS01ChallengeRecord("protocol-token-" + id)
					values, _ := dns.resolver.LookupTXT(r.Context(), "_acme-challenge.example.com.")
					found := false
					for _, value := range values {
						if value == expected {
							found = true
						}
					}
					if !found {
						t.Error("CA could not find expected TXT record")
					}
					if id == "2" && len(values) != 2 {
						t.Error("wildcard overwrote apex challenge")
					}
					accepted[id] = true
					fmt.Fprint(w, `{"type":"dns-01","status":"pending"}`)
				case "/order/1":
					w.Header().Set("Location", base+"/order/1")
					json.NewEncoder(w).Encode(map[string]any{"status": "ready", "finalize": base + "/finalize"})
				case "/finalize":
					var jws struct{ Payload string }
					json.NewDecoder(r.Body).Decode(&jws)
					payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
					var data struct{ CSR string }
					json.Unmarshal(payload, &data)
					der, _ := base64.RawURLEncoding.DecodeString(data.CSR)
					csr, err := x509.ParseCertificateRequest(der)
					if err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					if err := csr.CheckSignature(); err != nil {
						t.Error(err)
					}
					tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: csr.DNSNames, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
					cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, caKey)
					if err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					chain = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
					json.NewEncoder(w).Encode(map[string]any{"status": "valid", "certificate": base + "/cert"})
				case "/cert":
					w.Header().Set("Content-Type", "application/pem-certificate-chain")
					w.Write(chain)
				default:
					t.Errorf("unexpected ACME route: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			base = server.URL
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			present := presentHTTPChallenge
			if dns != nil {
				present = func(ctx context.Context, client *acme.Client, auth *acme.Authorization, challenge *acme.Challenge) (func(), error) {
					binding, err := loadDNSBinding(req.DNSServiceURL, auth.Identifier.Value)
					if err != nil {
						return nil, err
					}
					return dns.client.present(ctx, client, binding, challenge)
				}
			}
			cert, key, err := orderACMEWithPresenter(ctx, req, &acme.Client{Key: accountKey, DirectoryURL: base + "/directory", HTTPClient: server.Client()}, present)
			if tc.reject {
				if err == nil {
					t.Fatal("invalid authorization accepted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := tls.X509KeyPair([]byte(cert), []byte(key)); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(cert, "BEGIN CERTIFICATE") {
					t.Fatal("missing certificate")
				}
				block, _ := pem.Decode([]byte(cert))
				leaf, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				if err := verifyACMENames(leaf, req.Domains); err != nil {
					t.Fatal(err)
				}
			}
			activeChallenges.RLock()
			remaining := len(activeChallenges.values)
			activeChallenges.RUnlock()
			if remaining != 0 {
				t.Fatal("challenge leaked after order completion/failure")
			}
		})
	}
}
