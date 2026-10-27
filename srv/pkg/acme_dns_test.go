package pkg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type testDNSResolver struct {
	mu      sync.Mutex
	cnames  map[string]string
	txt     map[string][]string
	hideTXT bool
	lookups int
}

func (r *testDNSResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if target := r.cnames[name]; target != "" {
		return target + ".", nil
	}
	return "", &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}
func (r *testDNSResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	if r.hideTXT {
		return nil, nil
	}
	return append([]string(nil), r.txt[r.cnames[name]]...), nil
}

type dnsFixture struct {
	client        *acmeDNSClient
	resolver      *testDNSResolver
	server        *httptest.Server
	mu            sync.Mutex
	registrations int
	updates       int
	rejectUpdates bool
}

func newDNSFixture(t *testing.T) *dnsFixture {
	t.Helper()
	f := &dnsFixture{resolver: &testDNSResolver{cnames: make(map[string]string), txt: make(map[string][]string)}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method != "POST" {
			t.Error("unexpected method")
			w.WriteHeader(405)
			return
		}
		switch r.URL.Path {
		case "/register":
			f.registrations++
			sub := fmt.Sprintf("record%d", f.registrations)
			w.WriteHeader(201)
			json.NewEncoder(w).Encode(map[string]string{"username": "test-user", "password": "restricted-secret", "subdomain": sub, "fulldomain": sub + ".auth.example.net"})
		case "/update":
			f.updates++
			if f.rejectUpdates || r.Header.Get("X-Api-User") != "test-user" || r.Header.Get("X-Api-Key") != "restricted-secret" {
				w.WriteHeader(403)
				fmt.Fprint(w, `{"error":"restricted-secret"}`)
				return
			}
			var data struct {
				Subdomain string `json:"subdomain"`
				TXT       string `json:"txt"`
			}
			if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			if len(data.TXT) != 43 {
				t.Errorf("invalid ACME TXT digest: %q", data.TXT)
			}
			f.resolver.mu.Lock()
			target := data.Subdomain + ".auth.example.net"
			values := append(f.resolver.txt[target], data.TXT)
			if len(values) > 2 {
				values = values[len(values)-2:]
			}
			f.resolver.txt[target] = values
			f.resolver.mu.Unlock()
			json.NewEncoder(w).Encode(map[string]string{"txt": data.TXT})
		default:
			t.Errorf("unexpected acme-dns endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.server.Close)
	f.client = newACMEDNSClient()
	// Trust only the local fixture's certificate; retain production redirect policy.
	f.client.http.Transport = f.server.Client().Transport
	f.client.resolver = f.resolver
	f.client.pollInterval = time.Millisecond
	return f
}

func (f *dnsFixture) setCNAME(name, target string) {
	f.resolver.mu.Lock()
	defer f.resolver.mu.Unlock()
	f.resolver.cnames[name+"."] = target
}

func TestDNSDomainAndServiceValidation(t *testing.T) {
	req := testRequest()
	req.ChallengeType = ACMEDNS01
	req.DNSServiceURL = "https://AUTH.example.net/"
	req.Domains = []string{"Example.com", "*.Example.com.", "*.例子.中国", "example.com"}
	got, err := normalizeACMERequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if got.DNSServiceURL != "https://auth.example.net" || !reflect.DeepEqual(got.Domains, []string{"example.com", "*.example.com", "*.xn--fsqu00a.xn--fiqs8s"}) {
		t.Fatalf("unexpected normalization: %+v", got)
	}
	if !reflect.DeepEqual(dnsValidationDomains(got.Domains), []string{"example.com", "xn--fsqu00a.xn--fiqs8s"}) {
		t.Fatal("apex/wildcard delegation duplicated")
	}
	for _, domain := range []string{"*.*.example.com", "www.*.example.com", "*.127.0.0.1", "*.com", "*.example.com/path", "*.example.com:443"} {
		if _, err := normalizeACMEDomains([]string{domain}, ACMEDNS01); err == nil {
			t.Errorf("accepted %s", domain)
		}
	}
	for _, service := range []string{"http://auth.example.net", "https://user:pass@auth.example.net", "https://auth.example.net/?key=secret", "https://auth.example.net/#secret", "", "https:///register"} {
		if _, err := normalizeDNSServiceURL(service); err == nil {
			t.Errorf("accepted unsafe service URL %q", service)
		}
	}
	req.ChallengeType = "unsupported"
	if _, err := normalizeACMERequest(req); err == nil {
		t.Fatal("unknown challenge accepted")
	}
}

func TestDNSRegistrationReuseAndPrivateStorage(t *testing.T) {
	testCertEnvironment(t)
	f := newDNSFixture(t)
	domains := []string{"example.com", "*.example.com"}
	records, err := f.client.delegations(context.Background(), f.server.URL, domains, true)
	if err != nil || len(records) != 1 {
		t.Fatalf("register: %+v %v", records, err)
	}
	if records[0].Verified {
		t.Fatal("unconfigured CNAME reported ready")
	}
	encoded, _ := json.Marshal(records)
	if strings.Contains(string(encoded), "restricted-secret") || strings.Contains(string(encoded), "test-user") {
		t.Fatal("credentials exposed in API records")
	}
	path := acmeDNSBindingPath(f.server.URL, "example.com")
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("credentials permissions: %v %v", info, err)
	}
	f.setCNAME(records[0].Name, records[0].Target)
	for _, prepare := range []bool{false, true, true} {
		again, err := f.client.delegations(context.Background(), f.server.URL, domains, prepare)
		if err != nil || len(again) != 1 || !again[0].Verified || again[0].Target != records[0].Target {
			t.Fatalf("binding not reused: %+v %v", again, err)
		}
	}
	if f.registrations != 1 {
		t.Fatalf("registered %d times", f.registrations)
	}
	f.setCNAME(records[0].Name, "wrong.auth.example.net")
	again, err := f.client.delegations(context.Background(), f.server.URL, domains, false)
	if err != nil || again[0].Verified {
		t.Fatal("wrong CNAME reported ready")
	}
	if err := os.WriteFile(path, []byte("invalid json"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.delegations(context.Background(), f.server.URL, domains, true); err == nil {
		t.Fatal("corrupt credential replaced silently")
	}
	if f.registrations != 1 {
		t.Fatal("corrupt credentials triggered a new target")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.delegations(context.Background(), f.server.URL, domains, false); err == nil {
		t.Fatal("read-only check created missing credentials")
	}
	if f.registrations != 1 {
		t.Fatal("read-only check registered an account")
	}
}

func TestDNSTXTUpdatesPropagationAndErrors(t *testing.T) {
	testCertEnvironment(t)
	f := newDNSFixture(t)
	records, err := f.client.delegations(context.Background(), f.server.URL, []string{"example.com"}, true)
	if err != nil {
		t.Fatal(err)
	}
	f.setCNAME(records[0].Name, records[0].Target)
	binding, err := loadDNSBinding(f.server.URL, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	client := &acme.Client{Key: key}
	for _, token := range []string{"apex-token", "wildcard-token"} {
		cleanup, err := f.client.present(context.Background(), client, binding, &acme.Challenge{Token: token})
		if err != nil {
			t.Fatal(err)
		}
		cleanup()
	}
	values, _ := f.resolver.LookupTXT(context.Background(), "_acme-challenge.example.com.")
	if len(values) != 2 || values[0] == values[1] {
		t.Fatal("apex and wildcard TXT values overwritten")
	}
	f.resolver.mu.Lock()
	f.resolver.hideTXT = true
	f.resolver.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := f.client.present(ctx, client, binding, &acme.Challenge{Token: "never-visible"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("propagation wait did not time out: %v", err)
	}
	f.mu.Lock()
	f.rejectUpdates = true
	f.mu.Unlock()
	if _, err := f.client.present(context.Background(), client, binding, &acme.Challenge{Token: "reject"}); err == nil || strings.Contains(err.Error(), "restricted-secret") {
		t.Fatalf("update error missing or leaked credentials: %v", err)
	}
}

func TestDNSRedirectDoesNotForwardCredentials(t *testing.T) {
	var received bool
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received = true; w.WriteHeader(200) }))
	defer destination.Close()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := newACMEDNSClient()
	client.http.Transport = server.Client().Transport
	var result any
	err := client.post(context.Background(), server.URL+"/update", struct{}{}, &acmeDNSBinding{Username: "user", Password: "secret"}, 200, &result)
	if err == nil || received {
		t.Fatal("acme-dns redirect followed")
	}
}

func TestWildcardCertificateCoverage(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"example.com", "*.example.com"}}
	if err := verifyACMENames(cert, []string{"example.com", "*.example.com"}); err != nil {
		t.Fatal(err)
	}
	for _, names := range [][]string{{"*.other.com"}, {"*.api.example.com"}, {"foo.bar.example.com"}} {
		if err := verifyACMENames(cert, names); err == nil {
			t.Fatalf("accepted uncovered names: %v", names)
		}
	}
	if err := verifyACMENames(&x509.Certificate{DNSNames: []string{"www.example.com"}}, []string{"*.example.com"}); err == nil {
		t.Fatal("concrete domain substituted for wildcard")
	}
}

func TestRenewalPreservesDNSMethodAndLegacyHTTP(t *testing.T) {
	for _, method := range []string{ACMEDNS01, ""} {
		t.Run("method="+method, func(t *testing.T) {
			testCertEnvironment(t)
			cert, key := testCertificate(t, 1)
			meta := ACMEMetadata{Email: "admin@example.com", Domains: []string{"example.com"}, ChallengeType: method, Staging: true}
			if method == ACMEDNS01 {
				meta.DNSServiceURL = "https://auth.example.net"
			}
			config := map[string]any{"id": "testcert", "name": "Test", "type": CertTypeLetsEncrypt, "createdAt": int64(1234), "acme": meta}
			if _, err := saveCert("testcert", config, cert, key); err != nil {
				t.Fatal(err)
			}
			check := func(_ context.Context, req ACMERequest) error {
				expected := method
				if expected == "" {
					expected = ACMEHTTP01
				}
				if req.ChallengeType != expected || req.DNSServiceURL != meta.DNSServiceURL || !req.Staging {
					t.Fatalf("renewal settings changed: %+v", req)
				}
				return nil
			}
			updated, _, err := issueACMECert(context.Background(), ACMERequest{ID: "testcert", ChallengeType: ACMEHTTP01, DNSServiceURL: "https://wrong.example"}, true, check, func(context.Context, ACMERequest) (string, string, error) { return cert, key, nil })
			if err != nil {
				t.Fatal(err)
			}
			if updated["createdAt"] != int64(1234) {
				t.Fatal("creation time changed")
			}
		})
	}
}
