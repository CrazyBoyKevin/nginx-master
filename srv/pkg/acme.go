package pkg

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/net/idna"
)

const (
	CertTypeLetsEncrypt  = "letsencrypt"
	ACMEChallengePrefix  = "/.well-known/acme-challenge/"
	acmeStagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// Only one certificate mutation runs at a time, including long ACME operations.
// Other writes fail promptly, so deletion/import cannot race with renewal.
var certMutationMu sync.Mutex

type ACMERequest struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Email         string   `json:"email"`
	Domains       []string `json:"domains"`
	Staging       bool     `json:"staging"`
	AcceptTerms   bool     `json:"acceptTerms"`
	ChallengeType string   `json:"challengeType"`
	DNSServiceURL string   `json:"dnsServiceURL,omitempty"`
}

type ACMEMetadata struct {
	Email         string   `json:"email"`
	Domains       []string `json:"domains"`
	Staging       bool     `json:"staging"`
	ChallengeType string   `json:"challengeType"`
	DNSServiceURL string   `json:"dnsServiceURL,omitempty"`
}

type acmeChallenge struct{ host, response string }

var activeChallenges = struct {
	sync.RWMutex
	values map[string]acmeChallenge
}{values: make(map[string]acmeChallenge)}

func putChallenge(token, host, response string) func() {
	activeChallenges.Lock()
	activeChallenges.values[token] = acmeChallenge{host, response}
	activeChallenges.Unlock()
	return func() {
		activeChallenges.Lock()
		delete(activeChallenges.values, token)
		activeChallenges.Unlock()
	}
}

// This endpoint is public, but only serves exact, currently active tokens.
func ServeACMEChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, ACMEChallengePrefix)
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	activeChallenges.RLock()
	challenge, ok := activeChallenges.values[token]
	activeChallenges.RUnlock()
	if !strings.HasPrefix(r.URL.Path, ACMEChallengePrefix) || !ok || !strings.EqualFold(strings.TrimSuffix(host, "."), challenge.host) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, challenge.response)
	}
}

func normalizeACMERequest(req ACMERequest) (ACMERequest, error) {
	if !IsValidId(req.ID) {
		return req, errors.New("无效的证书 ID")
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 200 {
		return req, errors.New("请填写证书名称（不超过 200 字节）")
	}
	req.Email = strings.TrimSpace(req.Email)
	address, err := mail.ParseAddress(req.Email)
	if err != nil || address.Address != req.Email || !strings.Contains(req.Email, "@") {
		return req, errors.New("请填写有效的邮箱地址")
	}
	if !req.AcceptTerms {
		return req, errors.New("请先同意 Let's Encrypt 服务条款")
	}
	// Certificates issued before challengeType was introduced used HTTP-01.
	if req.ChallengeType == "" {
		req.ChallengeType = ACMEHTTP01
	}
	if req.ChallengeType != ACMEHTTP01 && req.ChallengeType != ACMEDNS01 {
		return req, errors.New("不支持的验证方式")
	}
	if req.ChallengeType == ACMEDNS01 {
		req.DNSServiceURL, err = normalizeDNSServiceURL(req.DNSServiceURL)
		if err != nil {
			return req, err
		}
	} else {
		req.DNSServiceURL = ""
	}
	req.Domains, err = normalizeACMEDomains(req.Domains, req.ChallengeType)
	return req, err
}

func normalizeACMEDomains(input []string, challengeType string) ([]string, error) {
	if len(input) == 0 || len(input) > 100 {
		return nil, errors.New("请填写 1 至 100 个域名")
	}
	labelRE := regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	domains := []string{}
	seen := make(map[string]bool)
	for _, raw := range input {
		value := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		wildcard := strings.HasPrefix(value, "*.")
		if wildcard && challengeType != ACMEDNS01 {
			return nil, errors.New("HTTP-01 不支持泛域名，请选择 CNAME 委托验证")
		}
		if wildcard {
			value = strings.TrimPrefix(value, "*.")
		}
		domain, err := idna.Lookup.ToASCII(value)
		if err != nil || len(domain) > 253 || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
			return nil, fmt.Errorf("无效的域名 %q：请填写完整域名，不含协议、端口或路径", raw)
		}
		for _, label := range strings.Split(domain, ".") {
			if !labelRE.MatchString(label) {
				return nil, fmt.Errorf("无效的域名 %q：通配符只能出现在最左侧，如 *.example.com", raw)
			}
		}
		if wildcard {
			domain = "*." + domain
		}
		if !seen[domain] {
			domains = append(domains, domain)
			seen[domain] = true
		}
	}
	return domains, nil
}

// Probe Nginx locally before placing an ACME order. Public reachability is
// subsequently checked by the CA; redirects here indicate a missing exemption.
func checkHTTP01Routes(ctx context.Context, domains []string) error {
	client := &http.Client{
		Timeout:       10 * time.Second,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	for _, domain := range domains {
		random := make([]byte, 24)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		token := hex.EncodeToString(random)
		cleanup := putChallenge(token, domain, token)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1"+ACMEChallengePrefix+token, nil)
		if err != nil {
			cleanup()
			return err
		}
		req.Host = domain
		resp, err := client.Do(req)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			if readErr != nil || resp.StatusCode != http.StatusOK || string(body) != token {
				err = fmt.Errorf("验证路径响应不匹配（HTTP %d）", resp.StatusCode)
			}
		}
		cleanup()
		if err != nil {
			return fmt.Errorf("%s 的 HTTP-01 路由检查失败：%w；请在站点管理中配置该域名、启用 HTTP 80 并重新保存，检查额外的重定向/访问限制", domain, err)
		}
	}
	return nil
}

func acmeAccountKey(email string, staging bool) (*ecdsa.PrivateKey, error) {
	digest := sha256.Sum256([]byte(fmt.Sprintf("%t:%s", staging, email)))
	path := filepath.Join(CfgBase, "acme", hex.EncodeToString(digest[:])+".key")
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, errors.New("ACME 账户密钥损坏")
		}
		return x509.ParseECPrivateKey(block.Bytes)
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writePrivateFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}

func obtainACMECertificate(ctx context.Context, req ACMERequest) (string, string, error) {
	key, err := acmeAccountKey(req.Email, req.Staging)
	if err != nil {
		return "", "", err
	}
	directory := acme.LetsEncryptURL
	if req.Staging {
		directory = acmeStagingDirectory
	}
	client := &acme.Client{Key: key, DirectoryURL: directory, HTTPClient: &http.Client{Timeout: 30 * time.Second}, UserAgent: "nginx-master"}
	return orderACMECertificate(ctx, req, client)
}

func orderACMECertificate(ctx context.Context, req ACMERequest, client *acme.Client) (string, string, error) {
	present := presentHTTPChallenge
	if req.ChallengeType == ACMEDNS01 {
		dnsClient := newACMEDNSClient()
		present = func(ctx context.Context, client *acme.Client, auth *acme.Authorization, challenge *acme.Challenge) (func(), error) {
			binding, err := loadDNSBinding(req.DNSServiceURL, strings.TrimPrefix(auth.Identifier.Value, "*."))
			if err != nil {
				return nil, err
			}
			return dnsClient.present(ctx, client, binding, challenge)
		}
	}
	return orderACMEWithPresenter(ctx, req, client, present)
}

type challengePresenter func(context.Context, *acme.Client, *acme.Authorization, *acme.Challenge) (func(), error)

func presentHTTPChallenge(_ context.Context, client *acme.Client, auth *acme.Authorization, challenge *acme.Challenge) (func(), error) {
	response, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		return nil, err
	}
	return putChallenge(challenge.Token, auth.Identifier.Value, response), nil
}

func orderACMEWithPresenter(ctx context.Context, req ACMERequest, client *acme.Client, present challengePresenter) (string, string, error) {
	challengeType := req.ChallengeType
	if challengeType == "" {
		challengeType = ACMEHTTP01
	}
	if _, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + req.Email}}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return "", "", fmt.Errorf("注册 ACME 账户失败：%w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(req.Domains...))
	if err != nil {
		return "", "", fmt.Errorf("创建签发订单失败：%w", err)
	}
	for _, url := range order.AuthzURLs {
		auth, err := client.GetAuthorization(ctx, url)
		if err != nil {
			return "", "", err
		}
		if auth.Status == acme.StatusValid {
			continue
		}
		var challenge *acme.Challenge
		for _, candidate := range auth.Challenges {
			if candidate.Type == challengeType {
				challenge = candidate
				break
			}
		}
		if challenge == nil {
			return "", "", fmt.Errorf("签发服务没有提供 %s 验证方式", challengeType)
		}
		cleanup, err := present(ctx, client, auth, challenge)
		if err != nil {
			return "", "", err
		}
		// Keep tokens until finalization, including retries from different CA validators.
		defer cleanup()
		if _, err := client.Accept(ctx, challenge); err != nil {
			return "", "", err
		}
		if _, err := client.WaitAuthorization(ctx, url); err != nil {
			hint := "请确认公网 A/AAAA 解析、80 端口及验证路径可达"
			if challengeType == ACMEDNS01 {
				hint = "请确认 CNAME 委托和验证 TXT 已在公网生效"
			}
			return "", "", fmt.Errorf("%s 验证失败：%w；%s", auth.Identifier.Value, err, hint)
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return "", "", err
	}
	// RSA preserves compatibility with the existing browser-side PEM validator.
	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: req.Domains}, certKey)
	if err != nil {
		return "", "", err
	}
	chain, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return "", "", fmt.Errorf("签发证书失败：%w", err)
	}
	var certPEM strings.Builder
	for _, der := range chain {
		certPEM.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certKey)})
	return certPEM.String(), string(keyPEM), nil
}

// IssueACMECert handles initial issuance and renewal using the same stable paths.
// Renewal reads all order parameters from disk instead of trusting the caller.
func IssueACMECert(ctx context.Context, req ACMERequest, renew bool) (map[string]any, string, error) {
	return issueACMECert(ctx, req, renew, checkACMEPreflight, obtainACMECertificate)
}

func issueACMECert(ctx context.Context, req ACMERequest, renew bool,
	checkPreflight func(context.Context, ACMERequest) error,
	obtain func(context.Context, ACMERequest) (string, string, error),
) (map[string]any, string, error) {
	if !IsValidId(req.ID) {
		return nil, "", errors.New("无效的证书 ID")
	}
	if !certMutationMu.TryLock() {
		return nil, "", errors.New("有证书操作正在进行，请完成后再试")
	}
	defer certMutationMu.Unlock()
	_, _, configPath := PathCert(req.ID)
	data, readErr := os.ReadFile(configPath)
	createdAt := time.Now().UnixMilli()
	if renew {
		if readErr != nil {
			return nil, "", fmt.Errorf("读取待续签证书失败：%w", readErr)
		}
		var saved struct {
			Type      string        `json:"type"`
			Name      string        `json:"name"`
			CreatedAt int64         `json:"createdAt"`
			ACME      *ACMEMetadata `json:"acme"`
		}
		if err := json.Unmarshal(data, &saved); err != nil {
			return nil, "", err
		}
		if saved.Type != CertTypeLetsEncrypt || saved.ACME == nil {
			return nil, "", errors.New("只有通过面板签发的 Let's Encrypt 证书支持一键续签")
		}
		req = ACMERequest{ID: req.ID, Name: saved.Name, Email: saved.ACME.Email, Domains: saved.ACME.Domains, Staging: saved.ACME.Staging, AcceptTerms: true, ChallengeType: saved.ACME.ChallengeType, DNSServiceURL: saved.ACME.DNSServiceURL}
		createdAt = saved.CreatedAt
	} else if !os.IsNotExist(readErr) {
		if readErr != nil {
			return nil, "", readErr
		}
		return nil, "", errors.New("证书 ID 已存在，请使用续签功能")
	}
	req, err := normalizeACMERequest(req)
	if err != nil {
		return nil, "", err
	}
	timeout := 4 * time.Minute
	if req.ChallengeType == ACMEDNS01 {
		timeout = 10 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := checkPreflight(ctx, req); err != nil {
		return nil, "", err
	}
	certPEM, keyPEM, err := obtain(ctx, req)
	if err != nil {
		return nil, "", err
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, "", errors.New("签发服务返回了空证书")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	if err := verifyACMENames(cert, req.Domains); err != nil {
		return nil, "", err
	}
	pemPath, keyPath, _ := PathCert(req.ID)
	config := map[string]any{
		"id": req.ID, "type": CertTypeLetsEncrypt, "name": req.Name,
		"createdAt": createdAt, "updateAt": time.Now().UnixMilli(),
		"domain": strings.Join(cert.DNSNames, ", "), "issuer": cert.Issuer.String(),
		"effectAt": cert.NotBefore.Unix(), "expiredAt": cert.NotAfter.Unix(),
		"pemRaw": certPEM, "keyRaw": keyPEM, "pemPath": pemPath, "keyPath": keyPath,
		"acme": ACMEMetadata{Email: req.Email, Domains: req.Domains, Staging: req.Staging, ChallengeType: req.ChallengeType, DNSServiceURL: req.DNSServiceURL},
	}
	output, err := saveCert(req.ID, config, certPEM, keyPEM)
	if err != nil {
		return nil, output, err
	}
	return config, output, nil
}

func verifyACMENames(cert *x509.Certificate, domains []string) error {
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			found := false
			for _, name := range cert.DNSNames {
				if strings.EqualFold(name, domain) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("签发的证书缺少泛域名 %s", domain)
			}
		} else if err := cert.VerifyHostname(domain); err != nil {
			return err
		}
	}
	return nil
}
