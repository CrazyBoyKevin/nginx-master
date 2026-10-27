package pkg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
)

const (
	ACMEHTTP01 = "http-01"
	ACMEDNS01  = "dns-01"
)

// Registration credentials never appear in certificate metadata or API responses.
// A binding is shared by the apex and wildcard, across certificates/environments.
type acmeDNSBinding struct {
	Domain     string `json:"domain"`
	ServiceURL string `json:"serviceURL"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Subdomain  string `json:"subdomain"`
	FullDomain string `json:"fulldomain"`
}

type ACMEDelegation struct {
	Domain   string `json:"domain"`
	Name     string `json:"name"`
	Target   string `json:"target"`
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
}

type dnsResolver interface {
	LookupCNAME(context.Context, string) (string, error)
	LookupTXT(context.Context, string) ([]string, error)
}

type acmeDNSClient struct {
	http         *http.Client
	resolver     dnsResolver
	pollInterval time.Duration
}

var acmeDNSRegistrationMu sync.Mutex

func newACMEDNSClient() *acmeDNSClient {
	return &acmeDNSClient{
		http: &http.Client{
			Timeout: 20 * time.Second,
			// Do not forward restricted credentials to redirect destinations.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		resolver:     &net.Resolver{PreferGo: true},
		pollInterval: 3 * time.Second,
	}
}

func normalizeDNSServiceURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("请填写 acme-dns 服务的 HTTPS 地址，不包含账户密码、查询参数或片段")
	}
	u.Host = strings.ToLower(u.Host)
	return strings.TrimRight(u.String(), "/"), nil
}

func dnsValidationDomains(domains []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, domain := range domains {
		domain = strings.TrimPrefix(domain, "*.")
		if !seen[domain] {
			result = append(result, domain)
			seen[domain] = true
		}
	}
	return result
}

func acmeDNSBindingPath(serviceURL, domain string) string {
	hash := sha256.Sum256([]byte(serviceURL + "\x00" + domain))
	return filepath.Join(CfgBase, "acme-dns", hex.EncodeToString(hash[:])+".json")
}

func validateDNSBinding(binding acmeDNSBinding) error {
	token := regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
	if !token.MatchString(binding.Username) || !token.MatchString(binding.Password) || !token.MatchString(binding.Subdomain) {
		return errors.New("acme-dns 返回了无效的验证凭据")
	}
	names, err := normalizeACMEDomains([]string{binding.FullDomain}, ACMEHTTP01)
	if err != nil || names[0] != binding.FullDomain || !strings.HasPrefix(binding.FullDomain, binding.Subdomain+".") {
		return errors.New("acme-dns 返回了无效的验证目标域名")
	}
	return nil
}

func loadDNSBinding(serviceURL, domain string) (acmeDNSBinding, error) {
	var binding acmeDNSBinding
	data, err := os.ReadFile(acmeDNSBindingPath(serviceURL, domain))
	if err != nil {
		if os.IsNotExist(err) {
			return binding, fmt.Errorf("%s 尚未配置委托验证，请先生成 CNAME 记录", domain)
		}
		return binding, err
	}
	if err := json.Unmarshal(data, &binding); err != nil {
		return binding, errors.New("委托验证凭据文件损坏，请从备份恢复")
	}
	if binding.ServiceURL != serviceURL || binding.Domain != domain {
		return binding, errors.New("委托验证凭据与域名或服务不匹配")
	}
	return binding, validateDNSBinding(binding)
}

func (client *acmeDNSClient) post(ctx context.Context, endpoint string, body any, binding *acmeDNSBinding, expectedStatus int, result any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if binding != nil {
		req.Header.Set("X-Api-User", binding.Username)
		req.Header.Set("X-Api-Key", binding.Password)
	}
	resp, err := client.http.Do(req)
	if err != nil {
		return fmt.Errorf("连接 acme-dns 服务失败：%w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != expectedStatus {
		// Response bodies may echo credentials; never return them to the browser.
		return fmt.Errorf("acme-dns 请求失败（HTTP %d），请检查服务地址、权限或服务日志", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(result); err != nil {
		return errors.New("acme-dns 返回了无效的 JSON 响应")
	}
	return nil
}

func (client *acmeDNSClient) checkCNAME(ctx context.Context, binding acmeDNSBinding) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	name := "_acme-challenge." + binding.Domain
	target, err := client.resolver.LookupCNAME(ctx, name+".")
	if err != nil {
		return fmt.Errorf("尚未查到 %s 的 CNAME，请添加解析并等待生效", name)
	}
	if !strings.EqualFold(strings.TrimSuffix(target, "."), binding.FullDomain) {
		return fmt.Errorf("%s 的 CNAME 目标不匹配，请设置为 %s", name, binding.FullDomain)
	}
	return nil
}

// prepare=false is strictly read-only: missing/corrupt credentials must never
// silently create a new target and invalidate an existing delegation.
func ACMEDelegations(ctx context.Context, serviceURL string, domains []string, prepare bool) ([]ACMEDelegation, error) {
	return newACMEDNSClient().delegations(ctx, serviceURL, domains, prepare)
}

func (client *acmeDNSClient) delegations(ctx context.Context, serviceURL string, domains []string, prepare bool) ([]ACMEDelegation, error) {
	serviceURL, err := normalizeDNSServiceURL(serviceURL)
	if err != nil {
		return nil, err
	}
	domains, err = normalizeACMEDomains(domains, ACMEDNS01)
	if err != nil {
		return nil, err
	}
	if !acmeDNSRegistrationMu.TryLock() {
		return nil, errors.New("正在配置验证记录，请稍后再试")
	}
	defer acmeDNSRegistrationMu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	result := []ACMEDelegation{}
	for _, domain := range dnsValidationDomains(domains) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := acmeDNSBindingPath(serviceURL, domain)
		_, statErr := os.Stat(path)
		if prepare && os.IsNotExist(statErr) {
			var binding acmeDNSBinding
			if err := client.post(ctx, serviceURL+"/register", struct{}{}, nil, http.StatusCreated, &binding); err != nil {
				return nil, err
			}
			binding.Domain, binding.ServiceURL = domain, serviceURL
			binding.FullDomain = strings.ToLower(strings.TrimSuffix(binding.FullDomain, "."))
			if err := validateDNSBinding(binding); err != nil {
				return nil, err
			}
			data, err := json.Marshal(binding)
			if err != nil {
				return nil, err
			}
			if err := writePrivateFile(path, data); err != nil {
				return nil, fmt.Errorf("保存委托验证凭据失败：%w", err)
			}
		}
		binding, err := loadDNSBinding(serviceURL, domain)
		if err != nil {
			return nil, err
		}
		record := ACMEDelegation{Domain: domain, Name: "_acme-challenge." + domain, Target: binding.FullDomain, Verified: true, Message: "CNAME 已生效"}
		if err := client.checkCNAME(ctx, binding); err != nil {
			record.Verified = false
			record.Message = err.Error()
		}
		result = append(result, record)
	}
	return result, nil
}

func checkACMEPreflight(ctx context.Context, req ACMERequest) error {
	if req.ChallengeType == ACMEHTTP01 {
		return checkHTTP01Routes(ctx, req.Domains)
	}
	client := newACMEDNSClient()
	for _, domain := range dnsValidationDomains(req.Domains) {
		binding, err := loadDNSBinding(req.DNSServiceURL, domain)
		if err != nil {
			return err
		}
		if err := client.checkCNAME(ctx, binding); err != nil {
			return err
		}
	}
	return nil
}

func (client *acmeDNSClient) present(ctx context.Context, acmeClient *acme.Client, binding acmeDNSBinding, challenge *acme.Challenge) (func(), error) {
	value, err := acmeClient.DNS01ChallengeRecord(challenge.Token)
	if err != nil {
		return nil, err
	}
	var result struct {
		TXT string `json:"txt"`
	}
	if err := client.post(ctx, binding.ServiceURL+"/update", map[string]string{"subdomain": binding.Subdomain, "txt": value}, &binding, http.StatusOK, &result); err != nil {
		return nil, err
	}
	if result.TXT != value {
		return nil, errors.New("acme-dns 未确认验证记录已更新")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	for {
		records, err := client.resolver.LookupTXT(ctx, "_acme-challenge."+binding.Domain+".")
		if err == nil {
			for _, record := range records {
				if record == value {
					// acme-dns keeps its last two TXT values and has no delete API.
					// Do not overwrite the other value: apex + wildcard share a name.
					return func() {}, nil
				}
			}
		}
		timer := time.NewTimer(client.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, fmt.Errorf("%s 的 TXT 验证记录尚未生效：%w；请检查委托解析和 acme-dns 公网 DNS 服务", binding.Domain, ctx.Err())
		case <-timer.C:
		}
	}
}
