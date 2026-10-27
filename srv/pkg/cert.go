package pkg

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var certFilesMu sync.RWMutex

func ListCert() (list []map[string]any, err error) {
	certFilesMu.RLock()
	defer certFilesMu.RUnlock()
	if err = os.MkdirAll(CertDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create [Cert] directory: %v", err)
	}

	list = []map[string]any{}
	// 读取目录下的所有文件
	files, err := os.ReadDir(CertDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read [Cert] directory: %v", err)
	}

	for _, file := range files {
		// 检查文件是否以 .json 结尾
		if filepath.Ext(file.Name()) == ".json" {
			filePath := filepath.Join(CertDir, file.Name())
			fileData, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}

			// 解析 JSON 文件
			var config map[string]interface{}
			err = json.Unmarshal(fileData, &config)
			if err != nil {
				continue
			}

			// 将解析后的 map 添加到数组中
			list = append(list, config)
		}
	}

	return
}

func PathCert(id string) (certPemPath, certKeyPath, certConfigPath string) {
	certPemPath = fmt.Sprintf("%s/%s.pem", CertDir, id)
	certKeyPath = fmt.Sprintf("%s/%s.key", CertDir, id)
	certConfigPath = fmt.Sprintf("%s/%s.json", CertDir, id)
	return
}

func SaveCert(id string, certConfig any, certPemRaw, certKeyRaw string) (output string, err error) {
	if !IsValidId(id) {
		return "", errors.New("Invalid id")
	}
	if !certMutationMu.TryLock() {
		return "", errors.New("有证书操作正在进行，请完成后再试")
	}
	defer certMutationMu.Unlock()
	if certConfig != nil {
		_, _, path := PathCert(id)
		data, readErr := os.ReadFile(path)
		if readErr != nil && !os.IsNotExist(readErr) {
			return "", readErr
		}
		if readErr == nil {
			var saved struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(data, &saved); err != nil {
				return "", err
			}
			if saved.Type == CertTypeLetsEncrypt {
				return "", errors.New("Let's Encrypt 证书请使用一键续签，不能手动覆盖")
			}
		}
	}
	return saveCert(id, certConfig, certPemRaw, certKeyRaw)
}

func saveCert(id string, certConfig any, certPemRaw, certKeyRaw string) (output string, err error) {
	certFilesMu.Lock()
	defer certFilesMu.Unlock()
	if certConfig != nil {
		if _, err := tls.X509KeyPair([]byte(certPemRaw), []byte(certKeyRaw)); err != nil {
			return "证书或私钥无效", err
		}
	}
	certPemPath, certKeyPath, certConfigPath := PathCert(id)

	certPemBak, certPemBakErr := os.ReadFile(certPemPath)
	certKeyBak, certKeyBakErr := os.ReadFile(certKeyPath)
	certConfigBak, certConfigBakErr := os.ReadFile(certConfigPath)
	for _, readErr := range []error{certPemBakErr, certKeyBakErr, certConfigBakErr} {
		if readErr != nil && !os.IsNotExist(readErr) {
			return "读取原证书失败", readErr
		}
	}

	var done = false
	defer func() {
		if !done {
			for _, backup := range []struct {
				path    string
				data    []byte
				readErr error
			}{
				{certPemPath, certPemBak, certPemBakErr},
				{certKeyPath, certKeyBak, certKeyBakErr},
				{certConfigPath, certConfigBak, certConfigBakErr},
			} {
				var restoreErr error
				if backup.readErr == nil {
					restoreErr = writePrivateFile(backup.path, backup.data)
				} else {
					restoreErr = os.Remove(backup.path)
					if os.IsNotExist(restoreErr) {
						restoreErr = nil
					}
				}
				if restoreErr != nil {
					err = errors.Join(err, fmt.Errorf("恢复证书文件 %s 失败：%w", backup.path, restoreErr))
				}
			}
		}
	}()

	if certConfig != nil {
		var certConfigJSON []byte
		certConfigJSON, err = json.MarshalIndent(certConfig, "", "\t")
		if err != nil {
			output = "marshal certConfig failed"
			return
		}
		err = writePrivateFile(certConfigPath, certConfigJSON)
		if err != nil {
			output = "write certConfigJSON failed, path: " + certConfigPath
			return
		}
		err = writePrivateFile(certPemPath, []byte(certPemRaw))
		if err != nil {
			output = "write certPemRaw failed, path: " + certPemPath
			return
		}
		err = writePrivateFile(certKeyPath, []byte(certKeyRaw))
		if err != nil {
			output = "write certKeyRaw failed, path: " + certKeyPath
			return
		}
	} else {
		err = os.Remove(certConfigPath)
		if err != nil && !os.IsNotExist(err) {
			output = "remove certConfigJSON failed, path: " + certConfigPath
			return
		}
		err = os.Remove(certPemPath)
		if err != nil && !os.IsNotExist(err) {
			output = "remove certPemRaw failed, path: " + certPemPath
			return
		}
		err = os.Remove(certKeyPath)
		if err != nil && !os.IsNotExist(err) {
			output = "remove certKeyRaw failed, path: " + certKeyPath
			return
		}
	}

	output, err = NginxReload()
	if err != nil {
		return
	}

	done = true
	return
}
