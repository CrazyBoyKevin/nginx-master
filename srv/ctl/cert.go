package ctl

import (
	"net/http"
	"nginx_master/pkg"

	"github.com/gin-gonic/gin"
)

func ListCert(c *gin.Context) {
	var requestBody map[string]interface{}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "Invalid JSON",
		})
		return
	}

	list, err := pkg.ListCert()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"err": "ListCertConfigs Failed",
		})
		return
	}

	full, _ := requestBody["full"].(bool)
	if !full {
		for _, v := range list {
			v["pemRaw"] = ""
			v["keyRaw"] = ""
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"list": list,
	})
}

func SaveCert(c *gin.Context) {
	var requestBody map[string]interface{}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "Invalid JSON",
		})
		return
	}

	var id, pemRaw, keyRaw string
	var ok bool

	id, ok = requestBody["id"].(string)
	if !ok || !pkg.IsValidId(id) {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "Invalid id",
		})
		return
	}
	pemRaw, ok = requestBody["pemRaw"].(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "Invalid pemRaw",
		})
		return
	}
	keyRaw, ok = requestBody["keyRaw"].(string)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "Invalid keyRaw",
		})
		return
	}

	certPemPath, certKeyPath, _ := pkg.PathCert(id)
	requestBody["type"] = "custom"
	delete(requestBody, "acme")
	requestBody["pemPath"] = certPemPath
	requestBody["keyPath"] = certKeyPath

	output, err := pkg.SaveCert(id, requestBody, pemRaw, keyRaw)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"output": output,
			"err":    err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"output":     output,
		"certConfig": requestBody,
	})
}

func DelCert(c *gin.Context) {
	var requestBody map[string]interface{}
	if err := c.ShouldBindJSON(&requestBody); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "Invalid JSON",
		})
		return
	}

	var id string
	var ok bool

	id, ok = requestBody["id"].(string)
	if !ok || !pkg.IsValidId(id) {
		c.JSON(http.StatusBadRequest, gin.H{
			"err": "Invalid id",
		})
		return
	}

	output, err := pkg.SaveCert(id, nil, "", "")

	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"err":    err.Error(),
			"output": output,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"output": output,
	})
}

func IssueCert(c *gin.Context) {
	var req pkg.ACMERequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"err": "Invalid JSON"})
		return
	}
	config, output, err := pkg.IssueACMECert(c.Request.Context(), req, false)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"err": err.Error(), "output": output})
		return
	}
	c.JSON(http.StatusOK, gin.H{"certConfig": config, "output": output})
}

func RenewCert(c *gin.Context) {
	var req struct {
		ID string `json:"id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"err": "Invalid JSON"})
		return
	}
	config, output, err := pkg.IssueACMECert(c.Request.Context(), pkg.ACMERequest{ID: req.ID}, true)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"err": err.Error(), "output": output})
		return
	}
	c.JSON(http.StatusOK, gin.H{"certConfig": config, "output": output})
}

func PrepareACMEDNS(c *gin.Context) { acmeDNSRecords(c, true) }
func CheckACMEDNS(c *gin.Context)   { acmeDNSRecords(c, false) }

func acmeDNSRecords(c *gin.Context, prepare bool) {
	var req struct {
		DNSServiceURL string   `json:"dnsServiceURL"`
		Domains       []string `json:"domains"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"err": "Invalid JSON"})
		return
	}
	records, err := pkg.ACMEDelegations(c.Request.Context(), req.DNSServiceURL, req.Domains, prepare)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"err": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"records": records})
}
