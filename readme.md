# NginxMaster【可视化 Nginx 管理面板】

## 简介
- 支持配置: 反向代理, 静态页面, 重定向 等
- 保存自动校验，失败自动回滚，确保 Nginx 服务不中断
- 可以管理 SSL 证书，自动识别证书内容，校验合法性
- 支持 Let's Encrypt HTTP-01 和 CNAME 委托验证签发、一键续签（支持泛域名，无需主 DNS 账户密钥）
- 更多功能开发中

## 登录方式

- 默认连接地址: http://IP:9999
- 默认用户名: admin
- 默认密码: admin9999

## Let's Encrypt 证书

支持两种验证方式，可在申请弹窗中选择。签发使用 Go 后端集成的 ACME 客户端，不需要安装 Certbot/acme.sh；目前提供手动一键续签，没有后台定时自动续签。

### HTTP-01（普通域名）

1. 将域名的 A/AAAA 记录指向部署本面板的服务器，并放通公网 TCP 80。若发布 AAAA 记录，IPv6 也必须能访问验证路径。
2. 在「站点管理」中绑定域名、启用 HTTP 并监听 80 端口，然后保存。升级前创建的站点需要重新保存一次，以生成验证路由；首次申请时可以暂不开启 HTTPS。
3. 在「证书管理」点击「申请 Let's Encrypt」，选择「HTTP-01」，填写名称、邮箱和域名，同意服务条款后申请。多个域名可以换行或用逗号分隔，所有域名都必须能通过 HTTP 验证。
4. 申请成功后，在站点的 HTTPS 配置中选择该证书。之后点击证书列表的「一键续签」即可更新证书并重载 Nginx，证书 ID 和文件路径保持不变，无需重新绑定站点。

HTTP-01 不需要添加验证用 DNS 记录，不支持泛域名（例如 `*.example.com`）。

验证请求使用 `/.well-known/acme-challenge/`，由 Nginx 转发到本机面板端口 9999；面板生成的强制 HTTPS 跳转会为该路径放行。该路径为保留路径，请勿添加冲突的 location；额外配置中的服务器级 `return`、`rewrite` 或访问限制也可能拦截验证，需要自行为验证路径放行。外部 CDN/负载均衡也必须将该路径转发到此实例。

申请前会用 `127.0.0.1:80` 和对应 Host 检查本机验证路由，再由 Let's Encrypt 检查公网可达性。HTTP-01 签发/续签最长等待约 4 分钟。

### CNAME 委托验证（支持泛域名）

本方式使用 DNS-01，但不要求提供主域名 DNS 账户的密钥。面板通过 [acme-dns](https://github.com/acme-dns/acme-dns) 的受限 API 更新专属验证 TXT，主域名只需一次性添加 CNAME。

1. 准备一个自建或可信的 acme-dns 服务。本项目集成其客户端，没有默认公共服务地址。API 必须使用受信任的 HTTPS，并允许 `/register` 注册及 `/update` 更新；自建服务还需要按官方文档设置权威 DNS 委托，并开放公网 TCP/UDP 53。
2. 在申请弹窗选择「CNAME 委托验证」，填写域名（例如 `example.com` 和 `*.example.com`）及 acme-dns 服务的 HTTPS 地址，点击「生成 CNAME 记录」。不需要先创建 HTTP 站点或开放网站 80 端口。
3. 将面板展示的 CNAME 添加到你的 DNS 控制台。面板显示完整记录名称；如果控制台自动补全根域名，只填写相应前缀。例如 `_acme-challenge.example.com` 通常填写 `_acme-challenge`。
4. 等待解析生效，点击「检查解析」。所有记录通过后，填写名称、邮箱，同意服务条款，再点击「申请证书」。后端还会检查 CNAME、更新 TXT 并等待 TXT 生效，然后提交给 Let's Encrypt 验证。
5. 申请成功后，将证书绑定到站点。之后点击「一键续签」，面板会复用验证凭据和 CNAME，无需再次手动添加记录。详情页可查看验证方式及检查 CNAME。

`example.com` 与 `*.example.com` 共用 `_acme-challenge.example.com` 这一条记录；`*.api.example.com` 需要另一条 `_acme-challenge.api.example.com` 记录。`*.example.com` 不覆盖根域名或多级子域名，需要时应将它们单独填写。

重复生成同一服务、同一域名的记录会复用已有绑定。关闭弹窗、签发失败或删除证书不会删除绑定，避免其他证书的续签失效。请保留 CNAME 和验证服务；如果已有同名 TXT/CNAME，需要先确认原证书使用情况，再处理冲突。更换验证服务需要重新配置委托并申请证书。

受限凭据仅能更新专属验证 TXT，不能修改主域名的 A/MX 等记录，但它和委托服务仍具备为被委托域名签发证书的能力。凭据保存在后端 `$NGINX_MASTER_BASE/acme-dns`，权限为 `0600`，不会通过列表、详情或配置接口返回给浏览器。服务不支持 HTTP 重定向，以避免凭据转发到其他地址。

### 续签、部署与备份

续签会保留证书 ID、文件路径、域名、验证方式和测试/生产环境。此前没有验证方式字段的证书按 HTTP-01 处理。

CNAME 委托验证签发/续签最长等待约 10 分钟。如果通过反向代理访问管理面板，请为 `/api/v1/issue_cert`、`/api/v1/renew_cert` 设置至少 `660s` 的 `proxy_read_timeout`；生成和检查 CNAME 的 `/api/v1/prepare_acme_dns`、`/api/v1/check_acme_dns` 建议至少 `90s`。连接中断后先刷新证书列表确认结果，再决定是否重试。

可先勾选「使用测试环境」验证配置，避免调试时消耗生产环境签发额度。测试证书会标记为「测试」，浏览器不信任；正式使用时取消勾选并新建生产证书，重新选择正式证书。

证书和私钥保存在 `$NGINX_MASTER_BASE/certs`，ACME 账户密钥保存在 `$NGINX_MASTER_BASE/acme`，委托验证凭据保存在 `$NGINX_MASTER_BASE/acme-dns`，新写入的敏感文件权限为 `0600`。Docker 部署请持久化并备份整个 `/nginx_master_data` 目录；自建 acme-dns 也需要持久化其数据库。丢失验证凭据后不能仅凭 CNAME 恢复，请优先从备份恢复。

证书替换后先执行 `nginx -t`，再重载；检查或重载命令失败会恢复原文件。证书签发、续签、导入和删除互斥，重复操作会提示稍后再试。

HTTP-01 的端口及泛域名限制见 [Let's Encrypt 官方说明](https://letsencrypt.org/docs/challenge-types/#http-01-challenge)。

### 验证改动

```sh
cd web
pnpm install --frozen-lockfile
pnpm build
# 可选：用本机 Nginx 验证 HTTP-01、HTTPS 跳转、正则 location 和 basic auth 的兼容
NGINX_TEST_BIN=/absolute/path/to/nginx node --test tests/acme-routing.test.mjs
cd ../srv
go test -race ./pkg ./ctl
go build -o build/nginx-master .
```


## docker 安装命令:
```
docker run -d --name nginx-master --net=host --restart always pch18/nginx-master
```
```
docker run -d --name nginx-master -p 9999:9999 -p 443:443 -p 80:80 --restart always pch18/nginx-master
```
支持多架构，amd64, arm64 等，如果缺了某个架构的构建，请提 issue

## 裸机安装命令（前提安装完nginx）
```
curl -fsSL https://raw.githubusercontent.com/pch18/nginxMaster/refs/heads/main/install.debian | sudo bash

wget -qO- https://raw.githubusercontent.com/pch18/nginxMaster/refs/heads/main/install.debian | sudo bash
```


## 构建发布
```
cd web
pnpm i
pnpm build
cd ..
docker buildx create --use
docker buildx build --platform=linux/amd64,linux/arm64 -t pch18/nginx-master . --push
```

## 构建多平台bin
```
cd srv
rm -f build/*
GOOS=linux GOARCH=amd64 go build -o build/app-linux-amd64 main.go
GOOS=linux GOARCH=arm64 go build -o build/app-linux-arm64 main.go
```
