import {
  Alert,
  Button,
  Checkbox,
  Form,
  Input,
  Modal,
  Notification,
  Popconfirm,
  Select,
  Space,
  Tag,
  Typography,
} from "@arco-design/web-react";
import { useMemo, useState } from "react";
import {
  type ACMEChallengeType,
  type ACMEDelegation,
  type CertConfig,
} from "@/common/interface";
import { makeId } from "@/common/newConfig";
import { request } from "@/utils/request";
import { createNiceModal } from "@/utils/nicemodel";
import dayjs from "dayjs";

export const notifyACMEResult = (err?: string, output?: string) => {
  Notification[err ? "error" : "success"]({
    title: err ? "证书操作失败" : "操作成功，Nginx 已重载",
    content: (
      <div className="whitespace-pre-wrap break-all select-text">
        {[err, output].filter(Boolean).join("\n")}
      </div>
    ),
    duration: err ? 0 : 4000,
    closable: true,
  });
};

export const openACMECertModal = createNiceModal<
  { certConfig?: CertConfig },
  { certConfig?: CertConfig }
>(({ _modal, certConfig }) => {
  const [form] = Form.useForm();
  const [busy, setBusy] = useState(false);
  const [dnsBusy, setDNSBusy] = useState(false);
  const [method, setMethod] = useState<ACMEChallengeType>(
    certConfig?.acme?.challengeType ?? "http-01"
  );
  const [records, setRecords] = useState<ACMEDelegation[]>([]);
  const working = busy || dnsBusy;
  const dnsReady =
    records.length > 0 && records.every((record) => record.verified);
  const id = useMemo(() => certConfig?.id ?? makeId(), []);

  const checkDelegations = async (prepare: boolean) => {
    if (!certConfig) {
      try {
        await form.validate(["domains", "dnsServiceURL"]);
      } catch {
        return;
      }
    }
    const values = form.getFields();
    const serviceURL =
      certConfig?.acme?.dnsServiceURL ??
      String(values.dnsServiceURL ?? "").trim();
    const domains =
      certConfig?.acme?.domains ??
      String(values.domains ?? "")
        .split(/[\s,，]+/)
        .filter(Boolean);
    setDNSBusy(true);
    setRecords([]);
    try {
      const res = await request.ACMEDelegations(serviceURL, domains, prepare);
      if (res.err) notifyACMEResult(res.err);
      else setRecords(res.records ?? []);
    } catch {
      notifyACMEResult(
        "未收到验证记录配置结果，请重试。已保存的记录会自动复用。"
      );
    } finally {
      setDNSBusy(false);
    }
  };

  const issue = async () => {
    try {
      await form.validate();
    } catch {
      return;
    }
    setBusy(true);
    try {
      const values = form.getFields();
      const res = await request.IssueCert({
        id,
        name: values.name.trim(),
        email: values.email.trim(),
        domains: values.domains.split(/[\s,，]+/).filter(Boolean),
        staging: Boolean(values.staging),
        acceptTerms: Boolean(values.acceptTerms),
        challengeType: method,
        dnsServiceURL:
          method === "dns-01" ? String(values.dnsServiceURL).trim() : undefined,
      });
      notifyACMEResult(res.err, res.output);
      if (!res.err && res.certConfig)
        _modal.resolve({ certConfig: res.certConfig });
    } catch {
      // A lost response does not prove issuance failed; refresh before retrying.
      Notification.error({
        title: "未收到签发结果",
        content: "请刷新证书列表确认结果后再重试，避免重复申请。",
        duration: 0,
      });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      {..._modal.props}
      title={certConfig ? "Let's Encrypt 证书详情" : "申请 Let's Encrypt 证书"}
      style={{ width: 680 }}
      maskClosable={false}
      closable={!working}
      escToExit={!working}
      onCancel={() => {
        if (!working) _modal.props.onCancel();
      }}
      footer={
        <Space>
          {certConfig && (
            <Popconfirm
              title="确认删除此证书？"
              onOk={async () => {
                const res = await request.DelCert(id);
                notifyACMEResult(res.err, res.output);
                if (!res.err) _modal.resolve({});
              }}
            >
              <Button status="danger" disabled={working}>
                删除
              </Button>
            </Popconfirm>
          )}
          <Button disabled={working} onClick={_modal.props.onCancel}>
            关闭
          </Button>
          {!certConfig && (
            <Button
              type="primary"
              loading={busy}
              disabled={dnsBusy || (method === "dns-01" && !dnsReady)}
              onClick={issue}
            >
              申请证书
            </Button>
          )}
        </Space>
      }
    >
      <div className="max-h-[65vh] overflow-y-auto">
        <Alert
          type="info"
          className="mb-4"
          content={
            method === "http-01" ? (
              <div>
                <div>
                  使用 HTTP-01 验证，不需要 DNS API。支持多个完整域名，不支持
                  *.example.com 泛域名。
                </div>
                <div>
                  请先将域名指向本机，并在站点管理中绑定域名、启用 HTTP 80
                  后保存。升级前创建的站点也需重新保存一次。
                </div>
                <div>
                  公网 80 端口必须可达；若设置了 AAAA 记录，IPv6
                  也必须能访问同一验证路径。
                </div>
              </div>
            ) : (
              <div>
                <div>
                  使用 CNAME 委托验证，支持泛域名，不需要提供主 DNS
                  账户的密钥，也不要求网站开放 80 端口。
                </div>
                <div>
                  先填写 acme-dns 服务地址并生成记录，再到 DNS 控制台添加一次
                  CNAME。检查通过后即可申请，后续续签复用该记录。
                </div>
                <div>
                  面板保存的受限凭据仅用于更新验证
                  TXT，但可以用于申请被委托域名的证书，请使用自建或可信服务。
                </div>
              </div>
            )
          }
        />
        {certConfig ? (
          <div className="space-y-3 select-text break-all">
            {certConfig.acme?.staging && (
              <Alert
                type="warning"
                content="这是测试环境证书，浏览器不信任。正式使用请重新申请生产环境证书。"
              />
            )}
            <div>名称：{certConfig.name}</div>
            <div>域名：{certConfig.domain}</div>
            <div>账户邮箱：{certConfig.acme?.email}</div>
            <div>
              验证方式：
              {method === "dns-01" ? "CNAME 委托验证（acme-dns）" : "HTTP-01"}
            </div>
            {method === "dns-01" && (
              <>
                <div>验证服务：{certConfig.acme?.dnsServiceURL}</div>
                <Button
                  loading={dnsBusy}
                  onClick={() => checkDelegations(false)}
                >
                  查看并检查 CNAME
                </Button>
                <DelegationRecords records={records} />
              </>
            )}
            <div>
              到期时间：
              {dayjs.unix(certConfig.expiredAt).format("YYYY-MM-DD HH:mm:ss")}
            </div>
            <div>证书路径：{certConfig.pemPath}</div>
            <div>私钥路径：{certConfig.keyPath}</div>
            <div>
              使用列表中的“一键续签”更新证书。续签保留文件路径，所有引用该证书的站点会随重载更新。
            </div>
          </div>
        ) : (
          <Form
            form={form}
            layout="vertical"
            initialValues={{
              staging: false,
              acceptTerms: false,
              challengeType: "http-01",
            }}
            disabled={working}
          >
            <Form.Item field="challengeType" label="验证方式">
              <Select
                onChange={(value: ACMEChallengeType) => {
                  setMethod(value);
                  setRecords([]);
                }}
                options={[
                  { value: "http-01", label: "HTTP-01（普通域名）" },
                  { value: "dns-01", label: "CNAME 委托验证（支持泛域名）" },
                ]}
              />
            </Form.Item>
            <Form.Item
              field="name"
              label="证书名称"
              rules={[{ required: true, message: "请填写名称" }]}
            >
              <Input maxLength={100} placeholder="例如：官网证书" />
            </Form.Item>
            <Form.Item
              field="domains"
              label="域名"
              rules={[{ required: true, message: "请填写域名" }]}
            >
              <Input.TextArea
                onChange={() => setRecords([])}
                rows={3}
                placeholder={
                  method === "dns-01"
                    ? "example.com\n*.example.com\n泛域名不包含根域名，需要时请同时填写"
                    : "example.com\nwww.example.com\n每行一个，或用逗号分隔"
                }
              />
            </Form.Item>
            {method === "dns-01" && (
              <>
                <Form.Item
                  field="dnsServiceURL"
                  label="acme-dns 服务地址"
                  rules={[
                    { required: true, message: "请填写 acme-dns 服务地址" },
                    {
                      validator: (value, callback) => {
                        try {
                          const url = new URL(String(value));
                          if (
                            url.protocol !== "https:" ||
                            url.username ||
                            url.password ||
                            url.search ||
                            url.hash
                          )
                            callback("请填写不含账户密码或参数的 HTTPS 地址");
                        } catch {
                          callback("请填写完整的 HTTPS 地址");
                        }
                      },
                    },
                  ]}
                  extra="首次生成记录会向该服务注册专属验证账户，受限凭据只保存在后端。"
                >
                  <Input
                    onChange={() => setRecords([])}
                    placeholder="https://auth.example.net"
                  />
                </Form.Item>
                <div className="mb-4 space-y-3">
                  <Button
                    loading={dnsBusy}
                    disabled={busy}
                    onClick={() => checkDelegations(records.length === 0)}
                  >
                    {records.length ? "检查解析" : "生成 CNAME 记录"}
                  </Button>
                  <DelegationRecords records={records} />
                  {records.length > 0 && (
                    <Alert
                      type={dnsReady ? "success" : "warning"}
                      content={
                        dnsReady
                          ? "所有 CNAME 已生效，可以申请证书。请长期保留这些记录。"
                          : "请将以上 CNAME 添加到 DNS 控制台，等待生效后点击“检查解析”。若控制台自动补全域名，只需填写记录名称的对应前缀。"
                      }
                    />
                  )}
                </div>
              </>
            )}
            <Form.Item
              field="email"
              label="ACME 账户邮箱"
              rules={[
                { required: true, type: "email", message: "请填写有效的邮箱" },
              ]}
            >
              <Input placeholder="admin@example.com" />
            </Form.Item>
            <Form.Item field="staging" triggerPropName="checked">
              <Checkbox>
                使用测试环境（用于验证配置，证书不受浏览器信任）
              </Checkbox>
            </Form.Item>
            <Form.Item
              field="acceptTerms"
              triggerPropName="checked"
              rules={[
                {
                  validator: (value, callback) => {
                    if (!value) callback("请先同意服务条款");
                  },
                },
              ]}
            >
              <Checkbox>
                我同意{" "}
                <a
                  href="https://letsencrypt.org/repository/"
                  target="_blank"
                  rel="noreferrer"
                  onClick={(e) => e.stopPropagation()}
                >
                  Let’s Encrypt 服务条款
                </a>
              </Checkbox>
            </Form.Item>
          </Form>
        )}
        {busy && (
          <Alert
            type="info"
            content={
              method === "dns-01"
                ? "正在更新验证 TXT 并等待 DNS 生效，最多等待约 10 分钟，请勿关闭页面。"
                : "正在检查验证路径并申请证书，最多等待约 4 分钟，请勿关闭页面。"
            }
          />
        )}
      </div>
    </Modal>
  );
});

function DelegationRecords({ records }: { records: ACMEDelegation[] }) {
  return (
    <div className="space-y-3">
      {records.map((record) => (
        <div
          key={record.name}
          className="border border-solid border-[var(--color-border-2)] rounded p-3 break-all"
        >
          <div className="mb-2">
            <Tag color={record.verified ? "green" : "orange"}>
              {record.verified ? "已生效" : "待配置 / 待生效"}
            </Tag>{" "}
            <span>CNAME</span>
          </div>
          <div>
            记录名称：<Typography.Text copyable>{record.name}</Typography.Text>
          </div>
          <div>
            记录值：<Typography.Text copyable>{record.target}</Typography.Text>
          </div>
          <div className="mt-2 text-[var(--color-text-3)]">
            {record.message}
          </div>
        </div>
      ))}
    </div>
  );
}
