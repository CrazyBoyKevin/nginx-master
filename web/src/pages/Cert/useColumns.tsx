import { Button, Tag, type TableColumnProps } from "@arco-design/web-react";
import { CertType, type CertConfig } from "@/common/interface";
import { AsyncButton } from "@/components/AsyncButton";
import { request } from "@/utils/request";
import { notifyACMEResult, openACMECertModal } from "./openACMECertModal";
import { openCertModal } from "./openCertModal";
import dayjs from "dayjs";
import { CertExpireTag } from "@/common/CertTitle";
import { pickCN } from "@/utils/parseCert";

export const useColumns = (
  mutate: (fn: (s?: CertConfig[]) => CertConfig[] | undefined) => void
): TableColumnProps[] => [
  {
    title: "#",
    dataIndex: "id",
    width: 125,
  },
  {
    title: "名称",
    dataIndex: "name",
    width: 100,
  },
  {
    title: "类型",
    dataIndex: "type",
    width: 160,
    render(_, s: CertConfig) {
      return s.type === CertType.LetsEncrypt ? (
        <span>
          Let's Encrypt {s.acme?.staging && <Tag color="orange">测试</Tag>}
        </span>
      ) : (
        "手动上传"
      );
    },
  },
  {
    title: "验证方式",
    width: 140,
    render(_, s: CertConfig) {
      return s.type === CertType.LetsEncrypt
        ? s.acme?.challengeType === "dns-01"
          ? "CNAME 委托验证"
          : "HTTP-01"
        : "—";
    },
  },
  {
    title: "域名",
    dataIndex: "domain",
    width: 150,
  },
  {
    title: "颁发者",
    dataIndex: "issuer",
    width: 150,
    render(col: string) {
      return pickCN(col);
    },
  },
  {
    title: "有效期至",
    dataIndex: "expiredAt",
    width: 150,
    render(col: number) {
      return (
        <div>
          <span>{dayjs.unix(col).format("YYYY-MM-DD")}</span>
          <CertExpireTag className="ml-2" expiredAt={col} />
        </div>
      );
    },
  },
  {
    title: "操作",
    width: 200,
    dataIndex: "cmd",
    render(_, s: CertConfig) {
      return (
        <div className="flex gap-2 items-center select-none">
          <Button
            onClick={() => {
              const modal =
                s.type === CertType.LetsEncrypt
                  ? openACMECertModal({ certConfig: s })
                  : openCertModal({ certConfig: s, title: "编辑证书" });
              void modal
                .then(({ certConfig }) => {
                  if (certConfig) {
                    mutate((s1) =>
                      s1?.map((s2) => (s2.id === s.id ? certConfig : s2))
                    );
                  } else {
                    mutate((s1) => s1?.filter((s2) => s2.id !== s.id));
                  }
                })
                .catch(() => {});
            }}
          >
            {s.type === CertType.LetsEncrypt ? "详情" : "编辑"}
          </Button>
          {s.type === CertType.LetsEncrypt && (
            <AsyncButton
              type="primary"
              onClick={async () => {
                try {
                  const res = await request.RenewCert(s.id);
                  notifyACMEResult(res.err, res.output);
                  if (!res.err && res.certConfig)
                    mutate((list) =>
                      list?.map((item) =>
                        item.id === s.id ? res.certConfig! : item
                      )
                    );
                } catch {
                  notifyACMEResult(
                    "未收到续签结果，请刷新证书列表确认后再重试。"
                  );
                }
              }}
            >
              一键续签
            </AsyncButton>
          )}
        </div>
      );
    },
  },
];
