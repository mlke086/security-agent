# asset-pkgs — asset-scan 镜像离线安装包（V13 P3-F）

asset-scan 镜像构建时的"最后兜底"——构建机首选从**内部下载站
192.168.80.101:8011**（与 agent 端 nuclei 二进制/模板同源）或**内网代理**拉取，
如都不可达，COPY 本目录文件离线装。Nuclei/模板版本与项目 agent 端对齐：

- **nuclei 3.11.0**（agent 当前主用版本）
- **nuclei-templates 10.4.6**（同上）

## 文件

| 文件 | 大小 | 用途 |
|------|------|------|
| `nuclei_3.11.0_linux_amd64.zip` | 42MB | nuclei v3.11.0 linux-amd64 二进制 |
| `nuclei-templates-10.4.6.zip` | 18MB | nuclei 模板库，v10.4.6 |
| `nmap.deb` / `masscan.deb` / `libpcap0.8.deb` / `liblinear4.deb` | ~2MB | Debian bookworm 离线包（与 secagent-base 同源） |

## 下载（v3.11.0 / 10.4.6）

```bash
# 内部下载站（项目主用，与 agent 端一致）
curl -fSL -o nuclei_3.11.0_linux_amd64.zip \
  http://192.168.80.101:8011/nuclei_3.11.0_linux_amd64.zip
curl -fSL -o nuclei-templates-10.4.6.zip \
  http://192.168.80.101:8011/nuclei-templates-10.4.6.zip

# .deb（bookworm 池）
curl -fSL -o nmap.deb \
  https://deb.debian.org/debian/pool/main/n/nmap/nmap_7.93+dfsg1-1_amd64.deb
curl -fSL -o masscan.deb \
  https://deb.debian.org/debian/pool/main/m/masscan/masscan_1.3.2+ds1-1_amd64.deb
curl -fSL -o libpcap0.8.deb \
  https://deb.debian.org/debian/pool/main/libp/libpcap/libpcap0.8_1.10.3-1_amd64.deb
curl -fSL -o liblinear4.deb \
  https://deb.debian.org/debian/pool/main/libl/liblinear/liblinear4_2.3.0+dfsg-5_amd64.deb
```

## Dockerfile 集成（V13 P3-F）

`deployments/prod/docker/Dockerfile.asset-scan` 多级 fallback：

1. **首选**: 从 `http://192.168.80.101:8011/` 下载 nuclei + 模板（与 agent 同源）
2. **次选**: 从 GitHub `projectdiscovery/nuclei` releases 下载
3. **最后**: COPY `asset-pkgs/` 离线包

模板预置到 `/opt/secagent/templates`（与 agent 端 `nuclei_templates_update` 路径一致），
`NUCLEI_TEMPLATES` 环境变量指向，`run_nuclei` 显式传 `-t` 参数。
