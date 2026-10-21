# 🛡️ php2shell-alert — PHP 紧急安全公告与在线暴露检测

**Live: <https://php.muran.ai>** · CVE-2026-109618 / CVE-2026-109619 · CVSS v4.0 9.2 (Critical)

一个部署在 Cloudflare Workers 上的双语（中文/English）公告站，说明 2026-10-21
披露的 PHP 核心未授权 RCE 漏洞（php2shell）的影响范围、攻击方式与升级路径，
并提供**被动 + 良性**的在线暴露检测。附带可本地复现的 Docker 靶场与 PoC。

A bilingual (中文/English) advisory site on Cloudflare Workers for the
critical PHP core RCE disclosed 2026-10-21, with a passive + benign online
exposure checker, plus a fully local Docker lab and PoC.

---

## TL;DR / 要点

- 漏洞在 **PHP 运行时本身**，自 5.4.0（2012）起全部受影响；应用代码再干净也没用。
- **唯一完整修复：升级** → 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12（2026-10-21 发布）。PHP ≤8.1 无官方修复（有 7.4/8.0/8.1 源码 backport 分支）。
- 临时缓解（均为部分缓解）：`session.upload_progress.enabled=0`（php.ini/FPM pool 级别，`.user.ini`/`ini_set()` **无效**）、管理级 `memory_limit=-1`、收紧 `post_max_size`、边缘拒绝 multipart。
- 野外攻击已开始（Cloudflare 2026-10-21 07:43 UTC 报告）。

## 在线检测的伦理边界 / Ethics of the checker

我们**绝不**向目标发送任何攻击形状的流量（无 OOM 压力、无 `|` 注入、无序列化载荷、无内存破坏探测）。检测只有两步：

1. 一次普通 `GET /`（读取 `X-Powered-By`、`Set-Cookie: PHPSESSID`、应用指纹）；
2. 一次**良性**小型 multipart 表单提交（等同浏览器上传一个小文件），观察响应是否体现 `session.upload_progress` 代码路径与 WAF 拦截信号。

版本横幅被隐藏时，判定为 `php_version_hidden`（按受影响处理），并引导在服务器上 `php -v` 自查——这是唯一可靠的确认方式。检测有 SSRF 防护（拒绝私有地址/本机/内网）与速率限制。

## 仓库结构 / Layout

```
├── public/            站点静态资源（Apple HIG 风格，中英双语，自适应手机/桌面）
├── src/worker.js      Cloudflare Worker：/api/check（被动+良性检测）+ 静态资源
├── lab/               本地靶场：PHP 8.2.34 (nginx+FPM) + poc_local.py + 验证记录
├── test/local.mjs     Worker 逻辑本地测试（node test/local.mjs）
└── wrangler.jsonc     部署配置（含 php.muran.ai 自定义域名）
```

## 本地复现 / Reproduce locally

```bash
# 1) 起靶场（PHP 8.2.34，漏洞默认配置）
docker build -t cve618-lab lab/
docker run -d --name cve618-lab -p 127.0.0.1:8080:80 cve618-lab
curl http://127.0.0.1:8080/api/app.php   # -> [api] session started

# 2) 打 PoC（仅允许 127.0.0.1）
python3 lab/poc_local.py 127.0.0.1 8080 'id; uname -sr'
# -> [gadget] uid=33(www-data) ...  RCE confirmed

# 3) 验证官方临时缓解有效
docker exec cve618-lab sh -c 'echo "session.upload_progress.enabled=0" > /usr/local/etc/php/conf.d/99-zz-mitig.ini'
docker restart cve618-lab
python3 lab/poc_local.py 127.0.0.1 8080 'id'   # -> exploit fails
```

完整记录与靶场内部原理见 [`lab/VERIFICATION.md`](lab/VERIFICATION.md)。

## 本地测试 / Tests

```bash
node test/local.mjs   # 12 项：版本判定、EOL、隐藏横幅、不可达、SSRF、i18n 完整性
```

## 部署 / Deploy

```bash
npm install -g wrangler
wrangler deploy      # 使用 wrangler.jsonc；自定义域名 php.muran.ai 需账号内已有 muran.ai zone
```

## Credits / 致谢

- 漏洞发现与披露：Calif（Ryan Austin，与 OpenAI 协作）、Wiz Research（Sagi Tzadik 等）、PHP 安全团队
- 公开 PoC 靶场思路：[junaire/CVE-2026-109618-exploit](https://github.com/junaire/CVE-2026-109618-exploit)、[murrez/php2shell](https://github.com/murrez/php2shell)
- 官方资料：[php.net 安全公告](https://www.php.net/archive/2026.php#2026-10-21-5) ·
  [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) ·
  [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) ·
  [Wiz](https://www.wiz.io/blog/php2shell-php-rce) ·
  [Calif](https://calif.io/php2shell/) ·
  [Sansec](https://sansec.io/research/php2shell)

## License

MIT. 本项目仅供防御与授权研究用途；检测仅限自有或已授权资产。
