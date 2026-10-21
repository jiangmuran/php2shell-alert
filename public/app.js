/* php2shell-alert — i18n + checker UI. No frameworks, no external deps. */
'use strict';

const I18N = {
  zh: {
    nav_check: '检查', nav_impact: '影响范围', nav_how: '原理', nav_fix: '如何升级', nav_faq: 'FAQ',
    hero_badge: 'CRITICAL · CVSS 9.2 ×2 · 2026-10-21',
    hero_h1: 'PHP 内核两个严重漏洞。<br>今天就要升级。',
    hero_sub: 'CVE-2026-109618 与 CVE-2026-109619（php2shell）：未授权远程代码执行，存在于 PHP 运行时本身。自 5.4.0（2012 年）起的每一个版本都受影响，应用代码再干净也无济于事。修复版已于 2026-10-21 14:00 UTC 发布，野外攻击已开始。',
    hero_cta1: '检查我的网站', hero_cta2: '如何升级',
    hero_signal: '🚨 Cloudflare 已于当日 07:43 UTC 报告针对 PHP 站点的攻击 · 大规模利用预计已经开始',
    check_h2: '在线检测：你的站点暴露了吗？',
    check_sub: '输入你的域名。我们只发送一次普通 GET 和一次正常的小型 multipart 表单（等同于浏览器上传一个小文件），绝不发送任何攻击载荷。',
    check_btn: '开始检测',
    check_fineprint: '仅检测你拥有或已获授权的站点。版本横幅被隐藏 ≠ 安全；最可靠的确认方式是在服务器上运行 <code>php -v</code>。',
    selfverify_summary: '⌘ 在服务器上自查（最可靠）',
    selfverify_note: '判定规则：8.2.x&lt;8.2.35、8.3.x&lt;8.3.36、8.4.x&lt;8.4.27、8.5.x&lt;8.5.12 → 受影响；8.1 及更老 → 受影响且无官方修复。',
    impact_h2: '影响范围',
    stat1: '的网站运行 PHP', stat2: '2012 年起全部版本受影响',
    stat3: 'CVSS v4.0 · 两个漏洞同分', stat4: 'FPM · mod_php · CGI · FrankenPHP · LiteSpeed',
    impact_callout: '漏洞在 <strong>PHP 运行时</strong>，不在任何应用里。WordPress、Magento、Laravel 的代码一行不改也会中招；甚至一个只输出 hello world 的 PHP 文件同样暴露。mod_php 风险最高：应用代码尚未运行即可被未授权利用。',
    impact_mem: '另一个变体是 <strong>Heartbleed 式内存泄露</strong>：无需 RCE、无需应用调用 session_start()，攻击者即可通过 PHPSESSID Cookie 读取 worker 进程内存中的密码、令牌、API 密钥。',
    chips_title: '已验证可被未授权 RCE 的应用（示例，非完整清单）：',
    how_h2: '攻击是怎么发生的',
    how_sub: '以下为官方公告层面的说明，不含可武器化的细节。',
    how1_h: '恶意 multipart 请求，在应用代码运行之前',
    how1_p: 'PHP 在请求启动阶段解析 multipart 上传体——此时你的第一行代码还没有执行。精心构造的请求可以在不突破 post_max_size 的前提下耗尽 memory_limit。',
    how2_h: '致命错误中断原生清理',
    how2_p: '内存耗尽触发紧急退出，跳过尚未完成的初始化清理，留下半初始化的内部状态与悬垂指针。请求结束后堆内存被释放，但全局状态仍指向它。',
    how3_h: '下一个请求消费陈旧状态 → RCE',
    how3_p: '同一 worker 处理后续请求时，在正常初始化之前就访问到这些“看起来有效”的陈旧指针——跨请求释放后使用（UAF）→ 以 Web 用户身份执行任意代码，或把进程内存泄进 Cookie。',
    how_note: '这一切发生在应用层之下：<strong>应用日志可能毫无痕迹</strong>。WAF 只能拦截已知攻击形状，无法替代升级。可观测信号：异常 multipart 请求 + 500/内存耗尽错误、异常超长或畸形的 PHPSESSID Cookie、worker 无故重启、PHP 进程拉起 sh/curl 等命令。',
    fix_h2: '如何升级（唯一完整方案）',
    fix_sub: '漏洞在运行时，无法通过修改应用代码修复。立即升级到对应分支的安全版本：',
    fixn82: '2026-12-31 起 EOL，尽快迁往更高分支',
    fix_eol: '运行 <strong>PHP 8.1 及更老版本</strong>？上游不再发布修复。选择：升级到受支持分支；或使用发行版/LTS 厂商的 backport 包；或使用官方提供的 7.4 / 8.0 / 8.1 源码 backport 分支自行构建。注意：Remi 仓库（rpms.remirepo.net）当天没有更新。',
    mit_h3: '一小时内无法升级？临时缓解（均为<strong>部分</strong>缓解）',
    mit1_s: '① 关闭 session.upload_progress 并重启所有 worker',
    mit1_p: '切断已验证的会话利用路径。必须在 php.ini / FPM pool / 服务器配置级别设置——<strong>.user.ini 和 ini_set() 无效</strong>（我们在本地靶场实测：开启即被利用，关闭后同一 exploit 失败）。',
    mit2_s: '② memory_limit = -1（管理级别强制）',
    mit2_p: '移除可被攻击者按需触发的内存上限错误路径。用 php_admin_value 强制，确认没有 pool/目录/应用把有限值改回去。副作用：单请求可耗尽服务器内存，仅作短期措施。',
    mit3_s: '③ 收紧 post_max_size 并在边缘限制 multipart',
    mit3_p: 'post_max_size 调小（无上传需求 8M，需要上传 32M 并保持 upload_max_filesize 更小）；在反代层限制解码后请求体大小、字段数、multipart part 数、头部数与嵌套深度——必须覆盖无 Content-Length 的请求。',
    mit4_s: '④ 必要时直接在 Web 服务器拒绝 multipart',
    mit4_p: '会破坏所有文件上传（媒体库、商品图），仅限极端情况下购买补丁时间：',
    mit5_s: '⑤ 其他可选加固',
    mit5_p: 'PHP 8.5：<code>fatal_error_backtraces=0</code>（阻断已确认的 backtrace 生产者）。FPM：<code>pm.max_requests=1</code>（牺牲性能打断跨请求链）。Cloudflare 用户：WAF 托管规则已对所有计划部署，作为权宜之计。',
    tl_h2: '时间线',
    tl1: 'Stefan Esser 发现首个 PHP memory_limit 远程漏洞，选择不公开 exploit',
    tl2: 'PHP bug #78876：长 multipart 变量导致 OOM 与临时文件残留，未被重视',
    tl3: 'OSTIF / Quarkslab 审计重新发现同一 OOM 问题，可利用性未证明，未修复',
    tl4: 'Calif（与 OpenAI 协作）与 Wiz Research 分别完成未授权 RCE 并报告 PHP',
    tl5: '细节提前泄露；watchTowr 确认远程代码执行真实可行',
    tl6: 'Cloudflare 报告针对 PHP 站点的攻击已出现，随即部署 WAF 规则',
    tl7: 'PHP 发布 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12，各方同步公开细节',
    faq_h2: '常见问题',
    q1: '我的站没用 PHP，需要关心吗？', a1: '不运行 PHP（含内置 PHP 的设备/面板/CMS 托管）则不受影响。注意很多“静态站”背后有 PHP 控制面板或统计脚本。',
    q2: '把 X-Powered-By 关掉是不是就安全了？', a2: '不是。隐藏版本只是让攻击者和检测工具都看不到，漏洞本身原封不动。唯一出路是升级运行时。',
    q3: 'WAF / Cloudflare 能挡住吗？', a3: '能挡已知形状，作为缓冲可以，但公告明确没有完整缓解。origin IP 暴露时 WAF 完全失效。升级才是终点。',
    q4: '检测站会对我的站做什么？', a4: '一次普通 GET，一次正常的小型 multipart 表单提交（等同浏览器上传小文件），仅此而已。不发送任何利用载荷、不施压内存。源码开源可审计。',
    q5: '共享主机 / 不管理服务器怎么办？', a5: '立刻联系主机商要求当天升级。PHP 8.1 及更老的没有官方修复——要求迁移到受支持分支。',
    q6: '怎么确认已被入侵？', a6: '排查：PHP worker 拉起 sh/bash/curl/wget/nc；webroot 新增 webshell；异常 cron/账号；异常超长 PHPSESSID Cookie 与 500/内存错误尖峰；完整指引见官方公告与 GHSA。',
    foot1: '本站为社区防御性公告站，与 PHP 官方 / The PHP Foundation 无关联。信息以 <a href="https://www.php.net/archive/2026.php#2026-10-21-5" target="_blank" rel="noopener">php.net 安全公告</a> 为准。',
    foot2: '检测仅限你拥有或已获授权的资产；除普通 GET 与良性小表单外不发送任何流量。<a href="https://github.com/jiangmuran/php2shell-alert" target="_blank" rel="noopener">源码与本地靶场（GitHub）↗</a> · MIT',
    // dynamic
    checking: '检测中，通常 5–15 秒…',
    err_invalid: '域名无法解析，请检查输入。',
    err_rate: '请求过于频繁，请一分钟后再试。',
    err_network: '检测服务暂时不可用，请稍后重试。',
    v_vulnerable: t => `检测到 PHP ${t.v} —— 受影响版本`,
    v_vulnerable_p: t => `立即升级到 ${t.fixed}（${t.branch} 分支安全版）。在完成升级前，应用下方“临时缓解”。`,
    v_eol: t => `PHP ${t.v} —— 分支已停止维护（EOL）`,
    v_eol_p: '上游不提供官方修复：升级到受支持分支，或向发行版索取 backport 包。',
    v_patched: t => `PHP ${t.v} 已包含修复`,
    v_patched_p: '很好。保持安全更新自动安装，并确认没有其他机器仍运行旧版本。',
    v_ancient: t => `PHP ${t.v} —— 极老版本，严重受影响`,
    v_hidden: '检测到 PHP，但版本被隐藏',
    v_hidden_p: '按受影响处理：X-Powered-By 被关掉不改变漏洞本身。在服务器上运行 php -v 确认实际版本；只要今天没升级，就当它有漏洞。',
    v_nosig: '未发现公开的 PHP 特征',
    v_nosig_p: '这不能证明安全：多数站点会隐藏版本。若该服务器确实运行 PHP，请以 php -v 结果为准。',
    v_unreachable: '无法连接到目标',
    v_unreachable_p: '检查域名拼写、协议与防火墙后重试。',
    waf_cf: '站点位于 Cloudflare 之后（WAF 已对所有计划部署临时拦截规则）。',
    waf_blocked: 'multipart 探测被源站/边缘拒绝（403）——可能已有拦截规则，仍不能替代升级。',
    sig_detected: '检测到的信号',
    copied: '已复制',
  },
  en: {
    nav_check: 'Check', nav_impact: 'Impact', nav_how: 'How it works', nav_fix: 'Update now', nav_faq: 'FAQ',
    hero_badge: 'CRITICAL · CVSS 9.2 ×2 · 2026-10-21',
    hero_h1: 'Two critical holes in PHP itself.<br>Patch today.',
    hero_sub: 'CVE-2026-109618 & CVE-2026-109619 ("php2shell"): unauthenticated remote code execution in the PHP runtime. Every version since 5.4.0 (2012) is affected — clean application code does not help. Fixes shipped 2026-10-21 14:00 UTC. Attacks in the wild have started.',
    hero_cta1: 'Check my site', hero_cta2: 'How to update',
    hero_signal: '🚨 Cloudflare reported attacks against PHP sites at 07:43 UTC · mass exploitation is expected',
    check_h2: 'Is your site exposed?',
    check_sub: 'Enter your domain. We send exactly one plain GET and one tiny, well-formed multipart form (equivalent to a browser uploading a small file). No exploit payload is ever sent.',
    check_btn: 'Run check',
    check_fineprint: 'Check only sites you own or are authorized to test. A hidden version banner ≠ safe; the most reliable confirmation is <code>php -v</code> on the server.',
    selfverify_summary: '⌘ Verify on your server (most reliable)',
    selfverify_note: 'Rule: 8.2.x&lt;8.2.35, 8.3.x&lt;8.3.36, 8.4.x&lt;8.4.27, 8.5.x&lt;8.5.12 → vulnerable; 8.1 and older → vulnerable with no official fix.',
    impact_h2: 'Impact',
    stat1: 'of all websites run PHP', stat2: 'every release since 2012 affected',
    stat3: 'CVSS v4.0 — both CVEs', stat4: 'FPM · mod_php · CGI · FrankenPHP · LiteSpeed',
    impact_callout: 'The flaw is in the <strong>PHP runtime</strong>, not in any application. WordPress, Magento and Laravel are affected with zero lines of their code changed — even a hello-world PHP file is exposed. mod_php is highest risk: exploitable before any application code runs.',
    impact_mem: 'A second variant is a <strong>Heartbleed-style memory disclosure</strong>: without RCE and without the app ever calling session_start(), an attacker can read passwords, tokens and API keys from worker memory via the PHPSESSID cookie.',
    chips_title: 'Pre-auth RCE verified against (examples, not exhaustive):',
    how_h2: 'How the attack works',
    how_sub: 'Advisory-level explanation — no weaponizable detail.',
    how1_h: 'A malicious multipart request, before your code runs',
    how1_p: 'PHP parses multipart bodies during request startup — before your first line executes. A crafted request can exhaust memory_limit without exceeding post_max_size.',
    how2_h: 'A fatal error interrupts native cleanup',
    how2_p: 'Out-of-memory triggers an emergency exit that skips pending initialization cleanup, leaving half-initialized internal state and dangling pointers. The request heap is freed while globals still point into it.',
    how3_h: 'The next request consumes stale state → RCE',
    how3_p: 'A later request on the same worker touches those “valid-looking” stale pointers before normal initialization — a cross-request use-after-free → arbitrary code execution as the web user, or process memory leaked into a cookie.',
    how_note: 'All of this happens below the application layer: <strong>app logs may show nothing</strong>. A WAF only blocks known shapes and is not a substitute for updating. Signals to watch: odd multipart requests + 500s / memory errors, oversized or malformed PHPSESSID cookies, unexplained worker restarts, PHP spawning sh/curl.',
    fix_h2: 'Update PHP (the only complete fix)',
    fix_sub: 'You cannot patch this from application code. Update to your branch’s security release now:',
    fixn82: 'EOL on 2026-12-31 — plan to move up',
    fix_eol: 'Running <strong>PHP 8.1 or older</strong>? Upstream ships no fix. Move to a supported branch, use your distribution/LTS vendor’s backport, or build from the official 7.4 / 8.0 / 8.1 source-backport branches. Note: the Remi repository had no update on release day.',
    mit_h3: 'Can’t patch within the hour? Temporary mitigations (all <strong>partial</strong>)',
    mit1_s: '① Disable session.upload_progress and restart every worker',
    mit1_p: 'Cuts the confirmed session path. Must be set in php.ini / FPM pool / server config — <strong>.user.ini and ini_set() do not work</strong> (verified in our local lab: exploited when on, exploit fails when off).',
    mit2_s: '② memory_limit = -1, enforced administratively',
    mit2_p: 'Removes the attacker-triggerable memory-limit failure. Enforce with php_admin_value and make sure no pool/directory/app restores a finite limit. Side effect: one request can eat all memory — short-term only.',
    mit3_s: '③ Tighten post_max_size and rate-limit multipart at the edge',
    mit3_p: 'Lower post_max_size (8M without uploads; 32M with, keeping upload_max_filesize smaller). At the proxy, cap decoded body size, input fields, multipart parts, headers and nesting depth — including requests without a usable Content-Length.',
    mit4_s: '④ Last resort: reject multipart at the web server',
    mit4_p: 'Breaks all file uploads — only to buy patching time:',
    mit5_s: '⑤ Other hardening',
    mit5_p: 'PHP 8.5: <code>fatal_error_backtraces=0</code> (kills the confirmed backtrace producer). FPM: <code>pm.max_requests=1</code> (trades performance to break the cross-request chain). Cloudflare users: managed WAF rules are on for all plans as a stopgap.',
    tl_h2: 'Timeline',
    tl1: 'Stefan Esser finds the first PHP memory-limit remote vulnerability; exploit never released',
    tl2: 'PHP bug #78876: long multipart variables cause OOM and leftover temp files — dismissed',
    tl3: 'OSTIF / Quarkslab audit redisCOVERS the OOM issue; exploitation unproven, unfixed',
    tl4: 'Calif (with OpenAI) and Wiz Research independently achieve unauthenticated RCE and report to PHP',
    tl5: 'Details leak early; watchTowr confirms working remote code execution',
    tl6: 'Cloudflare reports attacks against PHP sites; deploys WAF rules',
    tl7: 'PHP releases 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12; details become public',
    faq_h2: 'FAQ',
    q1: 'My site doesn’t use PHP. Should I care?', a1: 'If nothing on the box runs PHP (including appliance panels or CMS hosting), you’re not affected. Note many “static” sites still have PHP panels behind them.',
    q2: 'Is hiding X-Powered-By enough?', a2: 'No. Hiding the banner hides it from attackers and scanners alike — the bug is untouched. Updating the runtime is the only fix.',
    q3: 'Will a WAF / Cloudflare stop it?', a3: 'Known shapes are blocked — a useful buffer, but the advisory is explicit there is no complete mitigation. If the origin IP leaks, the WAF is bypassed. Patch.',
    q4: 'What does this checker do to my site?', a4: 'One plain GET and one tiny, well-formed multipart form submit — nothing more. No exploit payload, no memory pressure. Open source, auditable.',
    q5: 'I’m on shared hosting / don’t manage the server.', a5: 'Contact your host and demand the update today. PHP 8.1 and older get no official fix — ask to be moved to a supported branch.',
    q6: 'How do I check for compromise?', a6: 'Hunt for: PHP workers spawning sh/bash/curl/wget/nc, new webshells in webroots, unknown cron jobs/accounts, oversized PHPSESSID cookies, spikes of 500s / memory errors. Full guidance in the official advisory and GHSAs.',
    foot1: 'Independent community advisory site; not affiliated with php.net or The PHP Foundation. The <a href="https://www.php.net/archive/2026.php#2026-10-21-5" target="_blank" rel="noopener">official PHP advisory</a> is authoritative.',
    foot2: 'Check only assets you own or are authorized to test; nothing is sent beyond a plain GET and a benign small form. <a href="https://github.com/jiangmuran/php2shell-alert" target="_blank" rel="noopener">Source & local lab on GitHub ↗</a> · MIT',
    checking: 'Checking — usually 5–15 seconds…',
    err_invalid: 'Could not parse that domain. Check the input.',
    err_rate: 'Too many requests. Try again in a minute.',
    err_network: 'Checker temporarily unavailable. Try again shortly.',
    v_vulnerable: t => `PHP ${t.v} detected — VULNERABLE version`,
    v_vulnerable_p: t => `Update to ${t.fixed} (security release for the ${t.branch} branch) now. Until then, apply the temporary mitigations below.`,
    v_eol: t => `PHP ${t.v} — branch is end-of-life`,
    v_eol_p: 'No official fix exists upstream: move to a supported branch or get a vendor backport.',
    v_patched: t => `PHP ${t.v} contains the fix`,
    v_patched_p: 'Good. Keep security updates automatic, and make sure no other machine still runs an old build.',
    v_ancient: t => `PHP ${t.v} — ancient release, critically exposed`,
    v_hidden: 'PHP detected, version hidden',
    v_hidden_p: 'Treat it as vulnerable: turning off X-Powered-By changes nothing about the bug. Run php -v on the server; if it wasn’t updated today, assume it’s exploitable.',
    v_nosig: 'No public PHP signals found',
    v_nosig_p: 'This is not proof of safety — most sites hide their version. If PHP does run there, trust php -v over any banner.',
    v_unreachable: 'Could not reach the target',
    v_unreachable_p: 'Check the domain, scheme and firewall, then retry.',
    waf_cf: 'Site is behind Cloudflare (WAF stopgap rules deployed for all plans).',
    waf_blocked: 'Multipart probe rejected with 403 (origin/edge) — possible blocking rule, still not a substitute for updating.',
    sig_detected: 'Signals detected',
    copied: 'Copied',
  },
};

let LANG = localStorage.getItem('p2s-lang') || (navigator.language && navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en');
const t = (k) => I18N[LANG][k];

function applyLang() {
  document.documentElement.lang = LANG === 'zh' ? 'zh-CN' : 'en';
  document.querySelectorAll('[data-i18n]').forEach(el => {
    const v = t(el.dataset.i18n);
    if (v !== undefined) el.innerHTML = v;
  });
  const btn = document.getElementById('langToggle');
  if (btn) btn.textContent = LANG === 'zh' ? 'EN' : '中文';
}
document.getElementById('langToggle').addEventListener('click', () => {
  LANG = LANG === 'zh' ? 'en' : 'zh';
  localStorage.setItem('p2s-lang', LANG);
  applyLang();
});

/* ---------- checker ---------- */
const form = document.getElementById('checkForm');
const input = document.getElementById('checkInput');
const statusEl = document.getElementById('checkStatus');
const resultEl = document.getElementById('checkResult');
const btn = document.getElementById('checkBtn');

function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

function renderVerdict(d) {
  const v = d.verdict || {};
  const map = {
    vulnerable: { cls: 'red', icon: '⛔', title: t('v_vulnerable')({ v: v.version || '?', fixed: v.fixedIn || '', branch: v.branch || '' }),
                  text: t('v_vulnerable_p')({ fixed: v.fixedIn || '', branch: v.branch || '' }) },
    vulnerable_eol: { cls: 'red', icon: '⛔', title: t('v_eol')({ v: v.version || '?' }), text: t('v_eol_p') },
    patched: { cls: 'green', icon: '✅', title: t('v_patched')({ v: v.version || '?' }), text: t('v_patched_p') },
    ancient: { cls: 'red', icon: '⛔', title: t('v_ancient')({ v: v.version || '?' }), text: t('v_eol_p') },
    php_version_hidden: { cls: 'amber', icon: '⚠️', title: t('v_hidden'), text: t('v_hidden_p') },
    no_php_signals: { cls: 'amber', icon: 'ℹ️', title: t('v_nosig'), text: t('v_nosig_p') },
    unreachable: { cls: 'amber', icon: '📡', title: t('v_unreachable'), text: t('v_unreachable_p') },
  };
  let m = map[v.status] || map.no_php_signals;
  let html = `<div class="verdict ${m.cls}"><span class="v-icon">${m.icon}</span><div><h3>${esc(m.title)}</h3><p>${esc(m.text)}</p></div></div>`;

  const notes = [];
  if (d.waf && d.waf.cloudflare) notes.push(t('waf_cf'));
  if (d.waf && (d.waf.cloudflareBlockedMultipart || d.waf.multipartBlockedAtOrigin)) notes.push(t('waf_blocked'));
  if (Array.isArray(d.signals) && d.signals.length) {
    html += `<div class="sig-list"><b>${esc(t('sig_detected'))}</b>` + d.signals.map(s =>
      `<div class="sig"><span>•</span><span><b>${esc(s.name)}</b> — ${esc(s.value)}</span></div>`).join('') + `</div>`;
  }
  if (notes.length) html += notes.map(n => `<p class="fineprint">${esc(n)}</p>`).join('');
  resultEl.innerHTML = html;
  resultEl.hidden = false;
}

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const q = input.value.trim();
  if (!q) { input.focus(); return; }
  btn.disabled = true; statusEl.hidden = false; resultEl.hidden = true;
  statusEl.textContent = t('checking');
  try {
    const r = await fetch('/api/check?url=' + encodeURIComponent(q));
    const d = await r.json().catch(() => ({}));
    if (d.error === 'rate_limited') { statusEl.textContent = t('err_rate'); }
    else if (['missing_url', 'invalid_url', 'bad_scheme', 'private_host', 'userinfo_not_allowed'].includes(d.error)) { statusEl.textContent = t('err_invalid'); }
    else if (r.ok) { statusEl.hidden = true; renderVerdict(d); }
    else { statusEl.textContent = t('err_network'); }
  } catch { statusEl.textContent = t('err_network'); }
  btn.disabled = false;
});

/* ---------- copy buttons ---------- */
document.querySelectorAll('[data-copy]').forEach(b => {
  b.addEventListener('click', async () => {
    const old = b.textContent;
    try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = t('copied'); b.classList.add('copied'); }
    catch { /* clipboard blocked */ }
    setTimeout(() => { b.textContent = old; b.classList.remove('copied'); }, 1400);
  });
});

/* ---------- reveal on scroll ---------- */
const io = new IntersectionObserver((entries) => {
  entries.forEach(en => { if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); } });
}, { threshold: 0.08 });
document.querySelectorAll('.section-inner').forEach(el => { el.classList.add('reveal'); io.observe(el); });

applyLang();
