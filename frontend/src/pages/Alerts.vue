<template>
  <div class="card">
    <div class="card-inner head">
      <div>
        <div class="h1">告警中心</div>
        <div class="sub">HTTP 拉取（/alerts） + WS 推送（/ws/alerts）</div>
      </div>

      <div class="actions">
        <button class="btn" @click="refresh">刷新</button>
        <span class="pill">
          <span class="dot" :class="store.wsAlerts"></span>
          <span>WS {{ wsText(store.wsAlerts) }}</span>
        </span>
      </div>
    </div>

    <div class="card-inner">
      <div class="grid">
        <div class="mini-card">
          <div class="k">总告警</div>
          <div class="v">{{ store.alerts.length }}</div>
        </div>
        <div class="mini-card">
          <div class="k">高危</div>
          <div class="v red">{{ highCount }}</div>
        </div>
        <div class="mini-card">
          <div class="k">最新 ID</div>
          <div class="v mono">{{ newestId }}</div>
        </div>
      </div>

      <div class="table-wrap">
        <table class="table">
          <thead>
          <tr>
            <th style="width:80px;">ID</th>
            <th style="width:190px;">时间</th>
            <th style="width:160px;">类型</th>
            <th style="width:110px;">等级</th>
            <th style="width:160px;">攻击IP</th>
            <th style="width:140px;">目标主机</th>
            <th style="width:90px;">次数</th>
            <th style="width:90px;">窗口(s)</th>
            <th>证据</th>
          </tr>
          </thead>

          <tbody>
          <tr v-for="a in store.alerts" :key="a.id" class="row">
            <td class="mono">{{ a.id }}</td>
            <td class="mono muted">{{ fmt(a.created_at) }}</td>

            <td class="mono">{{ typeToCN(a.alert_type) }}</td>

            <td>
              <span class="badge" :class="sevClass(a.severity)">
                {{ sevToCN(a.severity) }}
              </span>
            </td>

            <td class="mono">{{ a.attack_ip }}</td>
            <td class="mono">{{ displayTargetHost(a) }}</td>
            <td class="mono">{{ a.count }}</td>
            <td class="mono">{{ a.window_seconds }}</td>
            <td>
              <button class="btn mini-btn" @click="openEvidence(a)">查看</button>
            </td>
          </tr>
          </tbody>
        </table>

        <div v-if="store.alerts.length === 0" class="empty">
          暂无告警（你可以运行 replay_ssh_failed.py 触发）
        </div>
      </div>
    </div>
  </div>

  <!-- Evidence Modal -->
  <div v-if="modal.open" class="modal-mask" @click.self="modal.open = false">
    <div class="modal">
      <div class="modal-head">
        <div class="modal-title">证据详情 · 告警 #{{ modal.alertId }}</div>

        <div class="modal-actions">
          <button class="btn ghost" @click="modal.showRaw = !modal.showRaw">
            {{ modal.showRaw ? "隐藏原始JSON" : "查看原始JSON" }}
          </button>
          <button class="btn" @click="openConsole">打开控制台</button>
          <button class="btn" @click="copyEvidence">复制</button>
        </div>
      </div>

      <div class="modal-body">
        <!-- ✅ 一眼看懂（产品级） -->
        <div class="summary card-lite">
          <div class="summary-title">一眼看懂</div>
          <div class="summary-grid">
            <div class="kv">
              <div class="k">攻击类型</div>
              <div class="v mono">{{ modal.summary.typeText }}</div>
            </div>
            <div class="kv">
              <div class="k">攻击源 IP</div>
              <div class="v mono">{{ modal.summary.attackIp || "-" }}</div>
            </div>
            <div class="kv">
              <div class="k">目标主机</div>
              <div class="v mono">{{ modal.summary.host || "-" }}</div>
            </div>
            <div class="kv">
              <div class="k">目标资产</div>
              <div class="v mono muted">{{ modal.summary.internalHost || "-" }}</div>
            </div>
            <div class="kv">
              <div class="k">尝试次数</div>
              <div class="v mono">{{ modal.summary.countText }}</div>
            </div>
            <div class="kv">
              <div class="k">攻击账号</div>
              <div class="v mono">{{ modal.summary.user || "-" }}</div>
            </div>
            <div class="kv">
              <div class="k">端口</div>
              <div class="v mono">{{ modal.summary.port || "-" }}</div>
            </div>

            <!-- ✅ 必须：完整目标 URL 列表 -->
            <div class="kv wide">
              <div class="k">涉及目标 URL</div>
              <div class="v">
                <!-- ✅ 新版：结构化 target_urls（带语义 + 是否存在） -->
                <div v-if="modal.summary.targetUrls && modal.summary.targetUrls.length" class="targets2">
                  <div v-for="(t, i) in visibleTargetUrls" :key="i" class="trow" :class="trowClass(t)">
                  <div class="line1">
                      <span class="mono path">{{ t.path || t.url }}</span>
                      <span v-if="t.tag" class="pill-tag">{{ t.tag }}</span>

                      <span class="pill-exist" :class="existsClass(t.exists)">
        {{ existsText(t.exists) }}
      </span>

                    <span v-if="t.status !== null && t.status !== undefined" class="pill-status" :class="statusClass(t.status)">
  {{ statusText(t.status) }}
</span>
                    </div>

                    <div class="line2 mono muted" v-if="t.url">
                      {{ t.url }}
                    </div>
                  </div>
                </div>

                <!-- ✅ targets 折叠 / 展开 -->
                <div
                  v-if="hiddenTargetCount > 0 || ui.targetsExpanded"
                  class="targets-toggle"
                >
                  <button
                    class="btn ghost mini-toggle"
                    @click="ui.targetsExpanded = !ui.targetsExpanded"
                  >
                    {{ ui.targetsExpanded ? "收起" : `展开全部（+${hiddenTargetCount}）` }}
                  </button>
                </div>

                <!-- ✅ 兼容旧版：只有 targets:string[] -->
                <div v-else-if="modal.summary.targets.length" class="targets">
                  <ul class="targets">
                    <li v-for="(u, i) in modal.summary.targets" :key="i">
                      <span class="mono url">{{ u }}</span>
                    </li>
                  </ul>
                </div>

                <div v-else class="muted">
                  -（当前证据未提供 targets/target_urls，检查后端 alert_builder.py 是否已输出 assessment.targets/assessment.target_urls）
                </div>
              </div>
            </div>

            <div class="kv wide">
              <div class="k">描述</div>
              <div class="v">
                {{ (modal as any).human || modal.summary.desc }}
              </div>
            </div>
          </div>
        </div>

        <div class="card-lite">
          <div class="section-title">处置建议</div>

          <div v-if="modal.recommendations.length === 0" class="empty small">
            暂无处置建议（rule_advice / recommendations_cn 为空）
          </div>

          <ul v-else class="advice">
            <li v-for="(r, i) in modal.recommendations" :key="i">
              {{ r }}
            </li>
          </ul>
        </div>

        <div class="card-lite">
          <div class="section-title">证据列表（最近 {{ modal.items.length }} 条）</div>

          <div v-if="modal.items.length === 0" class="empty small">
            没有可解析的证据内容（evidence 不是 JSON 或为空）
          </div>

          <table v-else class="table ev-table">
            <thead>
            <tr>
              <th style="width:190px;">时间</th>
              <th style="width:160px;">攻击IP</th>
              <th style="width:120px;">用户</th>
              <th style="width:90px;">端口</th>
              <th>原始日志</th>
            </tr>
            </thead>
            <tbody>
            <tr v-for="(it, idx) in modal.items" :key="idx" class="row">
              <td class="mono muted">{{ fmtTs(it.ts) }}</td>
              <td class="mono">{{ it.attack_ip || it.ip || "-" }}</td>
              <td class="mono">{{ showUser(it) }}</td>
              <td class="mono">{{ showPort(it) }}</td>
              <td class="mono wrap">{{ it.raw || "-" }}</td>
            </tr>
            </tbody>
          </table>
        </div>

        <div v-if="modal.showRaw" class="card-lite">
          <div class="section-title">原始 JSON</div>
          <pre class="mono pre">{{ modal.pretty }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive } from "vue";
import { useRouter } from "vue-router";
import { http } from "@/api/http";
import { idsStore as store } from "@/store/ids";
import type { AlertRow } from "@/types/ids";

const router = useRouter();

// 你当前已验证可用的 noVNC 地址（先写死，后面第 3 步再做资产映射）
//const NOVNC_URL = "http://8.141.7.186/novnc/vnc.html?path=novnc/websockify";
const NOVNC_URL = "https://novnc.zmqzmq.cn/vnc.html?path=websockify&autoconnect=1&resize=scale";

function openConsole() {
  router.push({
    path: "/console",
    query: {
      url: NOVNC_URL,
      alertId: String(modal.alertId), // 可选：方便你以后在控制台页显示“来自哪条告警”
    },
  });
}
function wsText(s: string) {
  if (s === "connected") return "已连接";
  if (s === "connecting") return "连接中";
  return "未连接";
}
function fmt(t: string) {
  return (t || "").replace("T", " ").replace("Z", "");
}
function sevClass(sv: string) {
  const v = (sv || "").toUpperCase();
  if (v.includes("CRIT")) return "badge-high";
  if (v.includes("HIGH")) return "badge-high";
  if (v.includes("MED")) return "badge-medium";
  return "badge-low";
}
function sevToCN(sv: string) {
  const v = (sv || "").toUpperCase();
  if (v.includes("CRIT")) return "严重";
  if (v.includes("HIGH")) return "高危";
  if (v.includes("MED")) return "中危";
  if (v.includes("LOW")) return "低危";
  return sv || "未知";
}

const ALERT_TYPE_CN: Record<string, string> = {
  SSH_BRUTEFORCE: "SSH 爆破",
  SSH_BRUTE_FORCE: "SSH 爆破",
  SSH_PASSWORD_SPRAY: "SSH 密码喷洒",
  SSH_FAIL_TO_SUCCESS: "爆破后成功登录",
  HTTP_PATH_BRUTEFORCE: "Web 敏感路径扫描",
  HTTP_SCAN: "Web 扫描行为",
  HTTP_ADMIN_SCAN: "后台入口探测",
};

function stripRulePrefix(t: string) {
  const raw = (t || "").trim();
  const up = raw.toUpperCase();
  if (up.startsWith("RULE::")) return { isRule: true, key: raw.slice(6) };
  return { isRule: false, key: raw };
}

function typeToCN(t: string) {
  const { isRule, key } = stripRulePrefix(t);
  const k = (key || "").toUpperCase();
  const cn = ALERT_TYPE_CN[k] || key || "未知";
  return isRule ? `规则·${cn}` : cn;
}

function alertTime(a: AlertRow): number {
  const s = (a as any)?.created_at;
  if (!s) return 0;
  const t = Date.parse(String(s));
  return Number.isFinite(t) ? t : 0;
}
function sortAlertsInPlace() {
  store.alerts.sort((a, b) => alertTime(b) - alertTime(a));
  if (store.alerts.length > store.alertsMax) store.alerts.length = store.alertsMax;
}

const highCount = computed(
  () =>
    store.alerts.filter(
      (x) =>
        (x.severity || "").toUpperCase().includes("HIGH") ||
        (x.severity || "").toUpperCase().includes("CRIT")
    ).length
);
const newestId = computed(() => store.alerts[0]?.id ?? "-");

async function refresh() {
  const res = await http.get("/alerts", { params: { limit: 50 } });
  const rows = (res.data || []) as AlertRow[];
  for (const a of rows) store.pushAlert(a);
  sortAlertsInPlace();
}

type EvidenceItem = {
  ts?: number | string;
  attack_ip?: string;
  ip?: string;
  host?: string;
  user?: string;
  port?: string | number;
  source?: string;
  raw?: string;
  id?: string;
  [k: string]: any;
};

type TargetUrl = {
  url: string;
  path?: string;
  tag?: string;
  exists?: boolean | null;
  status?: number | null;
  note?: string;
};

const modal = reactive({
  open: false,
  alertId: 0,
  pretty: "",
  showRaw: false,
  items: [] as EvidenceItem[],
  recommendations: [] as string[],
  human: "",
  summary: {
    typeText: "",
    attackIp: "",
    host: "",
    internalHost: "",
    user: "",
    port: "",
    countText: "",
    desc: "",
    targets: [] as string[],
    targetUrls: [] as TargetUrl[],
  },
});

// ✅ targets 折叠：默认最多展示 8 条
const TARGETS_PREVIEW_LIMIT = 2;

const ui = reactive({
  targetsExpanded: false,
});

const visibleTargetUrls = computed(() => {
  const arr = modal.summary.targetUrls || [];
  if (ui.targetsExpanded) return arr;
  return arr.slice(0, TARGETS_PREVIEW_LIMIT);
});

const hiddenTargetCount = computed(() => {
  const n = (modal.summary.targetUrls || []).length - (visibleTargetUrls.value || []).length;
  return n > 0 ? n : 0;
});

function isSshAlert(a: AlertRow, ev?: any) {
  const t = String(a?.alert_type || "").toUpperCase();
  if (t.includes("SSH")) return true;
  const ls = String(ev?.log_source || "").toLowerCase();
  return ls === "ssh";
}

function inferPublicHost(a: AlertRow, ev?: any): string {
  // ✅ 1) evidence.asset.public_host（最权威）
  const ph = ev?.asset?.public_host;
  if (typeof ph === "string" && ph.trim()) return ph.trim();

  // ✅ 2) HTTP/WEB 才允许用 a.host 当公网域名；SSH 禁止（否则就会出现 ssh://zmqzmq.cn:22）
  if (!isSshAlert(a, ev)) {
    const h = (a as any)?.host;
    if (typeof h === "string" && h.trim()) return h.trim();
  }

  // ✅ 3) 兜底：如果 targets 里有完整URL，解析 host（主要服务于 HTTP）
  const targets = ev?.assessment?.targets || ev?.targets || [];
  if (Array.isArray(targets) && targets.length) {
    try {
      const u = new URL(String(targets[0]));
      return u.host || u.hostname || "";
    } catch {}
  }

  return "";
}

function inferInternalHost(a: AlertRow, ev?: any, items?: EvidenceItem[]): string {
  // 1) 最权威：evidence.asset.internal_host
  const ih = ev?.asset?.internal_host;
  if (typeof ih === "string" && ih.trim()) return ih.trim();

  // 2) 其次：evidence.internal_host
  const ih2 = ev?.internal_host;
  if (typeof ih2 === "string" && ih2.trim()) return ih2.trim();

  // ✅ 3) SSH 规则聚合后常见：evidence.host = "server2"
  const ih3 = ev?.host;
  if (typeof ih3 === "string" && ih3.trim()) return ih3.trim();

  // 4) 再兜底：events[0].host
  if (Array.isArray(items) && items.length) {
    const h4 = (items[0] as any)?.host;
    if (typeof h4 === "string" && h4.trim()) return h4.trim();
  }

  // 5) 最后：a.host 只有在“看起来像内部名”时才当 internal（不含点更像 server2/web-01）
  const rawHost = String((a as any)?.host || "").trim();
  if (rawHost && !rawHost.includes(".")) return rawHost;

  return "";
}

function displayTargetHost(a: AlertRow): string {
  const ev = normalizeEvidence((a as any).evidence);
  const items = pickEvidenceItems(ev);

  const pub = inferPublicHost(a, ev);                 // HTTP: zmqzmq.cn
  const internal = inferInternalHost(a, ev, items);   // SSH: server2 / web-01

  const ssh = isSshAlert(a, ev);

  if (ssh) {
    // ✅ SSH：主显示资产主机（server2），括号可选显示对外标识（如果你后端真的给了 public_host）
    const main = internal || pub || "-";
    const sub = internal && pub && pub !== internal ? pub : "";
    return sub ? `${main} (${sub})` : main;
  }

  // ✅ HTTP：主显示域名（站点），括号显示内部资产（web-01）可选
  const main = pub || internal || "-";
  const sub = internal && pub && internal !== pub ? internal : "";
  return sub ? `${main} (${sub})` : main;
}

function normalizeEvidence(e: any) {
  try {
    if (typeof e === "string") return JSON.parse(e);
  } catch {}
  return e;
}
function toArrayEvidence(ev: any): EvidenceItem[] {
  if (!ev) return [];
  if (Array.isArray(ev)) return ev as EvidenceItem[];
  if (typeof ev === "object") return [ev as EvidenceItem];
  return [];
}
function pickEvidenceItems(ev: any): EvidenceItem[] {
  if (!ev) return [];
  if (typeof ev === "object" && !Array.isArray(ev)) {
    if (Array.isArray((ev as any).events)) return (ev as any).events as EvidenceItem[];
  }
  return toArrayEvidence(ev);
}

function splitAdviceText(s: string): string[] {
  const text = (s || "").trim();
  if (!text) return [];
  const parts = text
    .split(/\r?\n|；|;/g)
    .map((x) => x.trim())
    .filter(Boolean);

  const flat: string[] = [];
  for (const p of parts) {
    const sub = p.split(/^\d+[.)、]\s*/).filter(Boolean);
    if (sub.length > 0) {
      if (sub.length === 1 && sub[0] === p) flat.push(p);
      else sub.map((x) => x.trim()).filter(Boolean).forEach((x) => flat.push(x));
    } else {
      flat.push(p);
    }
  }
  return flat.length ? flat : [text];
}

function pickRecommendations(ev: any, a: AlertRow): string[] {
  if (ev && typeof ev === "object" && !Array.isArray(ev)) {
    const r = (ev as any).recommendations_cn;
    if (Array.isArray(r)) return r.map((x: any) => String(x));
  }

  if (ev && typeof ev === "object" && !Array.isArray(ev)) {
    const advice = (ev as any).rule_advice;
    if (typeof advice === "string" && advice.trim()) return splitAdviceText(advice);
    if (Array.isArray(advice)) return advice.map((x: any) => String(x));
  }

  const rawType = (a.alert_type || "").toUpperCase();
  if (rawType.startsWith("RULE::")) {
    return [
      "该告警来自规则引擎，但规则未提供 rule_advice。",
      "建议在对应规则 yml 中补充 advice 字段（人话处置建议），前端会优先展示它。",
    ];
  }

  const type = rawType;
  const ip = a.attack_ip || "";
  const host = a.host || "";
  const port = "22";

  if (type.includes("SSH_BRUTEFORCE") || type.includes("SSH_BRUTE_FORCE")) {
    return [
      `建议临时封禁攻击 IP：${ip || "（未知）"}（防火墙 / 安全组 / fail2ban）`,
      `检查目标主机 ${host || "（未知）"} 是否存在弱口令账户（如 root/admin/test），必要时强制改密`,
      `建议关闭 SSH 密码登录，启用密钥认证（PasswordAuthentication no）`,
      `限制 ${port} 端口访问来源（仅允许运维出口 IP），或改为非默认端口并配合 VPN/MFA`,
      `回溯同时间段日志：是否存在同源 IP 的横向尝试/扫描行为`,
    ];
  }

  return [
    "建议确认告警是否为误报：结合源 IP、时间段、业务访问特征进行判断",
    "对同源 IP 的后续请求进行限速/封禁，并加强审计留痕",
    "根据告警类型检查对应服务配置与补丁状态，必要时进行加固",
  ];
}

function fmtTs(ts: any) {
  if (ts === null || ts === undefined || ts === "") return "-";
  const n = Number(ts);
  if (!Number.isFinite(n)) return String(ts);
  const ms = n > 1e12 ? n : n * 1000;
  const d = new Date(ms);
  const pad = (x: number) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(
    d.getHours()
  )}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function inferPort(items: EvidenceItem[], fallbackRaw?: string): string {
  for (const it of items) {
    const p = (it as any)?.port;
    if (p !== null && p !== undefined && String(p).trim() !== "" && String(p) !== "null") {
      return String(p);
    }

    const raw = (it as any)?.raw;
    if (typeof raw === "string") {
      const m = raw.match(/\bport\s+(\d+)\b/i);
      if (m && m[1]) return m[1];
    }
  }

  if (typeof fallbackRaw === "string") {
    const m = fallbackRaw.match(/\bport\s+(\d+)\b/i);
    if (m && m[1]) return m[1];
  }

  return "";
}

function showPort(it: EvidenceItem): string {
  // 1) 证据里本来就有 port
  const p = (it as any)?.port;
  if (p !== null && p !== undefined && String(p).trim() && String(p) !== "null") {
    return String(p);
  }

  // 2) 从 raw 里抠 "port 22"
  const raw = String((it as any)?.raw || "");
  const m = raw.match(/\bport\s+(\d+)\b/i);
  if (m && m[1]) return m[1];

  return "-";
}

function showUser(it: EvidenceItem): string {
  // 1) 证据里本来就有 user
  const u = (it as any)?.user;
  if (typeof u === "string" && u.trim()) return u.trim();

  // 2) 从 raw 里抠 ssh 用户（兼容几种常见格式）
  const raw = String((it as any)?.raw || "");

  // Failed password for invalid user root from ...
  let m = raw.match(/\binvalid user\s+([^\s]+)\b/i);
  if (m && m[1]) return m[1];

  // Failed password for root from ...
  m = raw.match(/\bFailed password for\s+([^\s]+)\s+from\b/i);
  if (m && m[1]) return m[1];

  // Invalid user root from ...
  m = raw.match(/\bInvalid user\s+([^\s]+)\s+from\b/i);
  if (m && m[1]) return m[1];

  return "-";
}

function existsText(v: any): string {
  if (v === true) return "存在";
  if (v === false) return "不存在";
  return "未知";
}

function existsClass(v: any): string {
  if (v === true) return "exist-yes";
  if (v === false) return "exist-no";
  return "exist-unk";
}

function trowClass(t: TargetUrl) {
  const s = Number((t as any)?.status);
  const hasStatus = Number.isFinite(s);

  // ✅ 只基于后端字段高亮，不做任何推断
  if (t.exists === true) {
    // 200/301/302/401/403/… 都算“存在” -> 绿色底
    return "trow-exists";
  }

  // ✅ 服务端异常更显眼（红）
  if (hasStatus && s >= 500) return "trow-bad";

  // ✅ 需要认证 / 禁止访问：常见后台入口（黄）
  if (hasStatus && (s === 401 || s === 403)) return "trow-warn";

  // ✅ 404 / 不存在：不做任何行级样式（避免“越加越怪”）
  return "";
}

function statusText(s: any): string {
  const n = Number(s);
  if (!Number.isFinite(n)) return "";
  if (n === 200) return "200 OK";
  if (n === 301 || n === 302) return String(n) + " 重定向";
  if (n === 401) return "401 需认证";
  if (n === 403) return "403 禁止访问";
  if (n === 404) return "404 未找到";
  if (n >= 500) return String(n) + " 服务异常";
  return String(n);
}

function statusClass(s: any): string {
  const n = Number(s);
  if (!Number.isFinite(n)) return "";

  if (n >= 500) return "st-bad";          // 5xx 红
  if (n === 401 || n === 403) return "st-warn"; // 401/403 黄
  if (n === 404) return "st-miss";        // 404 灰
  if (n === 301 || n === 302) return "st-move"; // 30x 蓝
  if (n >= 200 && n < 300) return "st-ok";      // 2xx 绿
  return "";
}

function shortPathFromUrl(u: string): string {
  try {
    const x = new URL(u);
    return x.pathname || "/";
  } catch {
    return "/";
  }
}

function pickTargets(ev: any, a?: AlertRow): string[] {
  const t = String(a?.alert_type || "").toUpperCase();
  const items = pickEvidenceItems(ev);

  // ✅ HTTP：优先后端给的 assessment.targets（你图里 /admin /login 那种）
  if (!t.includes("SSH")) {
    const targets = ev?.assessment?.targets;
    if (Array.isArray(targets) && targets.length) {
      return targets.map((x: any) => String(x)).filter(Boolean);
    }

    // 没有 targets 的老数据：用 host 兜一个根 URL
    const host = a ? (inferPublicHost(a, ev) || inferInternalHost(a, ev, items) || "unknown") : "unknown";
    return [`http://${host}/`];
  }

  // ✅ SSH：永远用资产主机 + 端口（server2:22），不要用域名
  const host = a ? (inferInternalHost(a, ev, items) || "unknown") : "unknown";
  const port = String(ev?.port || (a as any)?.port || inferPort(items, (items[0] as any)?.raw) || 22);
  return [`ssh://${host}:${port}`];
}

function pickTargetUrls(ev: any): TargetUrl[] {
  const arr = ev?.assessment?.target_urls || ev?.assessment?.targetUrls || [];
  if (!Array.isArray(arr) || arr.length === 0) return [];

  const out: TargetUrl[] = [];
  for (const it of arr) {
    if (it && typeof it === "object") {
      const url = String((it as any).url || "").trim();
      if (!url) continue;
      out.push({
        url,
        path: String((it as any).path || "").trim() || shortPathFromUrl(url),
        tag: String((it as any).tag || "").trim(),
        exists: (it as any).exists,
        status: (it as any).status,
        note: String((it as any).note || "").trim(),
      });
    } else if (typeof it === "string") {
      const url = it.trim();
      if (!url) continue;
      out.push({ url, path: shortPathFromUrl(url), tag: "", exists: null, status: null, note: "" });
    }
  }
  return out;
}

function buildSummary(a: AlertRow, items: EvidenceItem[], ev: any) {
  const first = items[0] || {};
  const attackIp = (a.attack_ip || (first as any).attack_ip || (first as any).ip || "") as string;

  const publicHost = inferPublicHost(a, ev) || "";
  const internalHost = inferInternalHost(a, ev) || "";

  const isSSH = String(a.alert_type || "").toUpperCase().includes("SSH");
  const host = isSSH ? (internalHost || publicHost) : (publicHost || internalHost);

  const user = ((first as any).user || (ev as any)?.username || "") as string;

  const cnt = Number(a.count ?? items.length ?? 0);
  const win = Number(a.window_seconds ?? 0);

  const typeText = typeToCN(a.alert_type);
  const countText = win ? `${cnt} 次 / ${win} 秒` : `${cnt} 次`;

  const port = inferPort(items, (first as any).raw);
  const portText = port ? String(port) : "";

  // ✅ 1) 产品级：后端直接给的人话总结（最高优先级）
  const backendHuman =
    (ev && typeof ev === "object" && !Array.isArray(ev) ? (ev as any).human_summary_cn : "") ||
    (a as any).human_summary_cn ||
    "";

  // ✅ 2) 产品级：assessment.targets（用于 HTTP/SSH 的“涉及目标 URL”）
  const targets = pickTargets(ev, a);
  const targetUrls = pickTargetUrls(ev);

  // ✅ 3) 如果后端没给 human_summary_cn，再用前端兜底拼一个“产品口吻”的 desc
  let desc = "";
  if (backendHuman && String(backendHuman).trim()) {
    desc = String(backendHuman).trim();
  } else {
    // ---- fallback: 前端兜底文案（只在老数据/旧告警时走）----
    const { key } = stripRulePrefix(a.alert_type || "");
    const k = (key || "").toUpperCase();

    const ipTag = attackIp || "某来源 IP";
    const hostText = host || "zmqzmq.cn";

    if (k.includes("HTTP")) {
      // HTTP：不要“失败xx次”，要“探测/枚举”
      const urlPreview = targets.length ? targets.slice(0, 3).join("、") : `http://${hostText}/`;
      const more = targets.length > 3 ? ` 等 ${targets.length} 个 URL` : "";
      desc =
        `检测到来源 IP ${ipTag} 对站点 ${hostText} 发起敏感路径探测请求：` +
        `${urlPreview}${more}。` +
        (win ? ` 行为在 ${win} 秒内集中出现，符合路径枚举/后台入口探测特征。` : ` 行为符合路径枚举/后台入口探测特征。`);
    } else if (k.includes("SSH")) {
      const publicHost = inferPublicHost(a, ev) || "";
      const internalHost = inferInternalHost(a, ev) || "";
      const asset = internalHost || publicHost || "unknown";
      const p = portText || "22";
      const userText = user || "未知账号";
      const tag =
        publicHost && internalHost && publicHost !== internalHost ? `（对外标识：${publicHost}）` : "";

      desc =
        `检测到来源 IP ${ipTag}` +
        (win ? ` 在 ${win} 秒内` : " 短时间内") +
        `对资产 ${asset}:${p} 发起异常认证尝试，失败 ${cnt} 次（账号 ${userText}）${tag}，` +
        `行为特征符合 SSH 暴力破解/口令喷洒。`;
    } else {
      desc =
        `检测到 ${typeText}，来源 ${ipTag} → ${hostText}` +
        (win ? `，${win} 秒内 ${cnt} 次` : cnt ? `，累计 ${cnt} 次` : "") +
        "。";
    }
  }

  return {
    typeText,
    attackIp,
    host,
    user,
    port: portText,
    countText,
    desc,
    targets,
    targetUrls,// ✅ 顺手返回，方便你以后在 UI 里展示更漂亮
  };
}

function openEvidence(a: AlertRow) {
  modal.open = true;
  ui.targetsExpanded = false;
  modal.alertId = a.id;
  modal.showRaw = false;

  const ev = normalizeEvidence(a.evidence);

  modal.items = pickEvidenceItems(ev);
  modal.recommendations = pickRecommendations(ev, a);
  modal.pretty = JSON.stringify(ev, null, 2);

// ✅ 人话优先
  modal.human = "";
  if (ev && typeof ev === "object" && !Array.isArray(ev)) {
    modal.human = String((ev as any).human_summary_cn || "").trim();
  }
  if (!modal.human) modal.human = String((a as any).human_summary_cn || "").trim();

  const s = buildSummary(a, modal.items, ev);

  modal.summary.typeText = s.typeText;
  modal.summary.attackIp = s.attackIp;

  const ssh = isSshAlert(a, ev);

// ✅ 弹窗：SSH 的“目标主机”就是资产（server2）；HTTP 的“目标主机”就是站点（zmqzmq.cn）
  modal.summary.host = ssh
    ? (inferInternalHost(a, ev, modal.items) || "-")
    : (inferPublicHost(a, ev) || displayTargetHost(a));

// ✅ 弹窗：SSH 场景 internalHost 可以留空/或展示资产同值都行；这里展示资产更直观
  modal.summary.internalHost = ssh
    ? (inferInternalHost(a, ev, modal.items) || "")
    : (inferInternalHost(a, ev, modal.items) || "");

  modal.summary.user = s.user;
  modal.summary.port = s.port;
  modal.summary.countText = s.countText;
  modal.summary.desc = s.desc;
  modal.summary.targets = s.targets || [];
  modal.summary.targetUrls = (s as any).targetUrls || [];
}

async function copyEvidence() {
  await navigator.clipboard.writeText(modal.pretty || "");
}

onMounted(async () => {
  await refresh();
});
</script>

<style scoped>
.head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}
.actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

.dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  display: inline-block;
}
.dot.connected {
  background: #22c55e;
  box-shadow: 0 0 0 4px rgba(34, 197, 94, 0.18);
}
.dot.connecting {
  background: #f59e0b;
  box-shadow: 0 0 0 4px rgba(245, 158, 11, 0.18);
}
.dot.disconnected {
  background: #ef4444;
  box-shadow: 0 0 0 4px rgba(239, 68, 68, 0.18);
}

.grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 12px;
}
.mini-card {
  border-radius: 14px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  background: rgba(255, 255, 255, 0.05);
  padding: 12px 12px;
}
.k {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.55);
}
.v {
  margin-top: 8px;
  font-size: 20px;
  font-weight: 900;
}
.red {
  color: #fecaca;
}

.table-wrap {
  border-radius: 14px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  overflow: hidden;
  background: rgba(0, 0, 0, 0.16);
}

.row:hover {
  background: rgba(239, 68, 68, 0.06) !important;
}

.muted {
  color: rgba(255, 255, 255, 0.62);
}

.mini-btn {
  height: 30px;
  padding: 0 10px;
  border-radius: 10px;
}
.empty {
  padding: 16px;
  color: rgba(255, 255, 255, 0.55);
  text-align: center;
}
.empty.small {
  padding: 10px 0;
  text-align: left;
}

/* ✅ badge */
.badge {
  display: inline-flex;
  align-items: center;
  height: 28px;
  padding: 0 10px;
  border-radius: 999px;
  font-weight: 900;
  letter-spacing: 0.2px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: rgba(255, 255, 255, 0.06);
}
.badge-high {
  background: rgba(239, 68, 68, 0.14);
  border-color: rgba(239, 68, 68, 0.28);
  color: rgba(254, 202, 202, 0.95);
}
.badge-medium {
  background: rgba(245, 158, 11, 0.14);
  border-color: rgba(245, 158, 11, 0.28);
  color: rgba(253, 230, 138, 0.95);
}
.badge-low {
  background: rgba(34, 197, 94, 0.12);
  border-color: rgba(34, 197, 94, 0.26);
  color: rgba(187, 247, 208, 0.95);
}

/* modal */
.modal-mask {
  position: fixed;
  inset: 0;
  background: rgba(0, 0, 0, 0.55);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 18px;
  z-index: 80;
}
.modal {
  width: min(1100px, 100%);
  max-height: 86vh;
  overflow: auto;
  border-radius: 16px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: rgba(10, 10, 10, 0.92);
}
.modal-head {
  position: sticky;
  top: 0;
  z-index: 2;
  background: rgba(10, 10, 10, 0.96);
  border-bottom: 1px solid rgba(255, 255, 255, 0.08);
  padding: 12px 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.modal-title {
  font-weight: 900;
}
.modal-body {
  padding: 14px;
}

.modal-actions {
  display: flex;
  gap: 10px;
  align-items: center;
}
.btn.ghost {
  background: rgba(255, 255, 255, 0.06);
  border: 1px solid rgba(255, 255, 255, 0.1);
}
.card-lite {
  border-radius: 14px;
  border: 1px solid rgba(255, 255, 255, 0.1);
  background: rgba(255, 255, 255, 0.04);
  padding: 12px;
  margin-bottom: 12px;
}
.section-title {
  font-weight: 800;
  margin-bottom: 10px;
  color: rgba(255, 255, 255, 0.85);
}
.summary-title {
  font-weight: 900;
  margin-bottom: 10px;
  color: rgba(255, 255, 255, 0.92);
}
.summary-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
}
.kv .k {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.55);
}
.kv .v {
  margin-top: 6px;
  font-size: 14px;
  font-weight: 700;
}
.kv.wide {
  grid-column: 1 / -1;
}
.ev-table {
  background: rgba(0, 0, 0, 0.1);
}
.wrap {
  white-space: normal !important;
  word-break: break-word;
}
.pre {
  max-height: 380px;
  overflow: auto;
  padding: 10px;
  border-radius: 12px;
  background: rgba(0, 0, 0, 0.18);
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.advice {
  padding-left: 18px;
  margin: 0;
}
.advice li {
  margin: 6px 0;
  line-height: 1.55;
  color: rgba(255, 255, 255, 0.9);
}

/* ✅ targets */
.targets {
  padding-left: 18px;
  margin: 6px 0 0 0;
}
.targets li {
  margin: 6px 0;
  line-height: 1.45;
}
.url {
  display: inline-block;
  padding: 2px 6px;
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.06);
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.targets2 {
  display: flex;
  flex-direction: column;
  gap: 8px;
  margin-top: 6px;
}

.trow {
  padding: 8px 10px;
  border-radius: 10px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.trow .line1 {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  line-height: 1.25;
}

.trow .line2 {
  margin-top: 6px;
  font-size: 12px;
  line-height: 1.25;
  opacity: 0.85;
  word-break: break-all; /* URL 不撑高 */
}
/* ✅ 行级高亮：只基于 exists/status（后端真实结果） */
.trow.trow-exists {
  border-color: rgba(34, 197, 94, 0.22);
  background: rgba(34, 197, 94, 0.08);
}

.trow.trow-warn {
  border-color: rgba(245, 158, 11, 0.24);
  background: rgba(245, 158, 11, 0.08);
}

.trow.trow-bad {
  border-color: rgba(239, 68, 68, 0.26);
  background: rgba(239, 68, 68, 0.08);
}
/* path chip：更小、更紧凑 */
.path {
  display: inline-flex;
  align-items: center;
  padding: 2px 6px;
  border-radius: 8px;
  background: rgba(255, 255, 255, 0.06);
  border: 1px solid rgba(255, 255, 255, 0.08);
}

.pill-tag {
  display: inline-flex;
  align-items: center;
  height: 22px;
  padding: 0 8px;
  border-radius: 999px;
  font-weight: 800;
  font-size: 12px;
  border: 1px solid rgba(255, 255, 255, 0.10);
  background: rgba(255, 255, 255, 0.05);
  color: rgba(255, 255, 255, 0.88);
}

.pill-exist {
  display: inline-flex;
  align-items: center;
  height: 22px;
  padding: 0 8px;
  border-radius: 999px;
  font-weight: 900;
  font-size: 12px;
  border: 1px solid rgba(255, 255, 255, 0.10);
  background: rgba(255, 255, 255, 0.05);
}
.pill-exist.exist-yes {
  border-color: rgba(34, 197, 94, 0.28);
  background: rgba(34, 197, 94, 0.12);
  color: rgba(187, 247, 208, 0.95);
}
.pill-exist.exist-no {
  border-color: rgba(255, 255, 255, 0.14);
  background: transparent;
  color: rgba(255, 255, 255, 0.72);
  box-shadow: none;
}
.pill-exist.exist-unk {
  border-color: rgba(245, 158, 11, 0.28);
  background: rgba(245, 158, 11, 0.12);
  color: rgba(253, 230, 138, 0.95);
}

.pill-status {
  display: inline-flex;
  align-items: center;
  height: 20px;
  padding: 0 7px;
  border-radius: 999px;
  font-weight: 800;
  font-size: 12px;
  border: 1px solid rgba(255, 255, 255, 0.10);
  background: rgba(0, 0, 0, 0.14);
  color: rgba(255, 255, 255, 0.78);
}
.pill-status.st-ok {
  border-color: rgba(34, 197, 94, 0.28);
  background: rgba(34, 197, 94, 0.12);
  color: rgba(187, 247, 208, 0.95);
}

.pill-status.st-move {
  border-color: rgba(59, 130, 246, 0.28);
  background: rgba(59, 130, 246, 0.12);
  color: rgba(191, 219, 254, 0.95);
}

.pill-status.st-warn {
  border-color: rgba(245, 158, 11, 0.28);
  background: rgba(245, 158, 11, 0.12);
  color: rgba(253, 230, 138, 0.95);
}

.pill-status.st-miss {
  border-color: rgba(255, 255, 255, 0.14);
  background: transparent;
  color: rgba(255, 255, 255, 0.72);
  box-shadow: none;
}

.pill-status.st-bad {
  border-color: rgba(239, 68, 68, 0.28);
  background: rgba(239, 68, 68, 0.12);
  color: rgba(254, 202, 202, 0.95);
}
.targets-toggle {
  margin-top: 6px;
}

.mini-toggle {
  height: 26px;
  padding: 0 10px;
  border-radius: 10px;
  font-size: 12px;
}
</style>
