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
            <td class="mono">{{ a.host }}</td>
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
          <button class="btn" @click="copyEvidence">复制</button>
        </div>
      </div>

      <div class="modal-body">
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
            <div class="kv wide">
              <div class="k">描述</div>
              <div class="v">{{ modal.summary.desc }}</div>
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
              <td class="mono">{{ it.user || "-" }}</td>
              <td class="mono">{{ it.port || "-" }}</td>
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
import { http } from "@/api/http";
import { idsStore as store } from "@/store/ids";
import type { AlertRow } from "@/types/ids";

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

const modal = reactive({
  open: false,
  alertId: 0,
  pretty: "",
  showRaw: false,
  items: [] as EvidenceItem[],
  recommendations: [] as string[],
  summary: {
    typeText: "",
    attackIp: "",
    host: "",
    user: "",
    port: "",
    countText: "",
    desc: "",
  },
});

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
      if (m) return m[1];
    }
  }
  if (typeof fallbackRaw === "string") {
    const m = fallbackRaw.match(/\bport\s+(\d+)\b/i);
    if (m) return m[1];
  }
  return "";
}

function shortIpTag(ip?: string) {
  return ip || "";
}

function buildSummary(a: AlertRow, items: EvidenceItem[], ev: any) {
  const first = items[0] || {};
  const attackIp = (a.attack_ip || (first as any).attack_ip || (first as any).ip || "") as string;
  const host = (a.host || (first as any).host || "") as string;
  const user = ((first as any).user || (ev as any)?.username || "") as string;

  const cnt = Number(a.count ?? items.length ?? 0);
  const win = Number(a.window_seconds ?? 0);

  const typeText = typeToCN(a.alert_type);
  const countText = win ? `${cnt} 次 / ${win} 秒` : `${cnt} 次`;

  const port = inferPort(items, (first as any).raw);

  const { key } = stripRulePrefix(a.alert_type || "");
  const k = (key || "").toUpperCase();

  const ipTag = shortIpTag(attackIp) || "某来源 IP";
  const hostText = host || "（未知主机）";
  const userText = user || "（未知账号）";
  const portText = port ? String(port) : "";

  // ✅ 关键修正：用户名、端口分开表达，不再出现 user@port
  // 统一用“账号 xxx”“端口 xxx”的人话风格
  let desc = "";
  if (k.includes("SSH_BRUTE") || k.includes("SSH_BRUTEFORCE") || k.includes("SSH_BRUTE_FORCE")) {
    const extras: string[] = [];
    if (userText && userText !== "（未知账号）") extras.push(`账号 ${userText}`);
    if (portText) extras.push(`端口 ${portText}`);
    const extraText = extras.length ? `（${extras.join("，")}）` : "";

    desc =
      `【SSH 爆破告警】${ipTag} 正在对 ${hostText} 反复尝试登录${extraText}，` +
      (win ? `${win} 秒内` : "短时间内") +
      `失败 ${cnt} 次。`;
  } else if (k.includes("SSH_PASSWORD_SPRAY")) {
    const dc =
      ev && typeof ev === "object" && !Array.isArray(ev) ? (ev as any).distinct_count : undefined;
    const extras: string[] = [];
    extras.push(dc ? `覆盖 ${dc} 个账号` : "多账号尝试");
    if (portText) extras.push(`端口 ${portText}`);

    desc = `【密码喷洒告警】${ipTag} 正在对 ${hostText} 进行 SSH 登录尝试（${extras.join("，")}）。`;
  } else if (k.includes("SSH_FAIL_TO_SUCCESS")) {
    const fc =
      ev && typeof ev === "object" && !Array.isArray(ev) ? (ev as any).fail_count : undefined;
    const fws =
      ev && typeof ev === "object" && !Array.isArray(ev) ? (ev as any).fail_within_sec : undefined;

    const target = portText ? `${hostText}:${portText}` : hostText;

    desc =
      `【爆破后成功登录】${ipTag} 先在 ${fws || "短时间"}内失败` +
      (fc ? ` ≥${fc} 次` : "多次") +
      `，随后成功登录账号 ${userText} → ${target}，风险极高。`;
  } else {
    desc =
      `【告警】检测到 ${typeText}` +
      `，来源 ${ipTag}` +
      ` → ${hostText}` +
      (userText && userText !== "（未知账号）" ? `（账号 ${userText}）` : "") +
      (portText ? `（端口 ${portText}）` : "") +
      (win ? `，${win} 秒内 ${cnt} 次` : cnt ? `，累计 ${cnt} 次` : "") +
      "。";
  }

  return {
    typeText,
    attackIp,
    host,
    user,
    port: portText,
    countText,
    desc,
  };
}

function openEvidence(a: AlertRow) {
  modal.open = true;
  modal.alertId = a.id;
  modal.showRaw = false;

  const ev = normalizeEvidence(a.evidence);

  modal.items = pickEvidenceItems(ev);
  modal.recommendations = pickRecommendations(ev, a);
  modal.pretty = JSON.stringify(ev, null, 2);

  const s = buildSummary(a, modal.items, ev);
  modal.summary.typeText = s.typeText;
  modal.summary.attackIp = s.attackIp;
  modal.summary.host = s.host;
  modal.summary.user = s.user;
  modal.summary.port = s.port;
  modal.summary.countText = s.countText;
  modal.summary.desc = s.desc;
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
</style>
