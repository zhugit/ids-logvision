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
          <div class="k">高危 HIGH</div>
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
            <td class="mono">{{ a.alert_type }}</td>
            <td>
                <span class="badge" :class="sevClass(a.severity)">
                  {{ a.severity }}
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

        <div v-if="store.alerts.length===0" class="empty">
          暂无告警（你可以运行 replay_ssh_failed.py 触发）
        </div>
      </div>
    </div>
  </div>

  <!-- Evidence Modal -->
  <div v-if="modal.open" class="modal-mask" @click.self="modal.open=false">
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
        <!-- ✅ 中文摘要 -->
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

        <!-- ✅ 证据列表（表格化） -->
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

        <!-- ✅ 原始 JSON（可切换） -->
        <div v-if="modal.showRaw" class="card-lite">
          <div class="section-title">原始 JSON</div>
          <pre class="mono pre">{{ modal.pretty }}</pre>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive } from "vue";
import { http } from "@/api/http";
import { idsStore as store } from "@/store/ids";
import { getWsChannel } from "@/api/ws";
import type { AlertRow } from "@/types/ids";

// ✅ 单例 channel：同一个 url 只有一个 WS，不会反复 close/open 抖动
const ch = getWsChannel("/ws/alerts");

let offStatus: null | (() => void) = null;
let offJson: null | (() => void) = null;

function wsText(s: string){
  if (s === "connected") return "已连接";
  if (s === "connecting") return "连接中";
  return "未连接";
}
function fmt(t: string){
  return (t || "").replace("T"," ").replace("Z","");
}
function sevClass(sv: string){
  const v = (sv||"").toUpperCase();
  if (v.includes("HIGH")) return "badge-high";
  if (v.includes("MED")) return "badge-medium";
  return "badge-low";
}

const highCount = computed(() =>
  store.alerts.filter(x => (x.severity||"").toUpperCase().includes("HIGH")).length
);
const newestId = computed(() => store.alerts[0]?.id ?? "-");

async function refresh(){
  const res = await http.get("/alerts", { params: { limit: 50 } });
  store.setAlerts(res.data as AlertRow[]);
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
  summary: {
    typeText: "",
    attackIp: "",
    host: "",
    user: "",
    port: "",
    countText: "",
    desc: "",
  }
});

function normalizeEvidence(e: any) {
  try{
    if (typeof e === "string") return JSON.parse(e);
  }catch{}
  return e;
}

function toArrayEvidence(ev: any): EvidenceItem[] {
  if (!ev) return [];
  if (Array.isArray(ev)) return ev as EvidenceItem[];
  if (typeof ev === "object") return [ev as EvidenceItem];
  return [];
}

function fmtTs(ts: any) {
  if (ts === null || ts === undefined || ts === "") return "-";
  // 可能是秒 / 毫秒 / 字符串
  const n = Number(ts);
  if (!Number.isFinite(n)) return String(ts);

  const ms = n > 1e12 ? n : n * 1000; // >1e12 认为是毫秒
  const d = new Date(ms);
  const pad = (x: number) => String(x).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function typeToCN(t: string){
  const v = (t||"").toUpperCase();
  if (v.includes("SSH_BRUTEFORCE")) return "SSH 爆破（多次口令尝试）";
  return t || "未知";
}

function buildSummary(a: AlertRow, items: EvidenceItem[]) {
  const first = items[0] || {};
  const attackIp = (a.attack_ip || first.attack_ip || first.ip || "") as string;
  const host = (a.host || first.host || "") as string;
  const user = (first.user || "") as string;
  const port = (first.port ?? "") as any;

  const cnt = Number(a.count ?? items.length ?? 0);
  const win = Number(a.window_seconds ?? 0);

  const typeText = typeToCN(a.alert_type);
  const countText = win ? `${cnt} 次 / ${win} 秒` : `${cnt} 次`;

  // 描述用“人话”串起来
  let desc = `检测到 ${typeText}`;
  if (attackIp) desc += `，攻击源 ${attackIp}`;
  if (host) desc += ` → 目标主机 ${host}`;
  if (user) desc += `，尝试账号 ${user}`;
  if (port) desc += `，端口 ${port}`;
  if (cnt) desc += `，窗口内累计 ${cnt} 次`;
  desc += "。";

  return { typeText, attackIp, host, user, port: port ? String(port) : "", countText, desc };
}

function openEvidence(a: AlertRow){
  modal.open = true;
  modal.alertId = a.id;
  modal.showRaw = false;

  const ev = normalizeEvidence(a.evidence);
  modal.items = toArrayEvidence(ev);

  // 原始 JSON 仍然保留，方便复制
  modal.pretty = JSON.stringify(ev, null, 2);

  // ✅ 构建中文摘要
  const s = buildSummary(a, modal.items);
  modal.summary.typeText = s.typeText;
  modal.summary.attackIp = s.attackIp;
  modal.summary.host = s.host;
  modal.summary.user = s.user;
  modal.summary.port = s.port;
  modal.summary.countText = s.countText;
  modal.summary.desc = s.desc;
}

async function copyEvidence(){
  await navigator.clipboard.writeText(modal.pretty || "");
}

onMounted(async () => {
  await refresh();

  // ✅ 绑定 WS 状态（连接由 Layout 负责）
  offStatus = ch.subscribeStatus((s) => {
    store.wsAlerts = s;
  });

  // ✅ 严格只消费 alert，避免“串线”
  offJson = ch.subscribeJson((msg) => {
    if (msg?.type === "ping") return;
    if (msg?.type !== "alert" || !msg?.data) return;

    const d = msg.data;
    store.pushAlert({
      id: Number(d.id),
      alert_type: d.alert_type,
      severity: d.severity,
      attack_ip: d.attack_ip,
      host: d.host,
      count: Number(d.count ?? 0),
      window_seconds: Number(d.window_seconds ?? 0),
      evidence: d.evidence,
      created_at: d.created_at,
    });
  });
});

onUnmounted(() => {
  offStatus?.(); offStatus = null;
  offJson?.(); offJson = null;
});
</script>

<style scoped>
.head{
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap: 16px;
}
.actions{
  display:flex;
  align-items:center;
  gap: 10px;
}

.dot{
  width: 10px;
  height: 10px;
  border-radius: 999px;
  display:inline-block;
}
.dot.connected{ background: #22c55e; box-shadow: 0 0 0 4px rgba(34,197,94,.18); }
.dot.connecting{ background: #f59e0b; box-shadow: 0 0 0 4px rgba(245,158,11,.18); }
.dot.disconnected{ background: #ef4444; box-shadow: 0 0 0 4px rgba(239,68,68,.18); }

.grid{
  display:grid;
  grid-template-columns: repeat(3, minmax(0,1fr));
  gap: 12px;
  margin-bottom: 12px;
}
.mini-card{
  border-radius: 14px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(255,255,255,.05);
  padding: 12px 12px;
}
.k{
  font-size: 12px;
  color: rgba(255,255,255,.55);
}
.v{
  margin-top: 8px;
  font-size: 20px;
  font-weight: 900;
}
.red{ color: #fecaca; }

.table-wrap{
  border-radius: 14px;
  border: 1px solid rgba(255,255,255,.10);
  overflow: hidden;
  background: rgba(0,0,0,.16);
}

.row:hover{
  background: rgba(239,68,68,.06) !important;
}

.muted{ color: rgba(255,255,255,.62); }

.mini-btn{
  height: 30px;
  padding: 0 10px;
  border-radius: 10px;
}
.empty{
  padding: 16px;
  color: rgba(255,255,255,.55);
  text-align:center;
}
.empty.small{
  padding: 10px 0;
  text-align:left;
}

/* ===== modal增强 ===== */
.modal-actions{
  display:flex;
  gap: 10px;
  align-items:center;
}
.btn.ghost{
  background: rgba(255,255,255,.06);
  border: 1px solid rgba(255,255,255,.10);
}
.card-lite{
  border-radius: 14px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(255,255,255,.04);
  padding: 12px;
  margin-bottom: 12px;
}
.section-title{
  font-weight: 800;
  margin-bottom: 10px;
  color: rgba(255,255,255,.85);
}
.summary-title{
  font-weight: 900;
  margin-bottom: 10px;
  color: rgba(255,255,255,.92);
}
.summary-grid{
  display:grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
}
.kv .k{
  font-size: 12px;
  color: rgba(255,255,255,.55);
}
.kv .v{
  margin-top: 6px;
  font-size: 14px;
  font-weight: 700;
}
.kv.wide{
  grid-column: 1 / -1;
}
.ev-table{
  background: rgba(0,0,0,.10);
}
.wrap{
  white-space: normal !important;
  word-break: break-word;
}
.pre{
  max-height: 380px;
  overflow: auto;
  padding: 10px;
  border-radius: 12px;
  background: rgba(0,0,0,.18);
  border: 1px solid rgba(255,255,255,.08);
}
</style>
