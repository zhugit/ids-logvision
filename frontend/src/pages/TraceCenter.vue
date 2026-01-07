<template>
  <div class="wrap">
    <!-- Header -->
    <div class="card head">
      <div class="title">
        <div class="h1">溯源中心</div>
        <div class="sub">从告警 evidence.trace 还原：攻击阶段链 / 攻击指纹 / 时间线回放 / 关联线索</div>
      </div>

      <div class="actions">
        <button class="btn" @click="refresh" :disabled="loading">
          {{ loading ? "加载中..." : "刷新" }}
        </button>

        <span class="pill">
          <span class="dot" :class="wsDot"></span>
          <span>WS {{ wsText }}</span>
        </span>

        <input
          class="input"
          v-model="q"
          placeholder="筛选：IP / 规则 / Host / 路径关键字（回车）"
          @keydown.enter="applyFilter"
        />
        <button class="btn ghost" @click="applyFilter">筛选</button>
        <button class="btn ghost" @click="clearFilter" :disabled="!filterKey">清空</button>
      </div>
    </div>

    <!-- Stats -->
    <div class="grid">
      <div class="mini">
        <div class="k">告警数量</div>
        <div class="v">{{ filtered.length }}</div>
      </div>
      <div class="mini">
        <div class="k">包含溯源</div>
        <div class="v">{{ withTraceCount }}</div>
      </div>
      <div class="mini">
        <div class="k">最新告警</div>
        <div class="v mono">{{ newestId ? "#" + newestId : "-" }}</div>
      </div>
      <div class="mini wide">
        <div class="k">快捷筛选</div>
        <div class="chips">
          <button class="chip" @click="quick('高危')">高危</button>
          <button class="chip" @click="quick('中危')">中危</button>
          <button class="chip" @click="quick('SSH 爆破')">SSH 爆破</button>
          <button class="chip" @click="quick('路径扫描')">路径扫描</button>
          <button class="chip" @click="quick('有溯源')">有溯源</button>
        </div>
      </div>
    </div>

    <!-- Main -->
    <div class="split">
      <!-- Left: list -->
      <div class="card panel">
        <div class="panel-head">
          <div class="panel-title">告警列表</div>
          <div class="panel-sub">点击告警 → 右侧查看溯源回放</div>
        </div>

        <div v-if="filtered.length === 0" class="empty">
          暂无数据（或筛选条件无匹配）
        </div>

        <div v-else class="list">
          <div
            v-for="a in filtered"
            :key="String(a.id)"
            class="row"
            :class="{ active: String(selected?.id) === String(a.id) }"
            @click="select(a)"
          >
            <div class="row-top">
              <div class="badge" :class="sevClass(a.severity)">{{ sevCN(a.severity) }}</div>
              <div class="mono">#{{ a.id }}</div>
              <div class="mono ip">{{ a.attack_ip }}</div>
              <div class="host">{{ a.host }}</div>
            </div>

            <div class="row-mid">
              <div class="type">{{ ruleTitleCN(a.alert_type, a.evidence) }}</div>
              <div class="time">{{ a.created_at }}</div>
            </div>

            <div class="row-foot">
              <span class="tag ok" v-if="getTrace(a)">有溯源</span>
              <span class="tag ghost" v-else>无溯源</span>

              <span class="tag" v-if="getTopPath(a)">{{ getTopPath(a) }}</span>
              <span class="tag ghost" v-else>路径:-</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Right: detail -->
      <div class="card panel">
        <div class="panel-head">
          <div class="panel-title">溯源详情</div>
          <div class="panel-sub">阶段链 / 指纹 / 时间线 / 关联线索</div>
        </div>

        <!-- ✅ 右侧：固定摘要 + 固定 tabs + 内容区滚动 -->
        <div class="detail-shell">
          <!-- fixed -->
          <div class="detail-fixed" v-if="selected">
            <div class="detail-head">
              <div class="line">
                <span class="badge" :class="sevClass(selected.severity)">{{ sevCN(selected.severity) }}</span>
                <span class="mono">#{{ selected.id }}</span>
                <span class="mono ip">{{ selected.attack_ip }}</span>
                <span class="host">{{ selected.host }}</span>

                <span class="spacer"></span>

                <span class="pill2">
                  <span class="k2">溯源</span>
                  <span class="v2">{{ getTrace(selected) ? "已生成" : "未生成" }}</span>
                </span>

                <span class="pill2">
                  <span class="k2">路径</span>
                  <span class="v2 mono">{{ getTopPath(selected) || "-" }}</span>
                </span>
              </div>

              <div class="line small">
                <span class="type strong">{{ ruleTitleCN(selected.alert_type, selected.evidence) }}</span>
                <span class="time">{{ selected.created_at }}</span>
              </div>
            </div>

            <div class="tabs" v-if="getTrace(selected)">
              <button class="tab" :class="{ on: tab === 'timeline' }" @click="tab = 'timeline'">时间线</button>
              <button class="tab" :class="{ on: tab === 'tactic' }" @click="tab = 'tactic'">阶段链</button>
              <button class="tab" :class="{ on: tab === 'finger' }" @click="tab = 'finger'">指纹</button>
              <button class="tab" :class="{ on: tab === 'link' }" @click="tab = 'link'">关联</button>
            </div>
          </div>

          <!-- scroll -->
          <div class="detail-scroll" ref="detailScrollEl">
            <div v-if="!selected" class="empty">
              请选择左侧一条告警查看溯源回放
            </div>

            <template v-else>
              <div v-if="!getTrace(selected)" class="warn">
                <div class="warn-title">此告警暂无溯源 trace</div>
                <div class="warn-sub">
                  请确认后端在告警入库后调用 integrate_trace_into_alert，并在推送前写回 evidence.trace。
                </div>
              </div>

              <template v-else>
                <div v-if="tab === 'tactic'" class="section">
                  <div class="sec-title">攻击阶段链</div>
                  <div class="chips2">
                    <span class="chip2" v-for="(t, i) in (getTrace(selected)?.case?.tactic_chain || [])" :key="i">
                      <span class="idx">{{ i + 1 }}</span>
                      <span>{{ tacticCN(t) }}</span>
                    </span>
                    <span v-if="(getTrace(selected)?.case?.tactic_chain || []).length === 0" class="muted">-</span>
                  </div>
                </div>

                <div v-else-if="tab === 'finger'" class="section">
                  <div class="sec-title">攻击指纹</div>
                  <pre class="code">{{ pretty(getTrace(selected)?.case?.fingerprints) }}</pre>
                </div>

                <div v-else-if="tab === 'timeline'" class="section">
                  <div class="sec-title">时间线回放</div>

                  <div v-if="timelineAll.length === 0" class="muted">
                    没有 timeline（可能 raw_logs 回溯不到，或原始日志未包含该 IP）
                  </div>

                  <template v-else>
                    <div class="tl-tools">
                      <div class="muted">已显示 {{ timelineView.length }} / {{ timelineSorted.length }}</div>
                      <div class="tl-tools-right">
                        <button class="btn ghost" @click="toLatestTimeline">跳到最新</button>
                        <button class="btn ghost" @click="collapseTimeline" :disabled="tlShowCount <= TL_PAGE">收起</button>
                        <button class="btn" @click="loadMoreTimeline" :disabled="timelineView.length >= timelineSorted.length">
                          加载更多
                        </button>
                      </div>
                    </div>

                    <div class="timeline compact">
                      <div class="tl" v-for="(s, idx) in timelineView" :key="idx">
                        <div class="rail">
                          <div class="dot2"></div>
                          <div class="line2" v-if="idx !== timelineView.length - 1"></div>
                        </div>

                        <div class="tl-body">
                          <div class="tl-top">
                            <div class="mono">{{ fmtTs(s.ts) }}</div>
                            <div class="action">{{ actionCN(s.action) }}</div>
                          </div>

                          <div class="tl-summary" v-if="tlSummary(s.detail)">
                            {{ tlSummary(s.detail) }}
                          </div>

                          <details class="tl-more">
                            <summary>查看原始 detail</summary>
                            <pre class="code small">{{ pretty(s.detail) }}</pre>
                          </details>
                        </div>
                      </div>
                    </div>
                  </template>
                </div>

                <div v-else class="section">
                  <div class="sec-title">溯源关联线索</div>
                  <pre class="code">{{ pretty(getTrace(selected)?.link) }}</pre>
                </div>
              </template>
            </template>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";

type AlertRow = {
  id: number | string;
  alert_type: string;
  severity: string;
  attack_ip: string;
  host: string;
  count: number | string;
  window_seconds: number | string;
  evidence: any;
  created_at: string;
};

const API = (import.meta as any).env?.VITE_API_BASE || "http://localhost:8000";

const loading = ref(false);
const alerts = ref<AlertRow[]>([]);
const selected = ref<AlertRow | null>(null);

const q = ref("");
const filterKey = ref("");

const tab = ref<"tactic" | "finger" | "timeline" | "link">("timeline");

const wsState = ref<"on" | "off">("off");
const wsDot = computed(() => (wsState.value === "on" ? "dot-green" : "dot-gray"));
const wsText = computed(() => (wsState.value === "on" ? "已连接" : "未连接"));

const detailScrollEl = ref<HTMLElement | null>(null);

function safeJsonParse(v: any) {
  if (v == null) return null;
  if (typeof v === "object") return v;
  if (typeof v !== "string") return v;
  const s = v.trim();
  if (!s) return null;
  try {
    return JSON.parse(s);
  } catch {
    return v;
  }
}

function getTrace(a: AlertRow | null) {
  if (!a) return null;
  const ev = safeJsonParse(a.evidence);
  if (ev && typeof ev === "object" && (ev as any).trace) return (ev as any).trace;
  return null;
}

function getTopPath(a: AlertRow | null) {
  if (!a) return "";
  const tr = getTrace(a);
  return tr?.case?.dst_path || tr?.case?.fingerprints?.top_path || "";
}

function pretty(obj: any) {
  try {
    return JSON.stringify(obj ?? null, null, 2);
  } catch {
    return String(obj);
  }
}

const RULE_CN: Record<string, string> = {
  "RULE::SSH_BRUTE_FORCE": "SSH 爆破",
  "RULE::HTTP_SCAN": "路径扫描",
  "RULE::HTTP_ADMIN_SCAN": "路径扫描",
  "RULE::HTTP_PATH_BRUTEFORCE": "路径扫描",
  "RULE::PATH_SCAN": "路径扫描",
  "RULE::DIR_SCAN": "目录扫描",
  "RULE::PORT_SCAN": "端口扫描",
  "RULE::SENSITIVE_PATH": "敏感路径探测",
  "RULE::SQLI": "SQL 注入",
  "RULE::XSS": "XSS 跨站脚本",
  "RULE::SSRF": "SSRF 服务器端请求伪造",
  "RULE::RCE": "远程命令执行",
  "RULE::FILE_UPLOAD": "文件上传攻击",
  "RULE::DESERIALIZATION": "反序列化攻击",
  "RULE::WEAK_PASSWORD": "弱口令尝试",
  "RULE::LOGIN_BRUTE_FORCE": "登录爆破",
};

function ruleTitleCN(alertType: string, evidence: any) {
  const ev = safeJsonParse(evidence);
  const titleCN = (ev as any)?.title_cn || (ev as any)?.rule_title_cn;
  if (typeof titleCN === "string" && titleCN.trim()) return titleCN.trim();

  const key = String(alertType || "").trim();
  const up = key.toUpperCase().startsWith("RULE::") ? key.toUpperCase() : key;
  if (RULE_CN[up]) return RULE_CN[up];

  const rid = String(alertType || "").replace(/^RULE::/i, "").toUpperCase();
  if (rid.includes("HTTP")) return "路径扫描";
  if (rid.includes("PATH") && (rid.includes("SCAN") || rid.includes("BRUTE") || rid.includes("ENUM") || rid.includes("PROBE")))
    return "路径扫描";

  if (rid.includes("DIR") && (rid.includes("SCAN") || rid.includes("ENUM"))) return "目录扫描";
  if (rid.includes("PORT") && rid.includes("SCAN")) return "端口扫描";
  if (rid.includes("SQL")) return "SQL 注入";
  if (rid.includes("XSS")) return "XSS 跨站脚本";
  if (rid.includes("SSRF")) return "SSRF 服务器端请求伪造";
  if (rid.includes("UPLOAD")) return "文件上传攻击";
  if (rid.includes("RCE") || rid.includes("CMD")) return "远程命令执行";
  if (rid.includes("DESERIAL")) return "反序列化攻击";
  if (rid.includes("WEAK") || rid.includes("PASSWORD")) return "弱口令尝试";
  if (rid.includes("BRUTE") && (rid.includes("LOGIN") || rid.includes("AUTH"))) return "登录爆破";

  return key || "-";
}

function sevCN(sev: string) {
  const s = (sev || "").toUpperCase();
  if (s.includes("CRIT")) return "严重";
  if (s.includes("HIGH")) return "高危";
  if (s.includes("MED")) return "中危";
  if (s.includes("LOW")) return "低危";
  return sev || "-";
}

function sevClass(sev: string) {
  const s = (sev || "").toUpperCase();
  if (s.includes("HIGH") || s.includes("CRIT")) return "b-red";
  if (s.includes("MED")) return "b-amber";
  return "b-gray";
}

const newestId = computed(() => (alerts.value[0]?.id != null ? String(alerts.value[0].id) : ""));

const filtered = computed(() => {
  const key = filterKey.value.trim().toLowerCase();
  if (!key) return alerts.value;

  return alerts.value.filter((a) => {
    const ev = safeJsonParse(a.evidence);
    const text = [
      a.id,
      a.alert_type,
      ruleTitleCN(a.alert_type, a.evidence),
      sevCN(a.severity),
      a.attack_ip,
      a.host,
      a.created_at,
      getTrace(a) ? "有溯源" : "无溯源",
      getTopPath(a),
      JSON.stringify(ev ?? ""),
    ]
      .join(" ")
      .toLowerCase();
    return text.includes(key);
  });
});

const withTraceCount = computed(() => filtered.value.filter((a) => !!getTrace(a)).length);

function select(a: AlertRow) {
  selected.value = a;
  tab.value = "timeline";
  resetTimeline();
  requestAnimationFrame(() => detailScrollEl.value?.scrollTo({ top: 0, behavior: "auto" }));
}

async function refresh() {
  loading.value = true;
  try {
    const r = await fetch(`${API}/alerts?limit=80`);
    const data = await r.json();
    alerts.value = Array.isArray(data) ? (data as AlertRow[]) : [];

    if (!selected.value) {
      const first = alerts.value.length > 0 ? alerts.value[0] : null;
      if (first) selected.value = first;
    }
  } catch {
    // ignore
  } finally {
    loading.value = false;
  }
}

function applyFilter() {
  filterKey.value = q.value;
}
function clearFilter() {
  q.value = "";
  filterKey.value = "";
}
function quick(v: string) {
  q.value = v;
  applyFilter();
}

const TACTIC_CN: Record<string, string> = {
  recon: "侦察",
  scan: "扫描探测",
  initial_access: "初始访问",
  credential_access: "凭据获取",
  discovery: "信息收集",
  lateral_movement: "横向移动",
  privilege_escalation: "权限提升",
  persistence: "持久化",
  exfiltration: "数据外传",
  impact: "影响/破坏",
};
function tacticCN(t: any) {
  const s = String(t ?? "").trim();
  if (!s) return "-";
  return TACTIC_CN[s.toLowerCase()] || s;
}
function actionCN(a: any) {
  const s = String(a ?? "").trim();
  if (!s) return "-";
  const k = s.toLowerCase();
  if (k.includes("ssh")) return "SSH 认证行为";
  if (k.includes("http") || (k.includes("path") && (k.includes("scan") || k.includes("probe") || k.includes("brute")))) return "路径扫描";
  if (k.includes("dir") && k.includes("scan")) return "目录扫描";
  if (k.includes("port") && k.includes("scan")) return "端口扫描";
  return s;
}

function fmtTs(ts: any) {
  if (ts == null) return "";
  const s = String(ts).trim();
  if (s.includes("-") && s.includes(":")) return s;
  const n = Number(s);
  if (!Number.isFinite(n)) return s;
  const ms = n > 2_000_000_000_000 ? n : n * 1000;
  const d = new Date(ms);
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${y}-${m}-${day} ${hh}:${mm}:${ss}`;
}

/* timeline: 分页 */
const TL_PAGE = 30;
const tlShowCount = ref(TL_PAGE);

const timelineAll = computed(() => {
  const tr = getTrace(selected.value);
  return (tr?.case?.timeline || []) as any[];
});
const timelineSorted = computed(() => {
  const arr = [...(timelineAll.value || [])];
  return arr.reverse(); // 最新在上
});
const timelineView = computed(() => timelineSorted.value.slice(0, tlShowCount.value));

function resetTimeline() {
  tlShowCount.value = TL_PAGE;
}
function loadMoreTimeline() {
  tlShowCount.value = Math.min(tlShowCount.value + TL_PAGE, timelineSorted.value.length);
}
function collapseTimeline() {
  tlShowCount.value = TL_PAGE;
}
function toLatestTimeline() {
  resetTimeline();
  requestAnimationFrame(() => detailScrollEl.value?.scrollTo({ top: 0, behavior: "smooth" }));
}

function tlSummary(detail: any) {
  const d = detail || {};
  const user = d.ssh_user || d.user || d.username || d.login_user;
  const port = d.port;
  const path = d.path || d.dst_path || d.top_path || d.url;
  const code = d.status || d.http_status || d.code;
  const method = d.method;

  const parts = [
    method ? `方法:${method}` : "",
    user ? `用户:${user}` : "",
    port ? `端口:${port}` : "",
    path ? `路径:${String(path).slice(0, 80)}` : "",
    code ? `状态:${code}` : "",
  ].filter(Boolean);

  return parts.join("  ·  ");
}

watch(
  () => tab.value,
  () => requestAnimationFrame(() => detailScrollEl.value?.scrollTo({ top: 0, behavior: "auto" }))
);
watch(
  () => selected.value?.id,
  () => {
    resetTimeline();
    requestAnimationFrame(() => detailScrollEl.value?.scrollTo({ top: 0, behavior: "auto" }));
  }
);

function connectWs() {
  try {
    const ws = new WebSocket(`${API.replace("http://", "ws://").replace("https://", "wss://")}/ws/alerts`);
    ws.onopen = () => (wsState.value = "on");
    ws.onclose = () => (wsState.value = "off");
    ws.onerror = () => (wsState.value = "off");

    ws.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg?.type === "alert" && msg?.data) {
          const a = msg.data as AlertRow;
          alerts.value = [a, ...alerts.value.filter((x) => String(x.id) !== String(a.id))].slice(0, 200);
          if (!selected.value) selected.value = a;
        }
      } catch {
        // ignore
      }
    };
  } catch {
    wsState.value = "off";
  }
}

onMounted(async () => {
  await refresh();
  connectWs();
});
</script>

<style scoped>
/* =========================
   ✅ 核心：锁定整页高度，禁止整页滚动
   ========================= */
.wrap {
  display: flex;
  flex-direction: column;
  gap: 12px;

  height: calc(100vh - 16px); /* 关键：占满视口 */
  overflow: hidden;          /* 关键：整页不滚 */
  min-height: 0;
}

.card {
  border-radius: 16px;
  background: rgba(255,255,255,.03);
  border: 1px solid rgba(255,255,255,.08);
  overflow: hidden;
}

.head {
  padding: 14px 16px;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
}

.title .h1 { font-size: 18px; font-weight: 800; }
.title .sub { font-size: 12px; opacity: .75; margin-top: 4px; }

.actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }

.btn {
  padding: 8px 12px;
  border-radius: 10px;
  border: 1px solid rgba(255,255,255,.14);
  background: rgba(255,255,255,.06);
  cursor: pointer;
}
.btn:hover { background: rgba(255,255,255,.10); }
.btn:disabled { opacity: .6; cursor: not-allowed; }
.btn.ghost { background: transparent; }

.input {
  padding: 8px 10px;
  border-radius: 10px;
  border: 1px solid rgba(255,255,255,.14);
  background: rgba(0,0,0,.15);
  color: inherit;
  min-width: 260px;
  outline: none;
}

.pill {
  display:flex; align-items:center; gap:8px;
  padding: 6px 10px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,.14);
  background: rgba(0,0,0,.10);
  font-size: 12px;
}
.dot { width: 8px; height: 8px; border-radius: 99px; background: #777; }
.dot-green { background: #35d07f; }
.dot-gray { background: #666; }

.grid {
  display: grid;
  grid-template-columns: 1fr 1fr 1fr 2fr;
  gap: 10px;
}
.mini {
  border-radius: 14px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(0,0,0,.10);
  padding: 10px 12px;
}
.mini.wide { display: flex; flex-direction: column; gap: 8px; }
.k { font-size: 12px; opacity: .7; }
.v { font-size: 18px; font-weight: 800; margin-top: 4px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,"Liberation Mono","Courier New", monospace; }

.chips { display:flex; gap:8px; flex-wrap: wrap; }
.chip {
  font-size: 12px;
  padding: 6px 10px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,.14);
  background: rgba(0,0,0,.08);
  cursor: pointer;
}
.chip:hover { background: rgba(255,255,255,.06); }

/* ✅ 主体必须可伸缩、可计算高度 */
.split {
  flex: 1;            /* 关键 */
  min-height: 0;      /* 关键 */
  display: grid;
  grid-template-columns: 1fr 1.2fr;
  gap: 12px;
}

/* ✅ 两个 panel 都用 flex column，里面各自滚 */
.panel { min-height: 0; display: flex; flex-direction: column; }
.panel-head {
  padding: 10px 12px;
  border-bottom: 1px solid rgba(255,255,255,.08);
}
.panel-title { font-weight: 800; }
.panel-sub { font-size: 12px; opacity: .7; margin-top: 4px; }

/* ✅ 左侧列表独立滚动（你要的“告警下拉”就在这） */
.list {
  padding: 10px;
  flex: 1;
  min-height: 0;
  overflow: auto;

  scrollbar-gutter: stable;
  scrollbar-width: thin;
  scrollbar-color: rgba(255,255,255,.18) rgba(0,0,0,0);
}
.list::-webkit-scrollbar { width: 10px; }
.list::-webkit-scrollbar-track { background: transparent; }
.list::-webkit-scrollbar-thumb {
  border-radius: 999px;
  background: rgba(255,255,255,.14);
  border: 3px solid rgba(0,0,0,0);
  background-clip: padding-box;
}
.list::-webkit-scrollbar-thumb:hover {
  background: rgba(255,255,255,.22);
  background-clip: padding-box;
}
.list::-webkit-scrollbar-corner { background: transparent; }

.row {
  border-radius: 12px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(255,255,255,.03);
  padding: 10px;
  margin-bottom: 8px;
  cursor: pointer;
}
.row:hover { background: rgba(255,255,255,.06); }
.row.active {
  border-color: rgba(99, 179, 237, .55);
  box-shadow: 0 0 0 2px rgba(99, 179, 237, .12) inset;
}

.row-top { display:flex; align-items:center; gap:8px; flex-wrap: wrap; }
.row-mid { display:flex; justify-content: space-between; margin-top: 6px; opacity: .9; }
.row-foot { display:flex; gap:8px; margin-top: 8px; flex-wrap: wrap; }

.badge { font-size: 12px; padding: 3px 8px; border-radius: 999px; border: 1px solid rgba(255,255,255,.16); }
.b-red { background: rgba(255,80,80,.18); border-color: rgba(255,80,80,.35); }
.b-amber { background: rgba(255,193,7,.15); border-color: rgba(255,193,7,.35); }
.b-gray { background: rgba(180,180,180,.12); border-color: rgba(180,180,180,.25); }

.ip { opacity: .95; }
.host { opacity: .8; }
.type { font-weight: 700; }
.type.strong { font-weight: 800; }
.time { font-size: 12px; opacity: .75; }

.tag {
  font-size: 12px; padding: 3px 8px; border-radius: 999px;
  border: 1px solid rgba(255,255,255,.14);
  background: rgba(0,0,0,.10);
}
.tag.ghost { opacity: .65; }
.tag.ok {
  border-color: rgba(53,208,127,.35);
  background: rgba(53,208,127,.10);
}

/* ✅ 右侧固定区 + 滚动区 */
.detail-shell { flex: 1; display: flex; flex-direction: column; min-height: 0; }
.detail-fixed {
  padding: 10px;
  border-bottom: 1px solid rgba(255,255,255,.08);
  background: rgba(0,0,0,.06);
}
.detail-scroll {
  flex: 1;
  min-height: 0;
  overflow: auto;
  padding: 10px;
  scrollbar-gutter: stable;
  scrollbar-width: thin;
  scrollbar-color: rgba(255,255,255,.16) rgba(0,0,0,0);
}
.detail-scroll::-webkit-scrollbar { width: 10px; }
.detail-scroll::-webkit-scrollbar-track { background: transparent; }
.detail-scroll::-webkit-scrollbar-thumb {
  border-radius: 999px;
  background: rgba(255,255,255,.12);
  border: 3px solid rgba(0,0,0,0);
  background-clip: padding-box;
}
.detail-scroll::-webkit-scrollbar-thumb:hover {
  background: rgba(255,255,255,.20);
  background-clip: padding-box;
}

.detail-head {
  margin: 0;
  padding: 10px;
  border-radius: 12px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(0,0,0,.10);
}
.line { display:flex; gap:10px; align-items:center; flex-wrap: wrap; }
.line.small { margin-top: 6px; opacity: .9; }
.spacer { flex: 1; }

.pill2 {
  display:flex; align-items: baseline; gap: 6px;
  padding: 6px 10px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(0,0,0,.10);
}
.k2 { font-size: 12px; opacity: .7; }
.v2 { font-size: 12px; font-weight: 800; }

.warn {
  margin: 0;
  padding: 12px;
  border-radius: 12px;
  border: 1px solid rgba(255,193,7,.25);
  background: rgba(255,193,7,.08);
}
.warn-title { font-weight: 900; }
.warn-sub { margin-top: 6px; font-size: 12px; opacity: .85; }

.tabs { margin-top: 10px; display: flex; gap: 8px; flex-wrap: wrap; }
.tab {
  padding: 7px 10px;
  border-radius: 10px;
  border: 1px solid rgba(255,255,255,.12);
  background: rgba(0,0,0,.08);
  cursor: pointer;
  font-size: 12px;
}
.tab:hover { background: rgba(255,255,255,.06); }
.tab.on { border-color: rgba(99,179,237,.45); background: rgba(99,179,237,.10); }

.section { margin: 0; }
.sec-title { font-weight: 900; margin-bottom: 8px; }

.chips2 { display:flex; gap:8px; flex-wrap: wrap; }
.chip2 {
  display:flex; align-items:center; gap: 8px;
  padding: 6px 10px;
  border-radius: 999px;
  border: 1px solid rgba(255,255,255,.12);
  background: rgba(255,255,255,.04);
  font-size: 12px;
}
.idx {
  width: 18px; height: 18px; border-radius: 99px;
  display:flex; align-items:center; justify-content:center;
  border: 1px solid rgba(99,179,237,.35);
  background: rgba(99,179,237,.12);
  font-weight: 900;
  font-size: 11px;
}

.tl-tools { display:flex; justify-content: space-between; align-items:center; gap: 10px; margin-bottom: 10px; }
.tl-tools-right { display:flex; gap: 8px; flex-wrap: wrap; }

.timeline { display:flex; flex-direction: column; gap: 10px; }
.tl { display:grid; grid-template-columns: 20px 1fr; gap: 10px; }
.rail { display:flex; flex-direction: column; align-items:center; }
.dot2 {
  width: 8px; height: 8px; border-radius: 99px;
  background: rgba(99,179,237,.95);
  box-shadow: 0 0 0 4px rgba(99,179,237,.12);
  margin-top: 6px;
}
.line2 { width: 2px; flex: 1; background: rgba(255,255,255,.10); margin-top: 6px; border-radius: 99px; }

.tl-body {
  border-radius: 12px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(0,0,0,.10);
  padding: 10px;
}
.tl-top { display:flex; justify-content: space-between; gap: 10px; align-items: center; }
.action { font-weight: 900; }

.tl-summary { margin-top: 6px; font-size: 12px; opacity: .85; }
.tl-more { margin-top: 8px; border-top: 1px dashed rgba(255,255,255,.10); padding-top: 8px; }
.tl-more > summary { cursor: pointer; font-size: 12px; opacity: .92; }
.tl-more[open] > summary { opacity: 1; }

.code {
  white-space: pre-wrap;
  word-break: break-word;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas,"Liberation Mono","Courier New", monospace;
  font-size: 12px;
  padding: 10px;
  border-radius: 12px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(0,0,0,.16);
}
.code.small { font-size: 11px; padding: 8px; }

.empty { padding: 14px 12px; opacity: .7; }
.muted { opacity: .7; font-size: 12px; }

@media (max-width: 1100px) {
  .wrap { height: auto; overflow: visible; } /* 小屏允许整页滚 */
  .grid { grid-template-columns: 1fr 1fr; }
  .split { grid-template-columns: 1fr; }
}
</style>
