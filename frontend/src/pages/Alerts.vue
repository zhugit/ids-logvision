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
        <div class="modal-title">Evidence · Alert #{{ modal.alertId }}</div>
        <button class="btn" @click="copyEvidence">复制</button>
      </div>
      <div class="modal-body">
        <pre class="mono">{{ modal.pretty }}</pre>
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

const modal = reactive({
  open: false,
  alertId: 0,
  pretty: "",
});

function normalizeEvidence(e: any) {
  try{
    if (typeof e === "string") return JSON.parse(e);
  }catch{}
  return e;
}

function openEvidence(a: AlertRow){
  modal.open = true;
  modal.alertId = a.id;
  const ev = normalizeEvidence(a.evidence);
  modal.pretty = JSON.stringify(ev, null, 2);
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
</style>
