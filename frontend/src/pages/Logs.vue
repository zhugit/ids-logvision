<template>
  <div class="card">
    <div class="card-inner head">
      <div>
        <div class="h1">实时日志</div>
        <div class="sub">
          WebSocket 流式接入（/ws/logs）
          · 实时 {{ store.logs.length }} 条
          <span class="sep">·</span>
          <span class="muted">历史请点右上角「历史」</span>
        </div>
      </div>

      <div class="actions">
        <span class="pill">
          <span class="dot" :class="store.wsLogs"></span>
          <span>WS {{ wsText(store.wsLogs) }}</span>
        </span>

        <!-- ✅ 历史按钮 -->
        <button class="btn ghost" @click="openHistory">历史</button>

        <button class="btn" @click="clear">清空</button>
      </div>
    </div>

    <div class="card-inner">
      <div class="filter">
        <input v-model="q" class="inp" placeholder="过滤实时：source/host/level/message..." />
        <span class="pill">
          <span class="mono">MAX</span><span class="kbd">{{ store.logsMax }}</span>
        </span>
      </div>

      <div class="logbox">
        <div v-if="filtered.length === 0" class="empty">暂无实时日志（等待推送中）</div>

        <div v-for="row in filtered" :key="row.id" class="line">
          <span class="ts mono">{{ fmt(row.created_at) }}</span>
          <span class="pill mini mono">{{ row.source }}</span>
          <span class="pill mini mono">{{ row.host }}</span>

          <span class="badge" :class="levelClass(row.level)">{{ row.level }}</span>

          <span class="msg mono">{{ row.message }}</span>
        </div>
      </div>
    </div>
  </div>

  <!-- ✅✅✅ Drawer 永远 Teleport 到 body（不受任何容器限制） -->
  <Teleport to="body">
    <div v-if="historyOpen" class="drawer-mask" @click.self="closeHistory">
      <div class="drawer" role="dialog" aria-modal="true">
        <div class="drawer-head">
          <div>
            <div class="h2">历史日志</div>
            <div class="sub2">从数据库拉取 · 支持筛选/翻页 · 不会实时更新</div>
          </div>

          <div class="drawer-actions">
            <button class="btn ghost" @click="closeHistory">关闭</button>
          </div>
        </div>

        <div class="drawer-body">
          <!-- 筛选条 -->
          <div class="hfilter">
            <input v-model="hf.source" class="hinp" placeholder="source" />
            <input v-model="hf.host" class="hinp" placeholder="host" />
            <input v-model="hf.level" class="hinp" placeholder="level (INFO/WARN/ERROR)" />
            <input v-model="hf.q" class="hinp wide" placeholder="keyword in message..." />

            <button class="btn" @click="queryHistory(true)" :disabled="hLoading">
              {{ hLoading ? "查询中..." : "查询" }}
            </button>

            <button class="btn ghost" @click="resetHistory" :disabled="hLoading">
              重置
            </button>
          </div>

          <!-- 状态提示 -->
          <div class="hint" v-if="hError">{{ hError }}</div>

          <div class="hint" v-else>
            已加载 <b>{{ historyRows.length }}</b> 条
            <span class="sep">·</span>
            <span class="muted">点“加载更多”获取更早日志</span>
          </div>

          <!-- 历史列表 -->
          <div class="hbox">
            <div v-if="historyRows.length === 0" class="empty">暂无历史记录</div>

            <div v-for="row in historyRows" :key="'h-' + row.id" class="line">
              <span class="ts mono">{{ fmt(row.created_at) }}</span>
              <span class="pill mini mono">{{ row.source }}</span>
              <span class="pill mini mono">{{ row.host }}</span>

              <span class="badge" :class="levelClass(row.level)">{{ row.level }}</span>

              <span class="msg mono">{{ row.message }}</span>
            </div>
          </div>

          <!-- 分页 -->
          <div class="hpager">
            <button class="btn" @click="loadMore" :disabled="hLoading || !canLoadMore">
              {{ hLoading ? "加载中..." : (canLoadMore ? "加载更多" : "没有更多了") }}
            </button>

            <!-- ✅ 可选：回放到实时（默认保留，不想要直接删按钮+函数） -->
            <button class="btn ghost" @click="replayToLive" :disabled="historyRows.length === 0">
              回放到实时（插入顶部）
            </button>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { idsStore as store } from "@/store/ids";
import { getWsChannel } from "@/api/ws";

type LogRow = {
  id: number;
  source: string;
  host: string;
  level: string;
  message: string;
  created_at?: string;
};

const q = ref("");

// ✅ 历史抽屉状态
const historyOpen = ref(false);
const historyRows = ref<LogRow[]>([]);
const historyCursor = ref<number | null>(null); // ✅ 用 before_id 游标（更早的 id）
const hLoading = ref(false);
const hError = ref<string>("");

// ✅ 历史筛选
const hf = reactive({
  source: "",
  host: "",
  level: "",
  q: "",
});

// ✅ 后端 base url（如果你有 http.ts，也可以改成从那边走）
const API_BASE = "http://localhost:8000";

// WS channel（实时：只订阅推送）
const ch = getWsChannel("/ws/logs");

let offStatus: null | (() => void) = null;
let offJson: null | (() => void) = null;

function wsText(s: string){
  if (s === "connected") return "已连接";
  if (s === "connecting") return "连接中";
  return "未连接";
}
function fmt(t?: string){
  if (!t) return "-";
  return t.replace("T", " ").replace("Z", "");
}
function levelClass(lv: string){
  const v = (lv || "").toUpperCase();
  if (v.includes("ERROR")) return "badge-error";
  if (v.includes("WARN")) return "badge-warn";
  return "badge-info";
}
function clear(){
  store.logs.length = 0;
}

const filtered = computed(() => {
  const s = q.value.trim().toLowerCase();
  if (!s) return store.logs;
  return store.logs.filter((x) => {
    const blob = `${x.source} ${x.host} ${x.level} ${x.message}`.toLowerCase();
    return blob.includes(s);
  });
});

// --------------------
// 历史逻辑（HTTP）
// --------------------
const canLoadMore = computed(() => {
  return historyRows.value.length > 0 && historyCursor.value !== null;
});

function openHistory(){
  historyOpen.value = true;
  queryHistory(true);
}
function closeHistory(){
  historyOpen.value = false;
}

function resetHistory(){
  hf.source = "";
  hf.host = "";
  hf.level = "";
  hf.q = "";
  queryHistory(true);
}

function _minId(rows: LogRow[]): number | null {
  if (!rows.length) return null;
  let m = Number(rows[0].id);
  for (const r of rows) m = Math.min(m, Number(r.id));
  return Number.isFinite(m) ? m : null;
}

async function queryHistory(reset = false){
  if (hLoading.value) return;
  hLoading.value = true;
  hError.value = "";

  try{
    if (reset){
      historyRows.value = [];
      historyCursor.value = null;
    }

    const params = new URLSearchParams();
    params.set("limit", "200");

    // ✅ 分页游标：用 “当前最小 id - 1” 作为 before_id（避免重复）
    if (!reset && historyCursor.value !== null){
      params.set("before_id", String(historyCursor.value));
    }

    if (hf.source.trim()) params.set("source", hf.source.trim());
    if (hf.host.trim()) params.set("host", hf.host.trim());
    if (hf.level.trim()) params.set("level", hf.level.trim());
    if (hf.q.trim()) params.set("q", hf.q.trim());

    const res = await fetch(`${API_BASE}/logs/recent?${params.toString()}`);
    if (!res.ok){
      throw new Error(`HTTP ${res.status}`);
    }

    const rows = await res.json();

    const mapped: LogRow[] = (rows || []).map((x: any) => ({
      id: Number(x.id),
      source: x.source ?? "-",
      host: x.host ?? "-",
      level: x.level ?? "INFO",
      message: x.message ?? "",
      created_at: x.created_at ?? "",
    }));

    if (reset){
      historyRows.value = mapped;
    } else {
      historyRows.value.push(...mapped);
    }

    // ✅ 更新游标：找到当前已加载的最小 id，然后 cursor = minId - 1
    const minId = _minId(historyRows.value);
    if (minId === null){
      historyCursor.value = null;
    } else {
      const next = minId - 1;
      historyCursor.value = next > 0 ? next : null;
    }

    // 本页没数据 => 不可再加载
    if (mapped.length === 0){
      historyCursor.value = null;
    }
  }catch(e: any){
    hError.value = `历史加载失败：${e?.message ?? String(e)}`;
  }finally{
    hLoading.value = false;
  }
}

async function loadMore(){
  if (!canLoadMore.value) return;
  await queryHistory(false);
}

// ✅ 回放到实时：插入顶部，并裁剪到 logsMax（不会自动触发，只有你点按钮才会）
function replayToLive(){
  if (!historyRows.value.length) return;
  const copy = [...historyRows.value];
  store.logs.unshift(...copy);
  if (store.logs.length > store.logsMax){
    store.logs.splice(store.logsMax);
  }
  historyOpen.value = false;
}

// --------------------
// Drawer 体验：锁 body 滚动 + ESC 关闭
// --------------------
function onKeydown(e: KeyboardEvent){
  if (e.key === "Escape" && historyOpen.value){
    closeHistory();
  }
}

watch(historyOpen, (open) => {
  document.body.style.overflow = open ? "hidden" : "";
});

// --------------------
// WS 订阅（实时 ONLY）
// --------------------
onMounted(() => {
  window.addEventListener("keydown", onKeydown);

  offStatus = ch.subscribeStatus((s) => {
    store.wsLogs = s;
  });

  offJson = ch.subscribeJson((msg) => {
    if (msg?.type === "ping") return;
    if (msg?.type !== "log" || !msg?.data) return;

    const d = msg.data;
    store.pushLog({
      id: Number(d.id ?? Date.now()),
      source: d.source ?? "-",
      host: d.host ?? "-",
      level: d.level ?? "INFO",
      message: d.message ?? "",
      created_at: d.created_at ?? "",
    });
  });
});

onUnmounted(() => {
  window.removeEventListener("keydown", onKeydown);
  document.body.style.overflow = "";

  offStatus?.(); offStatus = null;
  offJson?.(); offJson = null;
});
</script>

<style scoped>
/* ✅ 原样保留你的样式 + Drawer 样式 */

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

.sep{ margin: 0 6px; opacity: .55; }
.muted{ opacity: .7; }

.filter{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap: 12px;
  margin-bottom: 12px;
}

.inp{
  flex: 1;
  height: 36px;
  border-radius: 12px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(255,255,255,.05);
  color: rgba(255,255,255,.92);
  padding: 0 12px;
  outline: none;
}
.inp:focus{
  border-color: rgba(124,58,237,.55);
  box-shadow: 0 0 0 4px rgba(124,58,237,.18);
}

.logbox{
  border-radius: 14px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(0,0,0,.18);
  max-height: 72vh;
  overflow:auto;
  padding: 8px;
}

.line{
  display:flex;
  align-items:flex-start;
  gap: 10px;
  padding: 8px 8px;
  border-radius: 12px;
}
.line:hover{
  background: rgba(255,255,255,.04);
}

.ts{
  width: 170px;
  color: rgba(255,255,255,.55);
  flex: 0 0 auto;
}

.mini{
  height: 22px;
  padding: 0 8px;
  font-size: 11px;
  color: rgba(255,255,255,.62);
}

.msg{
  color: rgba(255,255,255,.88);
  white-space: pre-wrap;
  word-break: break-word;
  flex: 1;
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

.empty{
  padding: 18px 12px;
  color: rgba(255,255,255,.55);
  text-align:center;
}

/* ---------- Drawer（Teleport 到 body 后，固定覆盖全屏） ---------- */
.drawer-mask{
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,.55);
  backdrop-filter: blur(8px);
  z-index: 9999;
  display:flex;
  justify-content:flex-end;
}

.drawer{
  width: min(860px, 92vw);
  height: 100%;
  border-left: 1px solid rgba(255,255,255,.12);
  background: rgba(10,12,20,.82);
  box-shadow: -20px 0 60px rgba(0,0,0,.45);
  display:flex;
  flex-direction:column;
}

.drawer-head{
  padding: 16px 16px 10px;
  display:flex;
  align-items:flex-start;
  justify-content:space-between;
  gap: 12px;
}

.h2{
  font-size: 18px;
  font-weight: 700;
  color: rgba(255,255,255,.92);
}
.sub2{
  margin-top: 4px;
  font-size: 12px;
  color: rgba(255,255,255,.62);
}

.drawer-actions{
  display:flex;
  align-items:center;
  gap: 10px;
}

.drawer-body{
  padding: 0 16px 16px;
  display:flex;
  flex-direction:column;
  gap: 10px;
  overflow: hidden;
}

.hfilter{
  display:flex;
  align-items:center;
  gap: 10px;
  flex-wrap: wrap;
}

.hinp{
  height: 34px;
  border-radius: 12px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(255,255,255,.05);
  color: rgba(255,255,255,.92);
  padding: 0 10px;
  outline: none;
  width: 140px;
}
.hinp.wide{ width: 260px; }
.hinp:focus{
  border-color: rgba(124,58,237,.55);
  box-shadow: 0 0 0 4px rgba(124,58,237,.18);
}

.hint{
  font-size: 12px;
  color: rgba(255,255,255,.66);
}

.hbox{
  border-radius: 14px;
  border: 1px solid rgba(255,255,255,.10);
  background: rgba(0,0,0,.16);
  padding: 8px;
  overflow:auto;
  height: calc(100vh - 220px);
}

.hpager{
  display:flex;
  gap: 10px;
  justify-content:flex-end;
}
</style>
