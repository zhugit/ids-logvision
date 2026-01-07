<!-- frontend/src/pages/Dashboard.vue -->
<template>
  <div class="dash">
    <!-- 顶部栏 -->
    <header class="topbar">
      <div class="title">
        <div class="h1">IDS · LogVision 安全态势大屏</div>
        <div class="sub">
          <span class="pill">实时态势</span>
          <span class="pill mono">Last Update: {{ lastUpdateText }}</span>
          <span class="pill" :class="wsOk ? 'ok' : 'bad'">WS {{ wsOk ? "ONLINE" : "OFFLINE" }}</span>
          <span v-if="activeRegion" class="pill warn">Region: {{ activeRegion }}</span>
        </div>
      </div>

      <div class="actions">
        <button class="btn ghost" @click="clearRegion">清除筛选</button>
        <button class="btn ghost" @click="refreshAll">刷新</button>
      </div>
    </header>

    <!-- 主体三列 -->
    <div class="grid">
      <!-- 左侧 -->
      <section class="col left">
        <div class="card">
          <div class="card-hd">
            <div class="card-title">总体概览</div>
            <div class="card-sub">今日 / 近1小时 / 当前活跃</div>
          </div>

          <div class="stats">
            <div class="stat">
              <div class="k">今日日志</div>
              <div class="v">{{ summary.todayLogs }}</div>
            </div>
            <div class="stat">
              <div class="k">今日告警</div>
              <div class="v red">{{ summary.todayAlerts }}</div>
            </div>
            <div class="stat">
              <div class="k">高危 HIGH</div>
              <div class="v red">{{ summary.high }}</div>
            </div>
            <div class="stat">
              <div class="k">中危 MED</div>
              <div class="v orange">{{ summary.medium }}</div>
            </div>
            <div class="stat">
              <div class="k">低危 LOW</div>
              <div class="v">{{ summary.low }}</div>
            </div>
            <div class="stat">
              <div class="k">活跃IP</div>
              <div class="v">{{ summary.activeIps }}</div>
            </div>
          </div>
        </div>

        <div class="card grow">
          <div class="card-hd">
            <div class="card-title">攻击趋势</div>
            <div class="card-sub">最近 60 分钟告警数</div>
          </div>
          <div ref="trendEl" class="chart"></div>
        </div>

        <div class="card">
          <div class="card-hd">
            <div class="card-title">攻击类型占比</div>
            <div class="card-sub">中文攻击类型（更适合答辩展示）</div>
          </div>
          <div ref="typeEl" class="chart small"></div>
        </div>
      </section>

      <!-- 中间：地图 -->
      <section class="col center">
        <div class="card map-card">
          <div class="card-hd">
            <div>
              <div class="card-title">攻击来源地理分布</div>
              <div class="card-sub">点击国家/区域联动右侧榜单</div>
            </div>

            <div class="map-actions">
              <button class="btn ghost" :class="{ on: mapMode === 'world' }" @click="setMapMode('world')">世界</button>
              <button class="btn ghost" :class="{ on: mapMode === 'china' }" @click="setMapMode('china')">中国</button>
            </div>
          </div>

          <div ref="mapEl" class="chart map"></div>

          <div class="map-foot">
            <div class="legend">
              <span class="dot d1"></span><span>低</span>
              <span class="dot d2"></span><span>中</span>
              <span class="dot d3"></span><span>高</span>
            </div>
            <div class="hint">说明：地图热度=近一段时间该区域触发的告警数量（可扩展为权重评分）</div>
          </div>
        </div>

        <div class="card">
          <div class="card-hd">
            <div class="card-title">最新告警滚动</div>
            <div class="card-sub">用于答辩展示“实时性”</div>
          </div>

          <div class="ticker">
            <div class="ticker-inner" :style="{ transform: `translateY(-${tickerOffset}px)` }">
              <div v-for="a in tickerAlerts" :key="a.id" class="tick">
                <span class="lvl" :class="a.severity">{{ a.severity.toUpperCase() }}</span>
                <span class="mono time">{{ fmtTime(a.ts) }}</span>
                <span class="msg">
                  {{ a.attackType }} · {{ a.title }}
                </span>
                <span class="mono muted">{{ a.targetUrl }}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- 右侧 -->
      <section class="col right">
        <div class="card">
          <div class="card-hd">
            <div class="card-title">高频攻击IP TOP 10</div>
            <div class="card-sub">（可联动地图筛选）</div>
          </div>
          <div ref="topIpEl" class="chart small"></div>
        </div>

        <div class="card">
          <div class="card-hd">
            <div class="card-title">端口分布</div>
            <div class="card-sub">常见：22 / 80 / 443</div>
          </div>
          <div ref="portEl" class="chart small"></div>
        </div>

        <div class="card grow">
          <div class="card-hd">
            <div class="card-title">规则触发列表</div>
            <div class="card-sub">展示“规则引擎 + 检测能力”（同时给出中文攻击类型）</div>
          </div>

          <div class="table">
            <div class="tr th">
              <div class="td mono">时间</div>
              <div class="td">攻击类型</div>
              <div class="td">级别</div>
              <div class="td">目标</div>
            </div>

            <div v-for="r in ruleHitsView" :key="r.id" class="tr">
              <div class="td mono muted">{{ fmtTime(r.ts) }}</div>
              <div class="td">
                {{ r.attackType }}
                <span v-if="r.rule" class="mono muted" style="margin-left: 6px;">({{ r.rule }})</span>
              </div>
              <div class="td">
                <span class="chip" :class="r.severity">{{ r.severity.toUpperCase() }}</span>
              </div>
              <div class="td mono">{{ r.targetUrl }}</div>
            </div>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onBeforeUnmount, onMounted, reactive, ref, computed } from "vue";
import * as echarts from "echarts";

type Severity = "high" | "medium" | "low";

type AttackTypeCN = "SSH暴力破解" | "登录失败" | "Web扫描探测" | "端口扫描" | "可疑请求" | "其他";

type AlertItem = {
  id: string;
  ts: number;
  severity: Severity;
  title: string;
  srcIp: string;
  region: string; // 国家/区域名（与地图 name 对齐，后续可统一映射）
  port?: string;
  targetUrl: string; // ✅ 完整URL（如果后端给不到，就展示 unknown/原样）
  rule?: string;
  attackType: AttackTypeCN; // ✅ 中文攻击类型
};

const trendEl = ref<HTMLDivElement | null>(null);
const typeEl = ref<HTMLDivElement | null>(null);
const mapEl = ref<HTMLDivElement | null>(null);
const topIpEl = ref<HTMLDivElement | null>(null);
const portEl = ref<HTMLDivElement | null>(null);

let trendChart: echarts.ECharts | null = null;
let typeChart: echarts.ECharts | null = null;
let mapChart: echarts.ECharts | null = null;
let topIpChart: echarts.ECharts | null = null;
let portChart: echarts.ECharts | null = null;

const wsOk = ref(false);
const activeRegion = ref<string>(""); // 地图点击筛选

type MapMode = "world" | "china";
const mapMode = ref<MapMode>("world");

function setMapMode(m: MapMode) {
  mapMode.value = m;
  activeRegion.value = ""; // 切换地图时清除筛选更合理
  renderMap();             // 只重绘地图即可
}

const summary = reactive({
  todayLogs: 0,
  todayAlerts: 0,
  high: 0,
  medium: 0,
  low: 0,
  activeIps: 0,
});

const alerts = ref<AlertItem[]>([]);
const lastUpdate = ref<number>(Date.now());
const lastUpdateText = computed(() => new Date(lastUpdate.value).toLocaleString());

/**
 * ✅ 目标URL：不写死任何域名
 * - 优先使用告警里的完整 URL 字段（target_url/targetUrl/url/full_url）
 * - 如果只有 path，尝试拼 host/domain/site + scheme
 * - 还没有就兜底展示 (unknown target) 或原 path
 */
function normalizeTargetUrl(input: any) {
  // 1) 已经是完整 URL：直接用
  if (typeof input === "string" && /^https?:\/\//i.test(input)) return input;

  // 2) 尝试从对象里拿完整 URL（兼容字段）
  const full = input?.target_url ?? input?.targetUrl ?? input?.url ?? input?.full_url ?? "";
  if (typeof full === "string" && /^https?:\/\//i.test(full)) return full;

  // 3) 如果只有 path，就尝试拼 host/domain（如果存在）
  const path = String(input?.path ?? input?.uri ?? input ?? "").trim();
  const host = String(input?.host ?? input?.domain ?? input?.site ?? "").trim();
  const scheme = String(input?.scheme ?? "https").trim() || "https";

  if (host && path) {
    const p = path.startsWith("/") ? path : `/${path}`;
    return `${scheme}://${host}${p}`;
  }

  // 4) 兜底：能展示多少展示多少
  if (host) return `${scheme}://${host}/`;
  if (path && path.startsWith("/")) return path;

  return "(unknown target)";
}

function inferAttackTypeCN(x: any): AttackTypeCN {
  const s = `${x?.rule ?? ""} ${x?.rule_name ?? ""} ${x?.type ?? ""} ${x?.title ?? ""} ${x?.name ?? ""} ${x?.raw ?? ""}`.toLowerCase();

  // SSH 暴力破解 / 密码失败
  if (s.includes("ssh") && (s.includes("brute") || s.includes("bruteforce") || s.includes("failed") || s.includes("password"))) {
    return "SSH暴力破解";
  }

  // 登录失败（Web/系统）
  if (s.includes("login") && (s.includes("fail") || s.includes("failed") || s.includes("invalid"))) {
    return "登录失败";
  }

  // 端口扫描
  if (s.includes("port") && s.includes("scan")) {
    return "端口扫描";
  }

  // Web 扫描（目录/路径/404峰值/爬虫探测等）
  if (s.includes("scan") || s.includes("crawler") || s.includes("dir") || s.includes("path") || s.includes("404")) {
    return "Web扫描探测";
  }

  // 可疑请求（注入/上传/模板/命令执行等关键字）
  if (s.includes("sqli") || s.includes("xss") || s.includes("ssti") || s.includes("rce") || s.includes("upload")) {
    return "可疑请求";
  }

  return "其他";
}

function fmtTime(ts: number) {
  const d = new Date(ts);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function clearRegion() {
  activeRegion.value = "";
  renderAll();
}

function refreshAll() {
  loadData();
}

/** =========================
 *  数据加载（最优策略）
 *  1) 先尝试接你现有接口 /alerts
 *  2) 如果失败就用模拟数据保证大屏可展示
 *  ========================= */
async function loadData() {
  try {
    const res = await fetch("/alerts", { credentials: "include" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    const list = Array.isArray(data) ? data : (data?.items ?? data?.alerts ?? []);
    if (!Array.isArray(list) || list.length === 0) throw new Error("empty alerts");

    alerts.value = list.slice(0, 120).map((x: any, idx: number): AlertItem => {
      const sevRaw = String(x?.severity ?? x?.level ?? "").toLowerCase();
      const sev: Severity =
        sevRaw.includes("high") ? "high" :
          sevRaw.includes("med") ? "medium" :
            sevRaw.includes("low") ? "low" :
              (x?.severity ? x.severity : "medium");

      const region = x?.region ?? x?.country ?? x?.geo?.country ?? "China";

      return {
        id: String(x?.id ?? x?.alert_id ?? x?.uuid ?? `${Date.now()}-${idx}`),
        ts: Number(x?.ts ?? x?.timestamp ?? x?.created_at ?? Date.now()),
        severity: sev,
        title: String(x?.title ?? x?.name ?? "规则触发告警"),
        srcIp: String(x?.src_ip ?? x?.ip ?? "0.0.0.0"),
        region: String(region),
        port: String(x?.port ?? ""),
        targetUrl: normalizeTargetUrl(x),
        rule: String(x?.rule ?? x?.rule_name ?? x?.type ?? ""),
        attackType: inferAttackTypeCN(x),
      };
    });

    wsOk.value = true;
  } catch (e) {
    wsOk.value = false;
    alerts.value = makeMockAlerts();
  }

  lastUpdate.value = Date.now();
  computeSummary();
  renderAll();
}

/** 统计汇总 */
function computeSummary() {
  const list = alerts.value;

  summary.todayLogs = 12830; // 你后面可用 /rawlogs 汇总替换
  summary.todayAlerts = list.length;

  summary.high = list.filter(a => a.severity === "high").length;
  summary.medium = list.filter(a => a.severity === "medium").length;
  summary.low = list.filter(a => a.severity === "low").length;

  summary.activeIps = new Set(list.map(a => a.srcIp)).size;
}

/** 地图筛选后的视图数据 */
const filteredAlerts = computed(() => {
  if (!activeRegion.value) return alerts.value;
  return alerts.value.filter(a => a.region === activeRegion.value);
});

/** 规则触发列表（右侧表格） */
const ruleHitsView = computed(() => {
  return filteredAlerts.value
    .slice()
    .sort((a, b) => b.ts - a.ts)
    .slice(0, 18)
    .map(a => ({
      id: a.id,
      ts: a.ts,
      attackType: a.attackType,
      rule: a.rule || "",
      severity: a.severity,
      targetUrl: a.targetUrl,
    }));
});

/** 滚动告警（中间底部） */
const tickerAlerts = computed(() => {
  return filteredAlerts.value
    .slice()
    .sort((a, b) => b.ts - a.ts)
    .slice(0, 30);
});

const tickerOffset = ref(0);
let tickerTimer: any = null;

function startTicker() {
  stopTicker();
  tickerOffset.value = 0;
  tickerTimer = setInterval(() => {
    const rowH = 34;
    const max = Math.max(0, (tickerAlerts.value.length - 6) * rowH);
    tickerOffset.value = tickerOffset.value >= max ? 0 : tickerOffset.value + rowH;
  }, 1500);
}
function stopTicker() {
  if (tickerTimer) clearInterval(tickerTimer);
  tickerTimer = null;
}

let mapsRegistered = false;

async function ensureMapsRegistered() {
  if (mapsRegistered) return;

  const worldJson = await import("@/assets/geo/world.json");
  const chinaJson = await import("@/assets/geo/china.json");

  echarts.registerMap("WORLD", (worldJson as any).default || worldJson);
  echarts.registerMap("CHINA", (chinaJson as any).default || chinaJson);

  mapsRegistered = true;
}


/** =========================
 *  渲染图表（ECharts）
 *  ========================= */
function ensureCharts() {
  if (trendEl.value && !trendChart) trendChart = echarts.init(trendEl.value);
  if (typeEl.value && !typeChart) typeChart = echarts.init(typeEl.value);
  if (mapEl.value && !mapChart) mapChart = echarts.init(mapEl.value);
  if (topIpEl.value && !topIpChart) topIpChart = echarts.init(topIpEl.value);
  if (portEl.value && !portChart) portChart = echarts.init(portEl.value);

  if (mapChart) {
    mapChart.off("click");
    mapChart.on("click", (params: any) => {
      const name = params?.name;
      if (typeof name === "string" && name.trim()) {
        activeRegion.value = name;
        renderAll();
      }
    });
  }
}

function renderAll() {
  ensureCharts();
  renderTrend();
  renderTypePie();
  renderMap();
  renderTopIp();
  renderPort();
  startTicker();
}

function renderTrend() {
  if (!trendChart) return;

  const now = Date.now();
  const buckets = new Array(60).fill(0);
  for (const a of filteredAlerts.value) {
    const deltaMin = Math.floor((now - a.ts) / 60000);
    if (deltaMin >= 0 && deltaMin < 60) buckets[59 - deltaMin] += 1;
  }
  const labels = Array.from({ length: 60 }, (_, i) => {
    const d = new Date(now - (59 - i) * 60000);
    return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
  });

  trendChart.setOption({
    grid: { left: 36, right: 14, top: 18, bottom: 26 },
    xAxis: {
      type: "category",
      data: labels,
      axisLabel: { color: "rgba(255,255,255,.55)", interval: 9 },
      axisLine: { lineStyle: { color: "rgba(255,255,255,.15)" } },
    },
    yAxis: {
      type: "value",
      axisLabel: { color: "rgba(255,255,255,.55)" },
      splitLine: { lineStyle: { color: "rgba(255,255,255,.08)" } },
    },
    series: [{ type: "line", data: buckets, smooth: true, symbol: "none", areaStyle: { opacity: 0.15 } }],
    tooltip: { trigger: "axis" },
  });
}

function renderTypePie() {
  if (!typeChart) return;

  const mp = new Map<string, number>();
  for (const a of filteredAlerts.value) {
    mp.set(a.attackType, (mp.get(a.attackType) || 0) + 1);
  }
  const data = Array.from(mp.entries()).map(([name, value]) => ({ name, value }));

  typeChart.setOption({
    tooltip: { trigger: "item" },
    series: [
      {
        type: "pie",
        radius: ["48%", "72%"],
        itemStyle: { borderRadius: 8, borderColor: "rgba(0,0,0,.2)", borderWidth: 2 },
        label: { color: "rgba(255,255,255,.75)" },
        data,
      },
    ],
  });
}

async function renderMap() {
  if (!mapChart) return;

  // ① 确保本地地图已注册（不走 CDN）
  try {
    await ensureMapsRegistered();
  } catch (e) {
    mapChart.clear();
    mapChart.setOption({
      title: {
        text: "地图加载失败（请检查本地 world.json / china.json）",
        left: "center",
        top: "middle",
        textStyle: { color: "rgba(255,255,255,.65)", fontSize: 12 },
      },
    });
    return;
  }

  const isWorld = mapMode.value === "world";
  const mapName = isWorld ? "WORLD" : "CHINA";

  // ② 按 region 聚合告警数量（注意：world 用国家名，china 用省市名）
  const m = new Map<string, number>();
  for (const a of alerts.value) {
    // 如果你后端 region 还没细分到省市，那切到中国地图时也能显示（只是会集中在“China/中国”这类名字上）
    m.set(a.region, (m.get(a.region) || 0) + 1);
  }
  const data = Array.from(m.entries()).map(([name, value]) => ({ name, value }));

  // ③ 渲染
  mapChart.setOption({
    tooltip: { trigger: "item" },
    visualMap: {
      min: 0,
      max: Math.max(10, ...data.map((d) => d.value)),
      left: 12,
      bottom: 18,
      text: ["高", "低"],
      textStyle: { color: "rgba(255,255,255,.65)" },
      inRange: { color: ["#2a3b4d", "#3f6f8a", "#ff6b6b"] },
      calculable: false,
    },

    geo: {
      map: mapName,
      roam: true,
      zoom: isWorld ? 1.08 : 1.15,
      itemStyle: {
        areaColor: "rgba(255,255,255,.06)",
        borderColor: "rgba(255,255,255,.15)",
      },
      emphasis: {
        itemStyle: { areaColor: "rgba(255,255,255,.12)" },
        label: { show: false },
      },
    },

    series: [
      {
        name: "告警热度",
        type: "map",
        map: mapName,
        geoIndex: 0,
        data,
      },
    ],
  });
}

function renderTopIp() {
  if (!topIpChart) return;

  const mp = new Map<string, number>();
  for (const a of filteredAlerts.value) mp.set(a.srcIp, (mp.get(a.srcIp) || 0) + 1);

  const arr = Array.from(mp.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10);

  topIpChart.setOption({
    grid: { left: 110, right: 14, top: 10, bottom: 10 },
    xAxis: {
      type: "value",
      axisLabel: { color: "rgba(255,255,255,.55)" },
      splitLine: { lineStyle: { color: "rgba(255,255,255,.08)" } },
    },
    yAxis: {
      type: "category",
      data: arr.map(x => x[0]),
      axisLabel: { color: "rgba(255,255,255,.65)" },
      axisLine: { lineStyle: { color: "rgba(255,255,255,.15)" } },
    },
    series: [{ type: "bar", data: arr.map(x => x[1]) }],
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
  });
}

function renderPort() {
  if (!portChart) return;

  const mp = new Map<string, number>();
  for (const a of filteredAlerts.value) {
    const p = (a.port || "").trim() || inferPortFromText(a.title) || inferPortFromText(a.rule || "");
    const key = p || "unknown";
    mp.set(key, (mp.get(key) || 0) + 1);
  }
  const arr = Array.from(mp.entries()).sort((a, b) => b[1] - a[1]).slice(0, 8);

  portChart.setOption({
    grid: { left: 40, right: 14, top: 18, bottom: 26 },
    xAxis: {
      type: "category",
      data: arr.map(x => x[0]),
      axisLabel: { color: "rgba(255,255,255,.65)" },
      axisLine: { lineStyle: { color: "rgba(255,255,255,.15)" } },
    },
    yAxis: {
      type: "value",
      axisLabel: { color: "rgba(255,255,255,.55)" },
      splitLine: { lineStyle: { color: "rgba(255,255,255,.08)" } },
    },
    series: [{ type: "bar", data: arr.map(x => x[1]) }],
    tooltip: { trigger: "axis" },
  });
}

function inferPortFromText(s: string) {
  const m = s.match(/\bport\s+(\d+)\b/i);
  return m ? m[1] : "";
}

/** mock：保证大屏随时可演示（✅ 不写死任何域名） */
function makeMockAlerts(): AlertItem[] {
  const regions = ["China", "United States", "Russia", "Japan", "Germany", "Singapore", "Brazil", "India"];
  const rules = ["ssh_bruteforce", "web_scan", "http_404_spike", "ssh_failed_password", "port_scan", "web_login_fail", "sqli_probe", "xss_probe"];
  const sevs: Severity[] = ["high", "medium", "low"];
  const ports = ["22", "80", "443", "8080", "3389", "9000"];
  const hosts = ["a.example.com", "b.example.net", "c.example.org", "portal.school.edu.cn", "api.demo.local"];

  const now = Date.now();
  const out: AlertItem[] = [];
  for (let i = 0; i < 90; i++) {
    const region = regions[Math.floor(Math.random() * regions.length)];
    const rule = rules[Math.floor(Math.random() * rules.length)];
    const severity = sevs[Math.floor(Math.random() * sevs.length)];
    const ts = now - Math.floor(Math.random() * 60) * 60000 - Math.floor(Math.random() * 60000);
    const host = hosts[Math.floor(Math.random() * hosts.length)];
    const path = rule.includes("login") ? "/login" : rule.includes("ssh") ? "/ssh" : "/";

    out.push({
      id: `${now}-${i}`,
      ts,
      severity,
      title:
        rule.includes("ssh") ? "SSH 异常认证行为" :
          rule.includes("login") ? "登录失败次数异常" :
            rule.includes("port_scan") ? "端口探测行为" :
              rule.includes("scan") ? "Web 探测行为" :
                rule.includes("sqli") ? "疑似 SQL 注入探测" :
                  rule.includes("xss") ? "疑似 XSS 探测" :
                    "异常行为告警",
      srcIp: `203.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
      region,
      port: ports[Math.floor(Math.random() * ports.length)],
      targetUrl: normalizeTargetUrl({ host, path, scheme: "https" }),
      rule,
      attackType: inferAttackTypeCN({ rule, title: rule }),
    });
  }
  return out;
}

/** resize */
function onResize() {
  trendChart?.resize();
  typeChart?.resize();
  mapChart?.resize();
  topIpChart?.resize();
  portChart?.resize();
}

onMounted(() => {
  loadData();
  window.addEventListener("resize", onResize);
});

onBeforeUnmount(() => {
  window.removeEventListener("resize", onResize);
  stopTicker();
  trendChart?.dispose(); trendChart = null;
  typeChart?.dispose(); typeChart = null;
  mapChart?.dispose(); mapChart = null;
  topIpChart?.dispose(); topIpChart = null;
  portChart?.dispose(); portChart = null;
});
</script>

<style scoped>
/* 大屏整体 */
.dash {
  height: 100%;
  padding: 14px;
  color: rgba(255, 255, 255, 0.92);
}

/* 顶栏 */
.topbar {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 12px;
  padding: 14px 14px 10px;
  border-radius: 16px;
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.06), rgba(255, 255, 255, 0.03));
  border: 1px solid rgba(255, 255, 255, 0.08);
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
  margin-bottom: 12px;
}
.h1 {
  font-size: 18px;
  font-weight: 800;
  letter-spacing: 0.3px;
}
.sub {
  margin-top: 6px;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}
.pill {
  font-size: 12px;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: rgba(0, 0, 0, 0.18);
}
.pill.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}
.pill.ok {
  border-color: rgba(80, 255, 180, 0.35);
}
.pill.bad {
  border-color: rgba(255, 90, 90, 0.35);
}
.pill.warn {
  border-color: rgba(255, 170, 60, 0.4);
}

.actions {
  display: flex;
  gap: 10px;
}
.btn {
  padding: 8px 12px;
  border-radius: 12px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  background: rgba(255, 255, 255, 0.06);
  color: rgba(255, 255, 255, 0.9);
  cursor: pointer;
}
.btn:hover {
  background: rgba(255, 255, 255, 0.1);
}
.btn.ghost {
  background: rgba(0, 0, 0, 0.15);
}

/* 三列布局 */
.grid {
  display: grid;
  grid-template-columns: 360px 1fr 360px;
  gap: 12px;
  height: calc(100% - 72px);
}
.col {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 0;
}
.grow {
  flex: 1;
  min-height: 0;
}

/* 卡片 */
.card {
  border-radius: 16px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: linear-gradient(180deg, rgba(255, 255, 255, 0.05), rgba(255, 255, 255, 0.03));
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.25);
  overflow: hidden;
}
.card-hd {
  padding: 12px 14px 8px;
  display: flex;
  justify-content: space-between;
  align-items: baseline;
  gap: 10px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
}
.card-title {
  font-weight: 800;
  font-size: 13px;
}
.card-sub {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.55);
}

/* 统计 */
.stats {
  padding: 12px;
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 10px;
}
.stat {
  padding: 10px 10px;
  border-radius: 14px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(0, 0, 0, 0.18);
}
.k {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.6);
}
.v {
  margin-top: 6px;
  font-size: 18px;
  font-weight: 900;
}
.v.red {
  color: rgba(255, 80, 80, 0.95);
}
.v.orange {
  color: rgba(255, 170, 60, 0.95);
}
.muted {
  color: rgba(255, 255, 255, 0.55);
}
.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
}

/* 图表容器 */
.chart {
  height: 240px;
}
.chart.small {
  height: 200px;
}
.chart.map {
  height: 460px;
}
.map-card {
  min-height: 560px;
}
.map-foot {
  padding: 10px 14px 12px;
  border-top: 1px solid rgba(255, 255, 255, 0.06);
  display: flex;
  justify-content: space-between;
  gap: 10px;
  align-items: center;
}
.legend {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: rgba(255, 255, 255, 0.6);
}
.dot {
  width: 10px;
  height: 10px;
  border-radius: 3px;
  display: inline-block;
}
.dot.d1 {
  background: #2a3b4d;
}
.dot.d2 {
  background: #3f6f8a;
}
.dot.d3 {
  background: #ff6b6b;
}
.hint {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.45);
}

/* 滚动告警 */
.ticker {
  position: relative;
  height: 6 * 34px;
  overflow: hidden;
  padding: 6px 10px 10px;
}
.tick {
  height: 34px;
  display: flex;
  align-items: center;
  gap: 10px;
  border-bottom: 1px dashed rgba(255, 255, 255, 0.06);
  padding: 0 6px;
  font-size: 12px;
}
.lvl {
  width: 54px;
  text-align: center;
  border-radius: 10px;
  padding: 3px 8px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  font-weight: 800;
}
.lvl.high {
  border-color: rgba(255, 80, 80, 0.35);
}
.lvl.medium {
  border-color: rgba(255, 170, 60, 0.35);
}
.lvl.low {
  border-color: rgba(80, 255, 180, 0.28);
}
.time {
  width: 68px;
}
.msg {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.table {
  padding: 10px 10px 12px;
}
.tr {
  display: grid;
  grid-template-columns: 86px 1fr 80px 1.2fr;
  gap: 10px;
  align-items: center;
  padding: 8px 8px;
  border-bottom: 1px solid rgba(255, 255, 255, 0.06);
  font-size: 12px;
}
.tr.th {
  color: rgba(255, 255, 255, 0.55);
  font-weight: 800;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}
.td {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.chip {
  display: inline-block;
  padding: 3px 8px;
  border-radius: 10px;
  border: 1px solid rgba(255, 255, 255, 0.12);
  font-weight: 800;
}
.chip.high {
  border-color: rgba(255, 80, 80, 0.35);
}
.chip.medium {
  border-color: rgba(255, 170, 60, 0.35);
}
.chip.low {
  border-color: rgba(80, 255, 180, 0.28);
}
.map-actions { display: flex; gap: 10px; }
.btn.on { border-color: rgba(255, 255, 255, 0.35); background: rgba(255,255,255,0.10); }

/* 响应式（窄屏自动两列/一列） */
@media (max-width: 1200px) {
  .grid {
    grid-template-columns: 1fr;
    height: auto;
  }
  .chart.map {
    height: 420px;
  }
}
</style>
