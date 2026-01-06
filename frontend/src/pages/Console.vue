<template>
  <div class="card console-card">
    <div class="card-inner head">
      <div>
        <div class="h1">远程控制台</div>
        <div class="sub">
          <span class="tag">noVNC</span>
          <span class="mono muted">{{ displayUrl }}</span>
          <span v-if="hasAlertId" class="tag tag2">来自告警 #{{ alertId }}</span>
        </div>
      </div>

      <div class="actions">
        <button class="btn ghost" v-if="hasAlertId" @click="backToAlerts">返回告警</button>

        <!-- ✅ 软刷新：同源就真刷新；跨域就只做重绘（不改 src，不重连） -->
        <button class="btn ghost" @click="reload">刷新控制台</button>

        <!-- ✅ 真重连：一定改 src 强制重连 -->
        <button class="btn ghost" @click="reconnect">重连</button>

        <button class="btn" @click="openNewTab">新窗口打开</button>
      </div>
    </div>

    <div class="card-inner viewer">
      <iframe
        ref="frameEl"
        class="frame"
        :src="iframeSrc"
        title="noVNC Console"
        allow="fullscreen; clipboard-read; clipboard-write"
        allowfullscreen
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

const route = useRoute();
const router = useRouter();

const alertId = computed(() => String(route.query.alertId || "").trim());
const hasAlertId = computed(() => alertId.value !== "");

/**
 * ✅ 关键：把路由里传来的 url 解码成“真实 URL”
 * 你 Alerts.vue 里用了 encodeURIComponent，这里必须 decode 回来
 */
const rawUrl = computed(() => {
  const v = String(route.query.url || "").trim();
  if (!v) return "";
  try {
    return decodeURIComponent(v);
  } catch {
    return v;
  }
});

const displayUrl = computed(() => rawUrl.value || "-");

type BuildMode = "scale";

/**
 * ✅ 给 noVNC URL 补参数：
 * - resize=scale：按容器缩放
 * - autoconnect=1：自动连接（你想要“手动点连接”就删掉这一行）
 */
function withNoVncParams(u: string, mode: BuildMode = "scale") {
  if (!u) return "";
  const x = new URL(u);

  if (mode === "scale") {
    x.searchParams.set("resize", "scale");
  }

  // 保持你当前的体验：一打开就自动连接
  x.searchParams.set("autoconnect", "1");

  return x.toString();
}

/**
 * ✅ iframe 只在“url 变了”时更新 src
 * ✅ reload 不改 src（否则一定会触发重新加载/可能弹密码）
 */
const iframeSrc = ref("");
const frameEl = ref<HTMLIFrameElement | null>(null);

// 保存“上一次的 base”，避免重复 set 导致 iframe 被重建
let lastBase = "";

/** 只加载一次（url 变了才更新），不带 _t */
function loadOnce() {
  if (!rawUrl.value) {
    iframeSrc.value = "";
    lastBase = "";
    return;
  }

  const base = withNoVncParams(rawUrl.value, "scale");
  if (base === lastBase) return;

  lastBase = base;
  iframeSrc.value = base;
}

/** ✅ 真重连：强制让 iframe 重新加载（一定会重连） */
function reconnect() {
  if (!rawUrl.value) return;
  const base = withNoVncParams(rawUrl.value, "scale");

  const x = new URL(base);
  x.searchParams.set("_t", String(Date.now())); // ✅ 只有重连才加 _t

  lastBase = base; // base 本身仍记录（不带 _t）
  iframeSrc.value = x.toString();
}

/**
 * ✅ 软刷新：
 * 1) 同源：iframe 内直接 location.reload() —— 有反应且通常不需要重新输密码
 * 2) 跨域：无法访问 location，退化为触发 resize/重绘（不改 src，不重连）
 */
function reload() {
  const el = frameEl.value;
  if (!el) return;

  try {
    const w = el.contentWindow;
    if (!w) return;

    // ✅ 同源判断：能读到 location.href 才算同源
    // 跨域读取会直接抛异常，被 catch
    const href = w.location.href;

    // 如果能读到 href，说明同源：直接真刷新
    // 注意：这是真“页面刷新”，一般不会再弹 VNC 密码（取决于 noVNC 的保存/自动连接逻辑）
    if (href) {
      w.location.reload();
      return;
    }
  } catch {
    // 跨域：进这里
  }

  // ✅ 跨域退化：只触发重绘/重算布局（不改变 src，不重连）
  try {
    const w = el.contentWindow;
    if (!w) return;

    w.dispatchEvent(new Event("resize"));
    w.postMessage({ type: "NOVNC_SOFT_REFRESH" }, "*");
  } catch {}
}

function openNewTab() {
  // 新窗口打开用 base（不带 _t），避免一开就强制重连
  if (!lastBase) return;
  window.open(lastBase, "_blank");
}

function backToAlerts() {
  router.push("/alerts");
}

/**
 * ✅ 只在 rawUrl 真变化时才 loadOnce
 */
watch(
  () => rawUrl.value,
  () => loadOnce(),
  { immediate: true }
);
</script>

<style scoped>
.console-card {
  height: 100%;
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}

.sub {
  margin-top: 8px;
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}

.actions {
  display: flex;
  align-items: center;
  gap: 10px;
}

.tag {
  display: inline-flex;
  align-items: center;
  height: 22px;
  padding: 0 10px;
  border-radius: 999px;
  font-weight: 900;
  font-size: 12px;
  border: 1px solid rgba(255, 255, 255, 0.14);
  background: rgba(255, 255, 255, 0.06);
}
.tag2 {
  border-color: rgba(124, 58, 237, 0.35);
  background: rgba(124, 58, 237, 0.16);
}

.muted {
  color: rgba(255, 255, 255, 0.62);
}

.viewer {
  flex: 1 1 auto;
  min-height: 0;
  padding: 0;
  overflow: hidden;
  border-radius: 14px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(0, 0, 0, 0.18);
}

.frame {
  width: 100%;
  height: 100%;
  border: 0;
  display: block;
  overflow: hidden;
}
</style>
