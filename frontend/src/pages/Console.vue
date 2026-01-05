<template>
  <div class="card console-card">
    <div class="card-inner head">
      <div>
        <div class="h1">远程控制台</div>
        <div class="sub">
          <span class="tag">noVNC</span>
          <span class="mono muted">{{ rawUrl }}</span>
          <span v-if="alertId" class="tag tag2">来自告警 #{{ alertId }}</span>
        </div>
      </div>

      <div class="actions">
        <button class="btn ghost" v-if="alertId" @click="backToAlerts">返回告警</button>
        <button class="btn ghost" @click="reload">刷新控制台</button>
        <button class="btn" @click="openNewTab">新窗口打开</button>
      </div>
    </div>

    <!-- ✅ viewer 必须 overflow:hidden，且高度要由父级链路保证 -->
    <div class="card-inner viewer">
      <iframe
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
import { computed, ref, watchEffect } from "vue";
import { useRoute, useRouter } from "vue-router";

const route = useRoute();
const router = useRouter();

const rawUrl = computed(() => String(route.query.url || "").trim());
const alertId = computed(() => String(route.query.alertId || "").trim());

type BuildMode = "scale";

/**
 * ✅ 给 noVNC URL 补参数：
 * - resize=scale：按容器缩放（让 noVNC 自适配你的 viewer，不要滚动条）
 * - autoconnect=1：自动连接（你想手动点“连接”就删掉这行）
 */
function withNoVncParams(u: string, mode: BuildMode = "scale") {
  if (!u) return "";
  try {
    const x = new URL(u);

    if (mode === "scale") {
      x.searchParams.set("resize", "scale");
    }

    // 你想保留“连接按钮”，就注释下一行
    x.searchParams.set("autoconnect", "1");

    return x.toString();
  } catch {
    const sep = u.includes("?") ? "&" : "?";
    const extra = mode === "scale" ? "resize=scale&autoconnect=1" : "autoconnect=1";
    return u + sep + extra;
  }
}

/**
 * ✅ 方案一：iframeSrc 独立维护
 * - 不去改路由 query（避免 url 越拼越长）
 * - reload 只改 iframeSrc，强制 iframe 重新加载 = 真重连
 */
const iframeSrc = ref("");

function rebuildIframeSrc() {
  const base = withNoVncParams(rawUrl.value, "scale");
  if (!base) {
    iframeSrc.value = "";
    return;
  }
  const x = new URL(base);
  x.searchParams.set("_t", String(Date.now())); // 强制刷新
  iframeSrc.value = x.toString();
}

function reload() {
  rebuildIframeSrc();
}

function openNewTab() {
  if (!iframeSrc.value) return;
  window.open(iframeSrc.value, "_blank");
}

function backToAlerts() {
  router.push("/alerts");
}

/**
 * ✅ 当路由 url 变化时自动重建 iframe src
 * （比如从告警点进来/换了目标控制台）
 */
watchEffect(() => {
  if (rawUrl.value) rebuildIframeSrc();
});
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
  overflow: hidden; /* ✅ 关键：不要出现页面滚动条 */
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
