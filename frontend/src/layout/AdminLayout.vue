<template>
  <div class="shell">
    <aside class="side">
      <!-- ✅ 品牌区：点击回到首页（大屏） -->
      <RouterLink class="brand brand-link" to="/dashboard">
        <div class="brand-title">IDS · LogVision</div>
        <div class="brand-sub">实时入侵检测系统</div>
      </RouterLink>

      <div class="menu">
        <!-- ✅ 新增：态势大屏（首页入口） -->
        <RouterLink class="item" to="/dashboard">
          <span class="dot dot-purple"></span>
          <span>态势大屏</span>
        </RouterLink>

        <RouterLink class="item" to="/logs">
          <span class="dot dot-cyan"></span>
          <span>实时日志</span>
        </RouterLink>

        <RouterLink class="item" to="/alerts">
          <span class="dot dot-red"></span>
          <span>告警中心</span>
        </RouterLink>

        <div class="menu-divider">
          <span class="menu-divider-text">告警分析</span>
        </div>

        <RouterLink class="item item-sub" to="/trace">
          <span class="dot dot-amber"></span>
          <span>溯源中心</span>
        </RouterLink>
      </div>
      <!-- ✅ 修复点：这里补上 menu 的闭合 -->

      <div class="side-foot">
        <div class="pill">
          <span class="mono">API</span>
          <span class="kbd">localhost:8000</span>
        </div>
        <div class="tip">SOC / SIEM 风格 UI</div>
      </div>
    </aside>

    <div class="content">
      <header class="topbar card">
        <div class="topbar-inner">
          <div class="left">
            <div class="h1">控制台</div>
            <div class="sub">实时日志接入 · 检测 · 告警可视化</div>
          </div>

          <div class="right">
            <!-- ✅ 顶部快捷入口：大屏 / 日志 / 告警 -->
            <RouterLink class="pill link" to="/dashboard">大屏</RouterLink>
            <RouterLink class="pill link" to="/logs">日志</RouterLink>
            <RouterLink class="pill link" to="/alerts">告警</RouterLink>
            <RouterLink class="pill link" to="/trace">溯源</RouterLink>
          </div>
        </div>
      </header>

      <main class="main">
        <div class="container">
          <RouterView />
        </div>
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted } from "vue";
import { idsStore as store } from "@/store/ids";

/**
 * ✅ 最佳做法：Layout 只负责“启动全局常驻实时模块”
 * - WS 的 acquire / subscribeJson / subscribeStatus 全部由 store.startRealtime() 统一管理
 * - 页面切换不会影响 WS 消费
 */
onMounted(() => {
  store.startRealtime();
});

onUnmounted(() => {
  /**
   * Layout 一般不会卸载（除非热更新/路由结构变动）
   * 保留 stopRealtime 以防你调试时出现“重复订阅”：
   * - 你想彻底关闭 WS 时可以打开这一行
   * - 正常生产建议不关，让它常驻
   */
  // store.stopRealtime();
});
</script>

<style scoped>
.shell {
  display: flex;
  min-height: 100vh;
}

/* ------------------- left side ------------------- */
.side {
  width: 280px;
  padding: 18px 16px;
  background: linear-gradient(180deg, rgba(10, 15, 28, 0.92), rgba(8, 12, 22, 0.98));
  border-right: 1px solid rgba(255, 255, 255, 0.08);
}

/* ✅ brand 现在是 RouterLink：保持原样式 + 可点击反馈 */
.brand {
  padding: 14px 12px;
  border-radius: 16px;
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  box-shadow: 0 18px 40px rgba(0, 0, 0, 0.25);
}
.brand-link {
  display: block;
  color: inherit;
  text-decoration: none;
  transition: all 0.18s ease;
}
.brand-link:hover {
  background: rgba(255, 255, 255, 0.06);
  transform: translateY(-1px);
}

.brand-title {
  font-weight: 900;
  letter-spacing: 0.4px;
  font-size: 18px;
}
.brand-sub {
  margin-top: 6px;
  font-size: 12px;
  color: rgba(255, 255, 255, 0.58);
}

.menu {
  margin-top: 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;

  /* ✅关键：让子项强制拉伸占满整行 */
  width: 100%;
  align-items: stretch;
}

.item {
  /* ✅关键：不管任何情况下，都必须占满 aside 的可用宽度 */
  width: 100%;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 12px;
  border-radius: 14px;
  border: 1px solid rgba(255, 255, 255, 0.08);
  background: rgba(255, 255, 255, 0.03);
  color: rgba(255, 255, 255, 0.82);
  transition: all 0.18s ease;

  /* ✅再保险：避免 flex 子项在列布局里出现 shrink-to-fit */
  align-self: stretch;
}

.item:hover {
  background: rgba(255, 255, 255, 0.06);
  transform: translateY(-1px);
}

/* ✅ 只给左侧菜单项高亮，不影响 brand */
.menu .item.router-link-active {
  background: rgba(124, 58, 237, 0.16);
  border-color: rgba(124, 58, 237, 0.35);
  color: rgba(255, 255, 255, 0.95);
  box-shadow: 0 14px 36px rgba(0, 0, 0, 0.28);
}

.menu-divider {
  margin: 6px 2px 2px;
  display: flex;
  align-items: center;
  gap: 10px;
  opacity: 0.9;
}
.menu-divider::before,
.menu-divider::after {
  content: "";
  flex: 1;
  height: 1px;
  background: rgba(255, 255, 255, 0.1);
}
.menu-divider-text {
  font-size: 12px;
  color: rgba(255, 255, 255, 0.55);
  letter-spacing: 0.6px;
}

/* ✅ 让“溯源中心”看起来是告警模块的下钻功能，而不是并列菜单 */
.item-sub {
  margin-left: 12px; /* 视觉缩进 */
  width: calc(100% - 12px);
  border-style: dashed; /* 区分主模块 */
  background: rgba(255, 255, 255, 0.02);
}
.menu .item-sub.router-link-active {
  background: rgba(245, 158, 11, 0.1);
  border-color: rgba(245, 158, 11, 0.3);
}

/* ✅ brand 永远保持自己的样式，不吃 router-link-active */
.brand.router-link-active,
.brand.router-link-exact-active {
  background: rgba(255, 255, 255, 0.04);
  border: 1px solid rgba(255, 255, 255, 0.08);
  box-shadow: 0 18px 40px rgba(0, 0, 0, 0.25);
  transform: none;
}

.dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  box-shadow: 0 0 0 4px rgba(255, 255, 255, 0.04);
}
.dot-cyan {
  background: #22d3ee;
}
.dot-red {
  background: #ef4444;
}
/* ✅ 新增一个紫色点（和 active 高亮风格一致） */
.dot-purple {
  background: #a78bfa;
}
/* ✅ 溯源中心：琥珀色 */
.dot-amber {
  background: #f59e0b;
}

.side-foot {
  margin-top: 18px;
  padding: 12px;
  border-top: 1px solid rgba(255, 255, 255, 0.08);
}
.tip {
  margin-top: 10px;
  font-size: 12px;
  color: rgba(255, 255, 255, 0.55);
}

/* ------------------- right content ------------------- */
/* ✅ 关键1：content 必须是 flex 列，并且有高度、允许子项撑开 */
.content {
  flex: 1;
  padding: 18px 18px 22px;

  display: flex;
  flex-direction: column;
  min-height: 0; /* ✅ 关键：允许子项在 flex 中正确滚动/撑开 */
}

/* topbar 不动：它是固定高度 */
.topbar-inner {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 16px;
}

.right {
  display: flex;
  gap: 10px;
}
.link {
  transition: all 0.15s ease;
}
.link:hover {
  background: rgba(255, 255, 255, 0.1);
  color: rgba(255, 255, 255, 0.95);
}

/* ✅ 关键2：main 要吃掉剩余高度 */
.main {
  margin-top: 16px;

  flex: 1 1 auto; /* ✅ 吃剩余 */
  min-height: 0; /* ✅ 允许内部容器撑满 */
}

/* ✅ 关键3：RouterView 的容器必须能撑满高度 */
.container {
  height: 100%;
  min-height: 0;
}
</style>
