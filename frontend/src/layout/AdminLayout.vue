<template>
  <div class="shell">
    <aside class="side">
      <div class="brand">
        <div class="brand-title">IDS · LogVision</div>
        <div class="brand-sub">实时入侵检测系统</div>
      </div>

      <div class="menu">
        <RouterLink class="item" to="/logs">
          <span class="dot dot-cyan"></span>
          <span>实时日志</span>
        </RouterLink>

        <RouterLink class="item" to="/alerts">
          <span class="dot dot-red"></span>
          <span>告警中心</span>
        </RouterLink>
      </div>

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
            <RouterLink class="pill link" to="/logs">日志</RouterLink>
            <RouterLink class="pill link" to="/alerts">告警</RouterLink>
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
import { getWsChannel } from "@/api/ws";
import { idsStore as store } from "@/store/ids";

// ✅ 改法二：WS 在 Layout 常驻，切换页面不断开
const chLogs = getWsChannel("/ws/logs");
const chAlerts = getWsChannel("/ws/alerts");

let offLogsStatus: null | (() => void) = null;
let offAlertsStatus: null | (() => void) = null;

onMounted(() => {
  // Layout 一挂载就 acquire：保持连接常驻
  chLogs.acquire();
  chAlerts.acquire();

  // ✅ 把 channel 状态同步给 store（页面不刷新也能实时显示）
  offLogsStatus = chLogs.subscribeStatus((s) => {
    store.wsLogs = s as any;
  });
  offAlertsStatus = chAlerts.subscribeStatus((s) => {
    store.wsAlerts = s as any;
  });
});

onUnmounted(() => {
  // Layout 一般不会卸载，但保留释放逻辑以防热更新/路由结构变化
  offLogsStatus?.(); offLogsStatus = null;
  offAlertsStatus?.(); offAlertsStatus = null;

  chLogs.release();
  chAlerts.release();
});
</script>

<style scoped>
.shell{
  display:flex;
  min-height:100vh;
}

.side{
  width: 280px;
  padding: 18px 16px;
  background: linear-gradient(180deg, rgba(10,15,28,.92), rgba(8,12,22,.98));
  border-right: 1px solid rgba(255,255,255,.08);
}

.brand{
  padding: 14px 12px;
  border-radius: 16px;
  background: rgba(255,255,255,.04);
  border: 1px solid rgba(255,255,255,.08);
  box-shadow: 0 18px 40px rgba(0,0,0,.25);
}
.brand-title{
  font-weight: 900;
  letter-spacing: .4px;
  font-size: 18px;
}
.brand-sub{
  margin-top: 6px;
  font-size: 12px;
  color: rgba(255,255,255,.58);
}

.menu{
  margin-top: 16px;
  display:flex;
  flex-direction:column;
  gap: 10px;
}

.item{
  display:flex;
  align-items:center;
  gap: 10px;
  padding: 12px 12px;
  border-radius: 14px;
  border: 1px solid rgba(255,255,255,.08);
  background: rgba(255,255,255,.03);
  color: rgba(255,255,255,.82);
  transition: all .18s ease;
}
.item:hover{
  background: rgba(255,255,255,.06);
  transform: translateY(-1px);
}

.router-link-active{
  background: rgba(124,58,237,.16);
  border-color: rgba(124,58,237,.35);
  color: rgba(255,255,255,.95);
  box-shadow: 0 14px 36px rgba(0,0,0,.28);
}

.dot{
  width: 10px;
  height: 10px;
  border-radius: 999px;
  box-shadow: 0 0 0 4px rgba(255,255,255,.04);
}
.dot-cyan{ background: #22d3ee; }
.dot-red{ background: #ef4444; }

.side-foot{
  margin-top: 18px;
  padding: 12px;
  border-top: 1px solid rgba(255,255,255,.08);
}
.tip{
  margin-top: 10px;
  font-size: 12px;
  color: rgba(255,255,255,.55);
}

.content{
  flex: 1;
  padding: 18px 18px 22px;
}

.topbar-inner{
  display:flex;
  align-items:center;
  justify-content:space-between;
  padding: 14px 16px;
}

.right{
  display:flex;
  gap: 10px;
}
.link{
  transition: all .15s ease;
}
.link:hover{
  background: rgba(255,255,255,.10);
  color: rgba(255,255,255,.95);
}

.main{
  margin-top: 16px;
}
</style>
