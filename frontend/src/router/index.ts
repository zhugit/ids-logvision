import { createRouter, createWebHistory } from "vue-router";
import AdminLayout from "@/layout/AdminLayout.vue";
import Dashboard from "@/pages/Dashboard.vue";
import Logs from "@/pages/Logs.vue";
import Alerts from "@/pages/Alerts.vue";
import TraceCenter from "@/pages/TraceCenter.vue";
import Console from "@/pages/Console.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/",
      component: AdminLayout,
      redirect: "/dashboard", // ✅ 首页默认大屏
      children: [
        { path: "dashboard", component: Dashboard }, // ✅ 大屏
        { path: "logs", component: Logs },
        { path: "alerts", component: Alerts },
        { path: "trace", component: TraceCenter }, // ✅ 溯源中心
        { path: "console", component: Console },
      ],
    },
  ],
});

export default router;
