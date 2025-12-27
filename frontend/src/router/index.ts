import { createRouter, createWebHistory } from "vue-router";
import AdminLayout from "@/layout/AdminLayout.vue";
import Logs from "@/pages/Logs.vue";
import Alerts from "@/pages/Alerts.vue";

const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/",
      component: AdminLayout,
      redirect: "/logs",
      children: [
        { path: "logs", component: Logs },
        { path: "alerts", component: Alerts },
      ],
    },
  ],
});

export default router;
