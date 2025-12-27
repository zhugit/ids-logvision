// src/store/ids.ts
import { reactive } from "vue";
import type { AlertRow, RawLog, WsState } from "@/types/ids";

export const idsStore = reactive({
  wsLogs: "disconnected" as WsState,
  wsAlerts: "disconnected" as WsState,

  logs: [] as RawLog[],
  alerts: [] as AlertRow[],

  logsMax: 800, // 控制内存
  alertsMax: 300, // 告警也做个上限，避免越跑越卡（你可自行改大）

  pushLog(row: RawLog) {
    this.logs.unshift(row);
    if (this.logs.length > this.logsMax) this.logs.length = this.logsMax;
  },

  // ✅ 用 splice 原地更新，避免“引用被替换”导致的奇怪显示/串数据现象
  setAlerts(rows: AlertRow[]) {
    this.alerts.splice(0, this.alerts.length, ...(rows || []));
    if (this.alerts.length > this.alertsMax) this.alerts.length = this.alertsMax;
  },

  pushAlert(a: AlertRow) {
    const idx = this.alerts.findIndex((x) => x.id === a.id);
    if (idx >= 0) this.alerts[idx] = a;
    else this.alerts.unshift(a);

    if (this.alerts.length > this.alertsMax) this.alerts.length = this.alertsMax;
  },
});
