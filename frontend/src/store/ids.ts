// src/store/ids.ts
import { reactive } from "vue";
import type { AlertRow, RawLog, WsState } from "@/types/ids";
import { getWsChannel } from "@/api/ws";

/**
 * ✅ 全局 IDS Store（应用级状态）
 * - Store 常驻订阅：切换页面也持续消费 WS 消息
 * - 页面只读 logs/alerts 和 ws 状态，不再创建/销毁 WS
 */

type Unsubscribe = () => void;

export const idsStore = reactive({
  // ---- public state ----
  wsLogs: "disconnected" as WsState,
  wsAlerts: "disconnected" as WsState,

  logs: [] as RawLog[],
  alerts: [] as AlertRow[],

  logsMax: 800, // 控制内存
  alertsMax: 300,

  // ---- internal ----
  _started: false,
  _unsubs: [] as Unsubscribe[],

  _chLogs: null as ReturnType<typeof getWsChannel> | null,
  _chAlerts: null as ReturnType<typeof getWsChannel> | null,

  // （可选）日志轻量去重缓存：如果你确认后端可能重复推，再打开
  // _logSeen: new Set<string>(),
  // _logSeenMax: 2000,

  // ---- helpers ----
  _trimHead<T>(arr: T[], max: number) {
    // 你用 unshift（最新在前），超长直接截断 length 即可
    if (arr.length > max) arr.length = max;
  },

  // ✅ 统一把 id 归一化成 string（避免 "62" vs 62 导致的“假重复”）
  _idOfAlert(a: AlertRow): string {
    const v = (a as any)?.id;
    return v === null || v === undefined ? "" : String(v);
  },

  // ✅ created_at 转时间戳（给排序用，不要求后端必须严格格式）
  _timeOfAlert(a: AlertRow): number {
    const s = (a as any)?.created_at;
    if (!s) return 0;
    const t = Date.parse(String(s));
    return Number.isFinite(t) ? t : 0;
  },

  // ✅ 保证 alerts 最新在前（页面也可以调用它）
  sortAlertsInPlace() {
    this.alerts.sort((a, b) => this._timeOfAlert(b) - this._timeOfAlert(a));
    this._trimHead(this.alerts, this.alertsMax);
  },

  pushLog(row: RawLog) {
    // ===== 可选：轻量去重（默认关闭，避免误去重）=====
    // const key = (row as any)?.id ?? `${(row as any)?.ts ?? ""}|${(row as any)?.message ?? ""}`;
    // if (key && this._logSeen.has(key)) return;
    // if (key) {
    //   this._logSeen.add(key);
    //   if (this._logSeen.size > this._logSeenMax) this._logSeen.clear();
    // }

    this.logs.unshift(row);
    this._trimHead(this.logs, this.logsMax);
  },

  // ✅ 用 splice 原地更新，避免“引用被替换”导致的奇怪显示/串数据
  setAlerts(rows: AlertRow[]) {
    this.alerts.splice(0, this.alerts.length, ...(rows || []));
    this._trimHead(this.alerts, this.alertsMax);
  },

  // ✅ 关键修复：按“归一化 id”去重（解决 62 vs "62"）
  pushAlert(a: AlertRow) {
    const id = this._idOfAlert(a);
    if (!id) return;

    const idx = this.alerts.findIndex((x) => this._idOfAlert(x) === id);

    if (idx >= 0) {
      // ✅ 合并更新更稳：避免部分字段在不同来源（WS/HTTP）缺失时把已有字段覆盖掉
      this.alerts[idx] = { ...(this.alerts[idx] as any), ...(a as any) } as AlertRow;
    } else {
      this.alerts.unshift(a);
    }

    this._trimHead(this.alerts, this.alertsMax);
  },

  /**
   * ✅ 启动“全局常驻”WS
   * - 在 App.vue / Layout.vue onMounted 调一次即可
   * - 多次调用不会重复订阅
   */
  startRealtime() {
    // ✅ 更硬的幂等：已 started 且通道存在就直接 return
    if (this._started && this._chLogs && this._chAlerts) return;

    // 防御：万一上次异常没清干净，先 stop 一次再起（不影响正常）
    if (this._unsubs.length || this._chLogs || this._chAlerts) {
      try {
        this.stopRealtime();
      } catch {}
    }

    this._started = true;

    // 1) Logs channel
    const chLogs = getWsChannel("/ws/logs");
    this._chLogs = chLogs;
    chLogs.acquire();

    // 订阅状态
    this._unsubs.push(
      chLogs.subscribeStatus((s) => {
        this.wsLogs = s as WsState;
      })
    );

    // 订阅消息
    this._unsubs.push(
      chLogs.subscribeJson((msg: any) => {
        if (!msg) return;

        if (msg.type === "log" && msg.data) {
          this.pushLog(msg.data as RawLog);
          return;
        }
      })
    );

    // 2) Alerts channel
    const chAlerts = getWsChannel("/ws/alerts");
    this._chAlerts = chAlerts;
    chAlerts.acquire();

    this._unsubs.push(
      chAlerts.subscribeStatus((s) => {
        this.wsAlerts = s as WsState;
      })
    );

    this._unsubs.push(
      chAlerts.subscribeJson((msg: any) => {
        if (!msg) return;

        if (msg.type === "alert" && msg.data) {
          this.pushAlert(msg.data as AlertRow);
          return;
        }
      })
    );
  },

  /**
   * ✅ 停止全局 WS（一般不用，只有“退出系统/注销/切换租户”才需要）
   * - 取消订阅 + release channel
   */
  stopRealtime() {
    // 取消订阅
    for (const u of this._unsubs) {
      try {
        u();
      } catch {}
    }
    this._unsubs = [];

    // release（refCount--），是否 close 由 ws.ts 策略决定
    try {
      this._chLogs?.release();
    } catch {}
    try {
      this._chAlerts?.release();
    } catch {}

    this._chLogs = null;
    this._chAlerts = null;

    this.wsLogs = "disconnected";
    this.wsAlerts = "disconnected";
    this._started = false;

    // this._logSeen.clear();
  },

  /**
   * ✅ 给页面“清空”按钮用
   */
  clearLogs() {
    this.logs.splice(0, this.logs.length);
    // this._logSeen.clear();
  },
  clearAlerts() {
    this.alerts.splice(0, this.alerts.length);
  },
});
