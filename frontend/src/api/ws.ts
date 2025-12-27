// src/api/ws.ts
export const WS_BASE = "ws://localhost:8000";

export type WsStatus = "connecting" | "connected" | "disconnected";

type Unsubscribe = () => void;

function normalizeWsUrl(urlOrPath: string) {
  let u = (urlOrPath || "").trim();

  // 传的是相对路径：/ws/logs
  if (u.startsWith("/")) u = `${WS_BASE}${u}`;

  // 传的是 http(s) 地址：自动换成 ws(s)
  if (u.startsWith("http://")) u = "ws://" + u.slice("http://".length);
  if (u.startsWith("https://")) u = "wss://" + u.slice("https://".length);

  return u;
}

class Channel {
  url: string;
  ws: WebSocket | null = null;

  status: WsStatus = "disconnected";
  refCount = 0;

  // subscribers
  onStatusSet = new Set<(s: WsStatus) => void>();
  onJsonSet = new Set<(msg: any) => void>();
  onRawSet = new Set<(ev: MessageEvent) => void>();
  onErrorSet = new Set<(e: Event) => void>();

  // reconnect
  private reconnectTimer: number | null = null;
  private manualClosed = false;
  private backoffMs = 500; // 初始 0.5s
  private maxBackoffMs = 8000;

  // ✅ 防止 CONNECTING 卡死
  private connectStartedAt = 0;
  private connectingGuardTimer: number | null = null;
  private connectingMaxMs = 10000; // 10s 还没连上就重建

  constructor(urlOrPath: string) {
    this.url = normalizeWsUrl(urlOrPath);
  }

  private setStatus(s: WsStatus) {
    this.status = s;
    this.onStatusSet.forEach((fn) => {
      try { fn(s); } catch {}
    });
  }

  private clearReconnectTimer() {
    if (this.reconnectTimer) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private clearConnectingGuard() {
    if (this.connectingGuardTimer) {
      window.clearTimeout(this.connectingGuardTimer);
      this.connectingGuardTimer = null;
    }
  }

  private scheduleReconnect(reason?: string) {
    if (this.manualClosed) return;
    if (this.refCount <= 0) return;
    if (this.reconnectTimer) return;

    const delay = this.backoffMs + Math.floor(Math.random() * 200);
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);

    this.backoffMs = Math.min(this.backoffMs * 2, this.maxBackoffMs);
  }

  private hardCloseWs(reason: string) {
    this.clearConnectingGuard();
    const ws = this.ws;
    this.ws = null;
    this.setStatus("disconnected");

    if (ws) {
      try { ws.onopen = ws.onclose = ws.onerror = ws.onmessage = null; } catch {}
      try { ws.close(1000, reason); } catch {}
    }
  }

  connect() {
    // 已经有连接或正在连接：正常情况下直接复用
    if (this.ws && (this.ws.readyState === WebSocket.OPEN)) return;

    // ✅ 如果卡在 CONNECTING 太久：重建
    if (this.ws && this.ws.readyState === WebSocket.CONNECTING) {
      const stuck = Date.now() - this.connectStartedAt > this.connectingMaxMs;
      if (!stuck) return;
      this.hardCloseWs("connecting timeout, rebuild");
    }

    this.manualClosed = false;
    this.clearReconnectTimer();
    this.clearConnectingGuard();
    this.setStatus("connecting");

    this.connectStartedAt = Date.now();

    const ws = new WebSocket(this.url);
    this.ws = ws;

    // ✅ CONNECTING 守护：10s 还没 open，则重建并走重连
    this.connectingGuardTimer = window.setTimeout(() => {
      this.connectingGuardTimer = null;
      // 仍然是 CONNECTING 才处理
      if (this.ws && this.ws.readyState === WebSocket.CONNECTING) {
        this.hardCloseWs("connecting guard timeout");
        if (!this.manualClosed && this.refCount > 0) this.scheduleReconnect("guard timeout");
      }
    }, this.connectingMaxMs);

    ws.onopen = () => {
      this.clearConnectingGuard();
      this.backoffMs = 500;
      this.setStatus("connected");
    };

    ws.onmessage = (ev) => {
      this.onRawSet.forEach((fn) => { try { fn(ev); } catch {} });

      try {
        const msg = JSON.parse(ev.data as any);
        if (msg?.type === "ping") return;
        this.onJsonSet.forEach((fn) => { try { fn(msg); } catch {} });
      } catch {
        // 非 JSON 忽略
      }
    };

    ws.onerror = (e) => {
      this.onErrorSet.forEach((fn) => { try { fn(e); } catch {} });
      // 不在这里强行 close，交给 onclose 统一处理
    };

    ws.onclose = (ev) => {
      this.clearConnectingGuard();
      this.ws = null;
      this.setStatus("disconnected");

      // ✅ 打印一下 close code，便于判断是不是 uvicorn reload/网络抖动
      // 1006 多见于服务端重启/网络中断；1000 正常关闭
      // 你可以先留着，稳定后再删
      // eslint-disable-next-line no-console
      console.log(`[WS CLOSE] ${this.url} code=${ev.code} reason=${ev.reason || ""}`);

      if (!this.manualClosed && this.refCount > 0) {
        this.scheduleReconnect(`close ${ev.code} ${ev.reason}`);
      }
    };
  }

  acquire() {
    this.refCount += 1;
    this.connect();
  }

  release() {
    this.refCount = Math.max(0, this.refCount - 1);

    // ✅ 没人用：停止重连，但不要主动 close
    // 否则页面切换/组件卸载时会不断 close/open，控制台就会一直 “no subscribers”
    if (this.refCount === 0) {
      this.manualClosed = true;
      this.clearReconnectTimer();
      this.setStatus("disconnected");
      return;
    }
  }

  subscribeStatus(fn: (s: WsStatus) => void): Unsubscribe {
    this.onStatusSet.add(fn);
    try { fn(this.status); } catch {}
    return () => this.onStatusSet.delete(fn);
  }

  subscribeJson(fn: (msg: any) => void): Unsubscribe {
    this.onJsonSet.add(fn);
    return () => this.onJsonSet.delete(fn);
  }

  subscribeRaw(fn: (ev: MessageEvent) => void): Unsubscribe {
    this.onRawSet.add(fn);
    return () => this.onRawSet.delete(fn);
  }

  subscribeError(fn: (e: Event) => void): Unsubscribe {
    this.onErrorSet.add(fn);
    return () => this.onErrorSet.delete(fn);
  }
}

// 全局单例池：同一个 url 只有一个 WS
const channels = new Map<string, Channel>();

export function getWsChannel(urlOrPath: string) {
  const url = normalizeWsUrl(urlOrPath);
  let ch = channels.get(url);
  if (!ch) {
    ch = new Channel(url);
    channels.set(url, ch);
  }
  return ch;
}

// 兼容旧代码
export function createWsClient(urlOrPath: string) {
  return new WebSocket(normalizeWsUrl(urlOrPath));
}
export function createWs(urlOrPath: string) {
  return createWsClient(urlOrPath);
}
