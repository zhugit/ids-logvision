export type WsState = "connected" | "connecting" | "disconnected";

export type RawLog = {
  id: number | string;
  source: string;
  host: string;
  level: string;
  message: string;
  created_at?: string;
};

export type AlertRow = {
  id: number;
  alert_type: string;
  severity: string;
  attack_ip: string;
  host: string;
  count: number;
  window_seconds: number;
  evidence: any; // 后端可能是 list/str，都兼容
  created_at: string;
};
