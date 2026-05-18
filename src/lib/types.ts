export interface LogEntry {
  ts: string;
  event: string;
  [key: string]: unknown;
}

export interface CfInfo {
  colo: string;
  country: string;
  asn: number;
}

export interface Target {
  ip: string;
  port: number;
  label: string;
}
