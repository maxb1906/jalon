// Types miroirs du JSON produit par le moteur Go (internal/model, internal/engine).
export type Status = 'ok' | 'info' | 'warn' | 'fail' | 'skipped'

export type Msg = { key: string; args?: string[] }
export type Note = { status: Status; msg: Msg }
export type KV = { label: string; value: string }

export type Base = { status: Status; summary: Msg; notes?: Note[]; duration_ms: number }
export type Step = Base & { id: string; layer: string }

export type Hop = {
  ttl: number; addr?: string; others?: string[]; name?: string; asn?: string
  sent: number; recv: number; loss_pct: number; min_ms: number; avg_ms: number; max_ms: number; jitter_ms: number
  reached?: boolean; unreachable?: boolean; silent?: boolean
}
export type Trace = Base & {
  mode: 'icmp' | 'tcp'; method?: string; dest: string; port?: number; hops?: Hop[]
  reached: boolean; last_hop: number; loss_from?: number; loop?: boolean; available: boolean; error?: string
}

export type Finding = { rule: string; severity: Status; layer: string; msg: Msg; advice?: Msg }
export type Verdict = { status: Status; headline: Msg; findings?: Finding[] }
export type Change = { kind: string; severity: Status; msg: Msg }
export type Comparison = { previous_id: string; previous_time: string; same_network: boolean; changes?: Change[] }

export type Timings = { dns_ms: number; tcp_ms: number; tls_ms: number; ttfb_ms: number; total_ms: number }

export type TargetReport = {
  target: { raw: string; scheme: string; host: string; port: number; proto: string }
  started: string; finished: string; error?: string
  dns?: Base & { name: string; ipv4?: string[]; ipv6?: string[] }
  tcp?: (Base & { family: string; ip?: string; port: number; outcome: string; rtt_ms?: number })[]
  tls?: Base & { version: string; cipher: string; alpn?: string; handshake_ms: number; days_left: number; intercepted?: boolean; intercept_issuer?: string; chain?: { subject: string; issuer: string; not_after: string }[] }
  http?: Base & { url: string; proto?: string; code?: number; timings: Timings; final_url?: string }
  http3?: Base & { attempted: boolean; advertised: boolean; ok: boolean }
  proto?: Base & { proto: string; banner?: string }
  traces?: Trace[]
  proxy?: Base
  chosen_ip?: string
  verdict: Verdict
  compare?: Comparison
  history_id?: string
}

export type Env = Base & {
  hostname: string; os: string
  ifaces?: { name: string; addrs: string[]; mtu: number; default: boolean }[]
  local_ipv4?: string; local_ipv6?: string; gateways?: string[]; dns_servers?: string[]
  proxies?: { source: string; value: string }[]; pac?: string; wpad?: string
  gateway_ping?: { target: string; sent: number; recv: number; avg_ms: number; error?: string }
  privileges: { admin: boolean; icmp_trace: boolean; tcp_trace: boolean; icmp_reason?: Msg; tcp_reason?: Msg }
  public_ip?: string
}

export type Report = {
  tool: string; version: string; lang: string; started: string; finished: string
  env?: Env; dns_global?: Base; captive?: Base
  targets: (TargetReport | null)[]
  status: Status; exit_code: number
}

export type EngineEvent = {
  type: 'run_start' | 'global_step' | 'target_start' | 'step_start' | 'step' | 'trace_update' | 'target_done' | 'run_done'
  target: number; raw?: string; step_id?: string; step?: Step; trace?: Trace
  report?: TargetReport; run?: Report; targets?: string[]
}

export type Info = {
  version: string; lang: string; os: string; history_dir: string; history: boolean
  protos: string[]; proto: string; trace_mode: string; no_trace: boolean
}

export type RunRequest = {
  targets: string; proto: string; trace_mode: string; no_trace: boolean; ipv4: boolean; ipv6: boolean; lang: string
}

export type HistoryItem = {
  id: string; time: string; raw: string; target_key: string; network: string; status: Status; headline: Msg; text: string
}

export type DiffResult = {
  from: string; to: string; from_raw: string; to_raw: string; from_time: string; to_time: string
  same_target: boolean; same_network: boolean; from_verdict: string; to_verdict: string
  from_status: Status; to_status: Status
  changes: (Change & { text: string })[]
}
