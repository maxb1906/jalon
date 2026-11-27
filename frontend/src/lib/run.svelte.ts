// État du diagnostic affiché : alimenté en direct par les événements du
// moteur, ou reconstitué à partir d'un diagnostic de l'historique.
import type { EngineEvent, Env, Report, Status, Step, Trace, TargetReport } from './types'

export type TargetState = {
  raw: string
  steps: Step[]
  running: string | null
  traces: Trace[]
  report: TargetReport | null
}

export const run = $state({
  id: '',
  active: false,
  cancelling: false,
  source: 'none' as 'none' | 'live' | 'history',
  historyId: '',
  started: '',
  global: [] as Step[],
  globalRunning: [] as string[],
  targets: [] as TargetState[],
  env: null as Env | null,
  report: null as Report | null,
  selected: 0,
})

export function resetLive(id: string) {
  run.id = id
  run.active = true
  run.cancelling = false
  run.source = 'live'
  run.historyId = ''
  run.started = new Date().toISOString()
  run.global = []
  run.globalRunning = []
  run.targets = []
  run.env = null
  run.report = null
  run.selected = 0
}

function upsertTrace(list: Trace[], tr: Trace) {
  const i = list.findIndex((x) => x.mode === tr.mode)
  if (i >= 0) list[i] = tr
  else list.push(tr)
}

export function onEngineEvent(e: EngineEvent) {
  switch (e.type) {
    case 'run_start':
      run.targets = (e.targets || []).map((raw) => ({ raw, steps: [], running: null, traces: [], report: null }))
      break
    case 'step_start':
      if (e.target < 0) run.globalRunning = [...run.globalRunning, e.step_id || '']
      else if (run.targets[e.target]) run.targets[e.target].running = e.step_id || null
      break
    case 'step':
      if (!e.step) break
      if (e.target < 0) {
        run.global = [...run.global, e.step]
        run.globalRunning = run.globalRunning.filter((id) => id !== e.step!.id)
      } else if (run.targets[e.target]) {
        const ts = run.targets[e.target]
        ts.steps = [...ts.steps, e.step]
        ts.running = null
      }
      break
    case 'trace_update':
      if (e.trace && run.targets[e.target]) upsertTrace(run.targets[e.target].traces, e.trace)
      break
    case 'target_done':
      if (e.report && run.targets[e.target]) {
        const ts = run.targets[e.target]
        ts.report = e.report
        ts.running = null
        ts.steps = stepsOf(e.report)
        ts.traces = (e.report.traces || []).slice()
      }
      break
    case 'run_done':
      run.active = false
      run.cancelling = false
      if (e.run) {
        run.report = e.run
        run.env = e.run.env || null
        run.global = globalSteps(e.run)
        run.globalRunning = []
      }
      break
  }
}

// Diagnostic tiré de l'historique : affiché comme un diagnostic terminé.
export function loadReport(rep: Report, historyId: string) {
  run.id = ''
  run.active = false
  run.cancelling = false
  run.source = 'history'
  run.historyId = historyId
  run.started = rep.started
  run.report = rep
  run.env = rep.env || null
  run.global = globalSteps(rep)
  run.globalRunning = []
  run.targets = rep.targets.filter((t): t is TargetReport => !!t).map((r) => ({
    raw: r.target.raw, steps: stepsOf(r), running: null, traces: (r.traces || []).slice(), report: r,
  }))
  run.selected = 0
}

function step(id: string, layer: string, b: any): Step {
  return { id, layer, status: b.status, summary: b.summary, notes: b.notes, duration_ms: b.duration_ms }
}

// stepsOf reprend l'ordre de model.TargetReport.Steps.
export function stepsOf(r: TargetReport): Step[] {
  const s: Step[] = []
  if (r.dns) s.push(step('dns', 'layer.dns', r.dns))
  for (const t of r.tcp || []) s.push(step('tcp_' + t.family, 'layer.tcp_' + t.family, t))
  if (r.tls) s.push(step('tls', 'layer.tls', r.tls))
  if (r.http) s.push(step('http', 'layer.http', r.http))
  if (r.http3) s.push(step('http3', 'layer.http3', r.http3))
  if (r.proto) s.push(step('proto', 'layer.proto.' + r.proto.proto, r.proto))
  if (r.proxy) s.push(step('proxy', 'layer.proxy', r.proxy))
  for (const t of r.traces || []) s.push(step('trace_' + t.mode, 'layer.trace_' + t.mode, t))
  return s
}

export function globalSteps(rep: Report): Step[] {
  const s: Step[] = []
  if (rep.env) s.push(step('env', 'layer.env', rep.env))
  if (rep.dns_global) s.push(step('dns_global', 'layer.dns_global', rep.dns_global))
  if (rep.captive) s.push(step('captive', 'layer.captive', rep.captive))
  return s
}

const rank: Record<string, number> = { skipped: 0, ok: 1, info: 2, warn: 3, fail: 4 }
export function worst(...ss: (Status | undefined)[]): Status {
  let w: Status = 'skipped'
  for (const s of ss) if (s && rank[s] > rank[w]) w = s
  return w
}

// layerStatus reprend model.TargetReport.LayerStatus (tableau de synthèse).
export function layerStatus(r: TargetReport): Record<'dns' | 'tcp' | 'tls' | 'app' | 'trace', Status> {
  const m = { dns: 'skipped', tcp: 'skipped', tls: 'skipped', app: 'skipped', trace: 'skipped' } as Record<'dns' | 'tcp' | 'tls' | 'app' | 'trace', Status>
  if (r.dns) m.dns = r.dns.status
  const tcp = (r.tcp || []).map((t) => t.status)
  if (tcp.includes('ok')) {
    const w = worst(...tcp)
    m.tcp = w === 'fail' || w === 'warn' ? 'warn' : 'ok'
  } else if (tcp.length) m.tcp = worst(...tcp)
  if (r.tls) m.tls = r.tls.status
  if (r.http) {
    let app = r.http.status
    if (r.http3 && r.http3.status === 'warn' && app === 'ok') app = 'warn'
    m.app = app
  } else if (r.proto) m.app = r.proto.status
  const tr = (r.traces || []).map((t) => t.status)
  if (tr.length) m.trace = worst(...tr)
  return m
}

// Statut provisoire par couche d'une cible en cours, d'après les étapes déjà
// publiées ; null = couche pas encore connue.
export function partialLayerStatus(ts: TargetState): Record<'dns' | 'tcp' | 'tls' | 'app' | 'trace', Status | null> {
  const of = (pred: (id: string) => boolean) => {
    const ss = ts.steps.filter((s) => pred(s.id)).map((s) => s.status)
    return ss.length ? worst(...ss) : null
  }
  return {
    dns: of((id) => id === 'dns'),
    tcp: of((id) => id.startsWith('tcp_')),
    tls: of((id) => id === 'tls'),
    app: of((id) => id === 'http' || id === 'http3' || id === 'proto'),
    trace: of((id) => id.startsWith('trace_')),
  }
}

// Statut provisoire d'une cible en cours : le pire des étapes déjà connues.
export function targetStatus(ts: TargetState): Status {
  if (ts.report) return ts.report.verdict.status
  return worst(...ts.steps.map((s) => s.status))
}
