// Backend de démonstration (npm run dev uniquement) : rejoue un diagnostic
// enregistré (report.json, données fictives) comme le ferait le moteur Go.
// Catalogues : « go run ./tools/guimock ».
import type { Backend } from '../api'
import { mockBus } from '../api'
import type { EngineEvent, Report, Step } from '../types'
import { stepsOf, globalSteps } from '../run.svelte'
import fixture from './report.json'

const catalogs = import.meta.glob('./catalog.*.json', { eager: true, import: 'default' }) as Record<string, Record<string, string>>
const rep = fixture as unknown as Report
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
let cancelled = false
let running = false

async function replay(id: string, raws: string[]) {
  running = true
  cancelled = false
  const send = (event: EngineEvent) => mockBus.emit('jalon:event', { run: id, event })
  const targets = raws.map((raw, i) => {
    const tr = structuredClone(rep.targets[i % rep.targets.length]!)
    tr.target.raw = raw
    return tr
  })
  send({ type: 'run_start', target: -1, targets: raws })
  for (const s of globalSteps(rep)) {
    send({ type: 'step_start', target: -1, step_id: s.id })
    await sleep(350)
    send({ type: 'step', target: -1, step: s })
  }
  await Promise.all(targets.map(async (tr, i) => {
    send({ type: 'target_start', target: i, raw: tr.target.raw })
    for (const s of stepsOf(tr) as Step[]) {
      if (cancelled) break
      send({ type: 'step_start', target: i, step_id: s.id.startsWith('tcp') ? 'tcp' : s.id.startsWith('trace') ? 'trace' : s.id })
      if (s.id === 'trace_icmp') {
        const full = tr.traces!.find((x) => x.mode === 'icmp')!
        for (let n = 1; n <= (full.hops?.length || 0); n++) {
          await sleep(260)
          send({ type: 'trace_update', target: i, trace: { ...full, hops: full.hops!.slice(0, n) } })
        }
      }
      await sleep(300 + Math.random() * 500)
      send({ type: 'step', target: i, step: s })
    }
    send({ type: 'target_done', target: i, report: tr })
  }))
  const run = { ...rep, targets, started: new Date().toISOString() }
  send({ type: 'run_done', target: -1, run })
  running = false
}

const history = rep.targets.map((t, i) => ({
  id: '2026112' + (6 - i) + '-0930' + i + '-demo', time: new Date(Date.now() - (i + 1) * 3.6e6).toISOString(),
  raw: t!.target.raw, target_key: t!.target.raw, network: 'demo', status: t!.verdict.status, headline: t!.verdict.headline, text: '',
}))

export const mock: Backend = {
  async Init() {
    return { version: 'dev', lang: 'fr', os: 'demo', history_dir: '/demo/jalon-history', history: true,
      protos: ['http', 'https', 'smtp', 'imap', 'pop3', 'ssh', 'rdp', 'ldap', 'ftp', 'banner'], proto: '', trace_mode: 'auto', no_trace: false }
  },
  async Strings(lang) {
    return catalogs['./catalog.' + lang + '.json'] || {}
  },
  async Start(req) {
    if (running) throw 'busy'
    const raws = req.targets.split(/[\n,]/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#'))
    if (!raws.length) throw 'aucune cible'
    const id = Math.random().toString(16).slice(2, 14)
    setTimeout(() => replay(id, raws), 0)
    return id
  },
  async Cancel() { cancelled = true },
  async Running() { return running },
  async Ticket() { return 'Jalon — démonstration\n' },
  async ReportHTML() { return '<!doctype html><meta charset="utf-8"><body style="font:14px system-ui;padding:24px"><h1>Rapport (démonstration)</h1><p>Le rapport HTML réel est produit par Go.</p></body>' },
  async Export(_id, format) { return '/demo/jalon-demo.' + format },
  async OpenReport() { return '/demo/jalon-demo.html' },
  async History(filter) {
    const tr = (m: any) => { const c = catalogs['./catalog.fr.json'] || {}; let i = 0; return (c[m.key] || m.key).replace(/%s/g, () => (m.args || [])[i++] ?? '') }
    return history.filter((h) => h.raw.includes(filter)).map((h) => ({ ...h, text: tr(h.headline) }))
  },
  async LoadHistory(id) {
    const i = history.findIndex((h) => h.id === id)
    return { ...rep, started: history[i].time, targets: [rep.targets[i]] }
  },
  async Diff(a, b) {
    const A = history.find((h) => h.id === a)!, B = history.find((h) => h.id === b)!
    return { from: A.id, to: B.id, from_raw: A.raw, to_raw: B.raw, from_time: A.time, to_time: B.time,
      same_target: A.raw === B.raw, same_network: true, from_verdict: A.text || A.headline.key, to_verdict: B.text || B.headline.key,
      from_status: A.status, to_status: B.status, changes: [] }
  },
  async OpenHistoryDir() {},
}
