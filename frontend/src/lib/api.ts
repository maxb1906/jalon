// Accès au backend Go (méthodes liées par Wails sur window.go.gui.App).
// Hors Wails (npm run dev), un backend de démonstration rejoue un diagnostic.
import type { DiffResult, HistoryItem, Info, Report, RunRequest } from './types'

export type Backend = {
  Init(): Promise<Info>
  Strings(lang: string): Promise<Record<string, string>>
  Start(req: RunRequest): Promise<string>
  Cancel(): Promise<void>
  Running(): Promise<boolean>
  Ticket(id: string): Promise<string>
  ReportHTML(id: string): Promise<string>
  Export(id: string, format: string): Promise<string>
  OpenReport(id: string): Promise<string>
  History(filter: string): Promise<HistoryItem[]>
  LoadHistory(id: string): Promise<Report>
  Diff(a: string, b: string): Promise<DiffResult>
  OpenHistoryDir(): Promise<void>
}

const w = window as any
export const isWails = typeof w.go?.gui?.App !== 'undefined'

let backend: Backend | null = null

export async function api(): Promise<Backend> {
  if (backend) return backend
  if (isWails) backend = w.go.gui.App as Backend
  else if (import.meta.env.DEV) backend = (await import('./mock/mock')).mock
  else throw new Error('backend unavailable')
  return backend!
}

export function onEvent(name: string, cb: (data: any) => void): () => void {
  if (w.runtime?.EventsOn) return w.runtime.EventsOn(name, cb)
  return mockBus.on(name, cb)
}

export function emit(name: string, data?: unknown) {
  if (w.runtime?.EventsEmit) w.runtime.EventsEmit(name, data)
}

export async function copyText(text: string): Promise<boolean> {
  try {
    if (w.runtime?.ClipboardSetText) return await w.runtime.ClipboardSetText(text)
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

// Bus d'évènements du mode démonstration.
export const mockBus = (() => {
  const subs: Record<string, ((d: any) => void)[]> = {}
  return {
    on(name: string, cb: (d: any) => void) {
      ;(subs[name] ||= []).push(cb)
      return () => { subs[name] = subs[name].filter((f) => f !== cb) }
    },
    emit(name: string, d: any) { (subs[name] || []).forEach((f) => f(d)) },
  }
})()

// Message d'une erreur renvoyée par Go (chaîne) ou JS.
export function errText(e: unknown): string {
  if (typeof e === 'string') return e
  if (e instanceof Error) return e.message
  return String(e)
}
