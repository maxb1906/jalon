// Traductions : le catalogue vient de Go (internal/i18n), une seule source
// pour la CLI, l'UI web et l'interface graphique.
import type { Msg } from './types'

export const i18n = $state({ lang: 'fr', cat: {} as Record<string, string> })

// tr rend un message {key, args} comme côté Go (%s, %%, argument « @clé »).
export function tr(m: Msg | null | undefined): string {
  if (!m || !m.key) return ''
  const f = i18n.cat[m.key]
  const args = m.args || []
  if (f === undefined) return [m.key, ...args].join(' ')
  let i = 0
  return f
    .split('%%')
    .map((part) =>
      part.replace(/%s/g, () => {
        let a = args[i++] ?? ''
        if (a.length > 1 && a[0] === '@' && i18n.cat[a.slice(1)] !== undefined) a = i18n.cat[a.slice(1)]
        return a
      }),
    )
    .join('%')
}

// t traduit une clé littérale (vérifiée par TestFrontendKeysExist).
export function t(key: string, ...args: (string | number)[]): string {
  return tr({ key, args: args.map(String) })
}

export function fmtDate(iso: string): string {
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return d.toLocaleString(i18n.lang === 'en' ? 'en-GB' : 'fr-BE', { dateStyle: 'short', timeStyle: 'medium' })
}

export function ms(v: number | undefined): string {
  if (v === undefined || v === null) return '–'
  if (v >= 1000) return (v / 1000).toFixed(2) + ' s'
  return (v < 10 ? v.toFixed(1) : Math.round(v).toString()) + ' ms'
}
