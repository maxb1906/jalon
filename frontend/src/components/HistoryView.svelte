<script lang="ts">
  import { i18n, t, fmtDate } from '../lib/i18n.svelte'
  import { api, errText } from '../lib/api'
  import { toast } from '../lib/toast.svelte'
  import type { DiffResult, HistoryItem, Info } from '../lib/types'
  import StatusIcon from './StatusIcon.svelte'

  let { info, onshow, onreport }: { info: Info; onshow: (id: string) => void; onreport: (id: string, title: string) => void } = $props()

  let q = $state('')
  let list = $state<HistoryItem[]>([])
  let loading = $state(true)
  let selected = $state<string[]>([])
  let diff = $state<DiffResult | null>(null)

  async function load() {
    loading = true
    try {
      list = await (await api()).History(q)
    } catch (e) {
      toast(errText(e), 'fail')
    }
    loading = false
    selected = selected.filter((id) => list.some((m) => m.id === id))
  }

  let timer: ReturnType<typeof setTimeout> | undefined
  $effect(() => {
    // recharge aussi au changement de langue (verdicts traduits côté Go)
    q
    i18n.lang
    clearTimeout(timer)
    timer = setTimeout(load, 150)
    return () => clearTimeout(timer)
  })

  function toggle(id: string) {
    if (selected.includes(id)) selected = selected.filter((x) => x !== id)
    else selected = [...selected.slice(-1), id]
    diff = null
  }

  async function compare() {
    try {
      diff = await (await api()).Diff(selected[0], selected[1])
    } catch (e) {
      toast(errText(e), 'fail')
    }
  }

  async function openDir() {
    try { await (await api()).OpenHistoryDir() } catch (e) { toast(errText(e), 'fail') }
  }
</script>

<div class="hv">
  <div class="card">
    <div class="card-head">
      <div class="tools">
        <input type="search" placeholder={t('web.filter')} bind:value={q} />
        <button class="primary" disabled={selected.length !== 2} onclick={compare}>{t('web.compare')}</button>
      </div>
      {#if info.history}
        <button class="ghost small" onclick={openDir} title={info.history_dir}>{t('gui.open_folder')}</button>
      {/if}
    </div>

    {#if !info.history}
      <p class="mut">{t('gui.history_off')}</p>
    {:else if !loading && !list.length}
      <div class="empty mut">{q ? t('gui.no_match') : t('cli.history_empty')}</div>
    {:else}
      <table>
        <thead><tr><th class="cb"></th><th>{t('web.date')}</th><th>{t('col.target')}</th><th>{t('col.verdict')}</th><th></th></tr></thead>
        <tbody>
          {#each list as m (m.id)}
            <tr class:sel={selected.includes(m.id)}>
              <td class="cb"><input type="checkbox" checked={selected.includes(m.id)} onchange={() => toggle(m.id)} aria-label={m.id} /></td>
              <td class="nowrap">{fmtDate(m.time)}</td>
              <td class="mono tgt">{m.raw}</td>
              <td><span class="vd"><StatusIcon status={m.status} size={14} /> {m.text}</span></td>
              <td class="acts nowrap">
                <button class="ghost small" onclick={() => onshow(m.id)}>{t('gui.show')}</button>
                <button class="ghost small" onclick={() => onreport(m.id, m.raw + ' — ' + fmtDate(m.time))}>{t('web.open')}</button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
      <p class="small mut foot">{t('gui.compare_hint')}</p>
    {/if}
  </div>

  {#if diff}
    <div class="card">
      <div class="card-head"><h3>{t('gui.comparison')}</h3><button class="ghost small" onclick={() => (diff = null)}>×</button></div>
      <div class="dhead">
        <div class="side"><div class="mut small">{fmtDate(diff.from_time)}</div><div class="mono">{diff.from_raw}</div><div class="vd"><StatusIcon status={diff.from_status} size={14} /> {diff.from_verdict}</div></div>
        <div class="arrow">→</div>
        <div class="side"><div class="mut small">{fmtDate(diff.to_time)}</div><div class="mono">{diff.to_raw}</div><div class="vd"><StatusIcon status={diff.to_status} size={14} /> {diff.to_verdict}</div></div>
      </div>
      {#if !diff.same_target}<p class="s-warn">{t('cli.diff_other_target')}</p>{/if}
      {#if !diff.same_network}<p class="mut">{t('text.other_network')}</p>{/if}
      {#if !diff.changes.length}
        <p class="mut">{t('text.no_changes')}</p>
      {:else}
        <ul>{#each diff.changes as c}<li><StatusIcon status={c.severity} size={13} /> <span>{c.text}</span></li>{/each}</ul>
      {/if}
    </div>
  {/if}
</div>

<style>
  .hv { display: flex; flex-direction: column; gap: 14px; max-width: 1200px; margin: 0 auto; width: 100%; }
  .hv :global(.card + .card) { margin-top: 0; }
  .tools { display: flex; gap: 8px; }
  .tools input { width: 280px; }
  .cb { width: 28px; }
  .nowrap { white-space: nowrap; }
  .tgt { word-break: break-all; }
  .vd { display: inline-flex; gap: 6px; align-items: baseline; }
  .vd :global(.si) { flex: none; transform: translateY(2px); }
  tr.sel td { background: var(--accent-bg); }
  .acts { text-align: right; }
  .acts button { padding: 2px 8px; color: var(--accent); }
  .empty { padding: 30px; text-align: center; }
  .foot { margin: 10px 0 0; }
  .dhead { display: grid; grid-template-columns: 1fr auto 1fr; gap: 14px; align-items: center; padding: 6px 0 12px; border-bottom: 1px solid var(--line); margin-bottom: 10px; }
  .side { display: flex; flex-direction: column; gap: 2px; }
  .arrow { font-size: 20px; color: var(--mut); }
  p { margin: 0 0 6px; }
  ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
  li { display: flex; gap: 7px; align-items: baseline; }
  li :global(.si) { flex: none; transform: translateY(1px); }
</style>
