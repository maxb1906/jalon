<script lang="ts">
  import { t, tr } from '../lib/i18n.svelte'
  import type { Trace } from '../lib/types'
  import StatusIcon from './StatusIcon.svelte'

  let { traces, live }: { traces: Trace[]; live: boolean } = $props()
  const shown = $derived(traces.filter((x) => x.available || x.hops?.length))
  let mode = $state<string>('')
  const cur = $derived(shown.find((x) => x.mode === mode) || shown[0])
  const maxAvg = $derived(Math.max(1, ...(cur?.hops || []).map((h) => (h.recv ? h.max_ms : 0))))
  const n = (v: number, recv: number) => (recv ? v.toFixed(1) : '–')
</script>

{#if cur}
  <div class="card">
    <div class="card-head">
      <h3>{t('gui.path')}</h3>
      <div class="tabs">
        {#if live}<span class="live small"><span class="dot"></span>{t('tui.live')}</span>{/if}
        {#each shown as x}
          <button class="ghost tab" class:on={x.mode === cur.mode} onclick={() => (mode = x.mode)}>
            <StatusIcon status={x.status} size={13} /> {x.mode === 'icmp' ? 'ICMP' : 'TCP SYN'}
          </button>
        {/each}
      </div>
    </div>
    {#if cur.summary?.key}<p class="sum">{tr(cur.summary)}</p>{/if}
    <table>
      <thead>
        <tr><th class="num">#</th><th>{t('hop.host')}</th><th class="num">{t('hop.loss')}</th><th class="num">min</th><th class="num">{t('hop.avg')}</th><th class="num">max</th><th class="num">{t('hop.jitter')}</th><th class="lat"></th></tr>
      </thead>
      <tbody>
        {#each cur.hops || [] as h (h.ttl)}
          <tr class:silent={!h.recv} class:lossfrom={cur.loss_from && h.ttl >= cur.loss_from}>
            <td class="num mut">{h.ttl}</td>
            <td class="host">
              {#if h.addr}
                {#if h.name}<span>{h.name}</span> <span class="mono mut">{h.addr}</span>{:else}<span class="mono">{h.addr}</span>{/if}
                {#if h.asn}<span class="pill bg-skipped">{h.asn}</span>{/if}
                {#if h.reached}<span class="pill bg-ok">{t('gui.dest')}</span>{/if}
              {:else}<span class="mut">* * *</span>{/if}
            </td>
            <td class="num" class:s-fail={h.loss_pct >= 50 && h.recv < h.sent} class:s-warn={h.loss_pct > 0 && h.loss_pct < 50}>{h.sent ? h.loss_pct.toFixed(0) + ' %' : '–'}</td>
            <td class="num">{n(h.min_ms, h.recv)}</td>
            <td class="num"><b>{n(h.avg_ms, h.recv)}</b></td>
            <td class="num">{n(h.max_ms, h.recv)}</td>
            <td class="num mut">{n(h.jitter_ms, h.recv)}</td>
            <td class="lat">
              {#if h.recv}
                <div class="lbar"><div class="rng" style="left:{(h.min_ms / maxAvg) * 100}%;width:{Math.max(1.5, ((h.max_ms - h.min_ms) / maxAvg) * 100)}%"></div><div class="avg" style="left:{(h.avg_ms / maxAvg) * 100}%"></div></div>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if cur.error}<p class="small s-warn">{cur.error}</p>{/if}
  </div>
{/if}

<style>
  .tabs { display: flex; gap: 4px; align-items: center; }
  .tab { padding: 3px 9px; font-size: 12.5px; color: var(--fg-2); }
  .tab.on { background: var(--accent-bg); color: var(--accent); font-weight: 600; }
  .live { display: inline-flex; align-items: center; gap: 6px; color: var(--fail); font-weight: 600; margin-right: 6px; }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--fail); animation: pulse 1.2s ease-in-out infinite; }
  @keyframes pulse { 50% { opacity: .25; } }
  .sum { margin: 0 0 8px; color: var(--fg-2); }
  table { font-size: 13px; }
  td { padding: 4px 8px; }
  .host { word-break: break-all; }
  .host .pill { margin-left: 4px; font-size: 11px; }
  tr.silent td { color: var(--mut); }
  tr.lossfrom td:first-child { box-shadow: inset 3px 0 0 var(--fail); }
  th.lat, td.lat { width: 22%; min-width: 120px; }
  .lbar { position: relative; height: 8px; margin-top: 6px; background: var(--panel-2); border-radius: 4px; }
  .rng { position: absolute; top: 0; bottom: 0; background: color-mix(in srgb, var(--accent) 35%, transparent); border-radius: 4px; }
  .avg { position: absolute; top: -2px; bottom: -2px; width: 3px; margin-left: -1.5px; background: var(--accent); border-radius: 2px; }
</style>
