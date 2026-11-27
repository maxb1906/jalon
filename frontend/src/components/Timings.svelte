<script lang="ts">
  import { t, ms } from '../lib/i18n.svelte'
  import type { Timings } from '../lib/types'

  let { timings, proto, code }: { timings: Timings; proto?: string; code?: number } = $props()
  const parts = $derived([
    { k: 'dns', label: 'DNS', v: timings.dns_ms },
    { k: 'tcp', label: 'TCP', v: timings.tcp_ms },
    { k: 'tls', label: 'TLS', v: timings.tls_ms },
    { k: 'ttfb', label: 'TTFB', v: timings.ttfb_ms },
  ].filter((p) => p.v > 0))
  const total = $derived(Math.max(timings.total_ms, parts.reduce((a, p) => a + p.v, 0), 0.001))
</script>

{#if timings.total_ms > 0}
  <div class="card">
    <div class="card-head">
      <h3>{t('gui.timings')}</h3>
      <span class="mut small">{proto ? proto.toUpperCase() : ''}{code ? ' · ' + code : ''} · {t('gui.total')} {ms(timings.total_ms)}</span>
    </div>
    <div class="bar">
      {#each parts as p}
        <div class="seg c-{p.k}" style="flex-grow:{p.v / total}" title="{p.label} {ms(p.v)}"></div>
      {/each}
      <div class="seg rest" style="flex-grow:{Math.max(0, total - parts.reduce((a, p) => a + p.v, 0)) / total}"></div>
    </div>
    <div class="legend">
      {#each parts as p}
        <span><i class="c-{p.k}"></i>{p.label} <b>{ms(p.v)}</b></span>
      {/each}
    </div>
  </div>
{/if}

<style>
  .bar { display: flex; height: 14px; border-radius: 4px; overflow: hidden; background: var(--panel-2); gap: 2px; }
  .seg { min-width: 3px; flex-basis: 0; }
  .seg.rest { min-width: 0; background: var(--line); }
  .legend { display: flex; gap: 18px; margin-top: 8px; font-size: 12.5px; color: var(--fg-2); flex-wrap: wrap; }
  .legend i { display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 6px; vertical-align: -1px; }
  .legend b { color: var(--fg); font-weight: 600; font-variant-numeric: tabular-nums; }
  .c-dns { background: #7c5cd6; } .c-tcp { background: #2f80d1; } .c-tls { background: #18a39a; } .c-ttfb { background: #e08a1e; }
</style>
