<script lang="ts">
  import { t } from '../lib/i18n.svelte'
  import { run, layerStatus, partialLayerStatus, targetStatus } from '../lib/run.svelte'
  import StatusIcon from './StatusIcon.svelte'
  import { tr } from '../lib/i18n.svelte'

  const cols = ['dns', 'tcp', 'tls', 'app', 'trace'] as const
</script>

<div class="card syn">
  <table>
    <thead>
      <tr><th>{t('col.target')}</th>{#each cols as c}<th class="c">{t('col.' + c)}</th>{/each}<th>{t('col.verdict')}</th></tr>
    </thead>
    <tbody>
      {#each run.targets as ts, i}
        {@const ls = ts.report ? layerStatus(ts.report) : partialLayerStatus(ts)}
        <tr class:sel={i === run.selected} onclick={() => (run.selected = i)}>
          <td class="mono tgt">{ts.raw}</td>
          {#each cols as c}
            <td class="c">{#if ls[c]}<StatusIcon status={ls[c] ?? undefined} size={14} />{:else if run.active}<span class="dot"></span>{:else}<span class="mut">–</span>{/if}</td>
          {/each}
          <td>
            {#if ts.report}<span class="vd"><StatusIcon status={targetStatus(ts)} size={14} /> {tr(ts.report.verdict.headline)}</span>
            {:else if run.active}<span class="mut"><span class="spin s-info"></span> {t('gui.in_progress')}</span>{:else}<span class="mut">{t('gui.interrupted')}</span>{/if}
          </td>
        </tr>
      {/each}
    </tbody>
  </table>
</div>

<style>
  .syn { padding: 6px 8px; }
  tr { cursor: pointer; }
  tbody tr:hover td { background: var(--panel-2); }
  tr.sel td { background: var(--accent-bg) !important; }
  tr.sel td:first-child { box-shadow: inset 3px 0 0 var(--accent); }
  .c { text-align: center; width: 64px; }
  .tgt { word-break: break-all; max-width: 260px; }
  .vd { display: inline-flex; gap: 6px; align-items: baseline; }
  .vd :global(.si) { flex: none; transform: translateY(2px); }
  td { vertical-align: middle; }
  .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: var(--line-2); }
</style>
