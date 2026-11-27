<script lang="ts">
  import { t, tr, fmtDate } from '../lib/i18n.svelte'
  import type { Comparison } from '../lib/types'
  import StatusIcon from './StatusIcon.svelte'

  let { compare }: { compare: Comparison } = $props()
  const ch = $derived(compare.changes || [])
</script>

<div class="card">
  <div class="card-head">
    <h3>{t('gui.changes')}</h3>
    <span class="mut small">{t('gui.since', fmtDate(compare.previous_time))}{compare.same_network ? '' : ' ' + t('text.other_network')}</span>
  </div>
  {#if !ch.length}
    <p class="mut">{t('text.no_changes')}</p>
  {:else}
    <ul>
      {#each ch as c}<li><StatusIcon status={c.severity} size={13} /> <span>{tr(c.msg)}</span></li>{/each}
    </ul>
  {/if}
</div>

<style>
  p { margin: 0; }
  ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 4px; }
  li { display: flex; gap: 7px; align-items: baseline; }
  li :global(.si) { flex: none; transform: translateY(1px); }
</style>
