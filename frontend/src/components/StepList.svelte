<script lang="ts">
  import { t, tr, ms } from '../lib/i18n.svelte'
  import type { Step } from '../lib/types'
  import StatusIcon from './StatusIcon.svelte'

  let { steps, running = [] as string[], compact = false }: { steps: Step[]; running?: string[]; compact?: boolean } = $props()

  // Étapes dépliées (par défaut : celles qui posent problème).
  let open = $state<Record<string, boolean>>({})
  const isOpen = (s: Step) => open[s.id] ?? (s.status === 'warn' || s.status === 'fail')

  function runningLabel(id: string): string {
    if (id === 'tcp') return t('col.tcp')
    if (id === 'proto') return t('col.app')
    if (id === 'trace') return t('col.trace')
    return t('layer.' + id)
  }
</script>

<div class="steps" class:compact>
  {#each steps as s (s.id)}
    {@const notes = s.notes || []}
    {@const expanded = isOpen(s)}
    <div class="step" class:exp={expanded}>
      <button class="row ghost" onclick={() => (open[s.id] = !expanded)} disabled={!notes.length} aria-expanded={expanded}>
        <StatusIcon status={s.status} />
        <span class="layer">{tr({ key: s.layer })}</span>
        <span class="sum s-{s.status === 'ok' ? 'x' : s.status}">{tr(s.summary)}</span>
        <span class="dur mut">{s.duration_ms ? ms(s.duration_ms) : ''}</span>
        <span class="chev mut" class:none={!notes.length} class:open={expanded}>›</span>
      </button>
      {#if expanded && notes.length}
        <ul class="notes">
          {#each notes as n}
            <li class:info={n.status === 'info'}><StatusIcon status={n.status} size={13} /> <span>{tr(n.msg)}</span></li>
          {/each}
        </ul>
      {/if}
    </div>
  {/each}
  {#each running as id (id)}
    <div class="step">
      <div class="row pending">
        <span class="spin s-info"></span>
        <span class="layer">{runningLabel(id)}</span>
        <span class="sum mut">{t('gui.in_progress')}</span>
      </div>
    </div>
  {/each}
</div>

<style>
  .steps { display: flex; flex-direction: column; }
  .step { border-bottom: 1px solid var(--line); }
  .step:last-child { border-bottom: 0; }
  .row { width: 100%; display: grid; grid-template-columns: 18px 11.5em 1fr auto 12px; align-items: baseline; gap: 10px; padding: 8px 4px; border: 0; border-radius: 6px; text-align: left; white-space: normal; }
  .row:disabled { opacity: 1; cursor: default; }
  .row :global(.si) { align-self: center; }
  .pending { color: var(--fg-2); }
  .pending .spin { align-self: center; justify-self: center; }
  .layer { font-weight: 600; }
  .sum { color: var(--fg); }
  .sum.s-x { color: var(--fg-2); }
  .dur { font-size: 12px; font-variant-numeric: tabular-nums; }
  .chev { font-size: 16px; line-height: 1; transition: transform .15s; align-self: center; }
  .chev.open { transform: rotate(90deg); }
  .chev.none { visibility: hidden; }
  .notes { list-style: none; margin: 0 0 8px; padding: 0 0 0 calc(18px + 11.5em + 24px); display: flex; flex-direction: column; gap: 3px; }
  .notes li { display: flex; gap: 7px; align-items: baseline; font-size: 13px; }
  .notes li :global(.si) { flex: none; transform: translateY(1px); }
  .notes li.info { color: var(--fg-2); }
  .compact .row { grid-template-columns: 18px 1fr auto 12px; row-gap: 1px; }
  .compact .layer { grid-column: 2; }
  .compact .sum { grid-column: 2 / 5; grid-row: 2; font-size: 12.5px; }
  .compact .dur { grid-column: 3; grid-row: 1; }
  .compact .chev { grid-column: 4; grid-row: 1; }
  .compact .notes { padding-left: 28px; }
  .compact .notes li { font-size: 12.5px; }
  @media (max-width: 1100px) {
    .steps:not(.compact) .row { grid-template-columns: 18px 9.5em 1fr auto 12px; }
    .steps:not(.compact) .notes { padding-left: calc(18px + 9.5em + 24px); }
  }
</style>
