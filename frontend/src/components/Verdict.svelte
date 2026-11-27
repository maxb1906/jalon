<script lang="ts">
  import { t, tr } from '../lib/i18n.svelte'
  import type { Verdict } from '../lib/types'
  import StatusIcon from './StatusIcon.svelte'

  let { verdict }: { verdict: Verdict } = $props()
  const main = $derived(verdict.status !== 'ok' ? verdict.findings?.[0] : undefined)
  const others = $derived((verdict.findings || []).filter((_, i) => i > 0 || verdict.status === 'ok'))
</script>

<div class="verdict v-{verdict.status}">
  <div class="head">
    <StatusIcon status={verdict.status} size={26} />
    <div>
      <div class="kicker">{t('col.verdict')} · {t('status.' + verdict.status)}</div>
      <div class="headline">{tr(verdict.headline)}</div>
      {#if main?.advice?.key}<div class="advice">→ {tr(main.advice)}</div>{/if}
    </div>
  </div>
  {#if others.length}
    <ul>
      {#each others as f}
        <li><StatusIcon status={f.severity} size={13} /> <span>{tr(f.msg)}{#if f.advice?.key}<span class="mut"> — {tr(f.advice)}</span>{/if}</span></li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .verdict { border-radius: var(--radius); padding: 16px 18px; border: 1px solid; }
  .v-ok { background: var(--ok-bg); border-color: color-mix(in srgb, var(--ok) 30%, transparent); }
  .v-warn { background: var(--warn-bg); border-color: color-mix(in srgb, var(--warn) 30%, transparent); }
  .v-fail { background: var(--fail-bg); border-color: color-mix(in srgb, var(--fail) 30%, transparent); }
  .v-info, .v-skipped { background: var(--skip-bg); border-color: var(--line); }
  .head { display: flex; gap: 14px; align-items: flex-start; }
  .head :global(.si) { margin-top: 3px; }
  .kicker { font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: .05em; opacity: .8; }
  .v-ok .kicker { color: var(--ok); } .v-warn .kicker { color: var(--warn); } .v-fail .kicker { color: var(--fail); }
  .headline { font-size: 17px; font-weight: 600; margin-top: 2px; }
  .advice { margin-top: 6px; font-weight: 500; }
  ul { list-style: none; margin: 12px 0 0; padding: 10px 0 0 40px; border-top: 1px solid color-mix(in srgb, currentColor 12%, transparent); display: flex; flex-direction: column; gap: 4px; }
  li { display: flex; gap: 7px; align-items: baseline; font-size: 13px; }
  li :global(.si) { flex: none; transform: translateY(1px); }
</style>
