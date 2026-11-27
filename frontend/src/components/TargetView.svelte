<script lang="ts">
  import { t } from '../lib/i18n.svelte'
  import { run, type TargetState } from '../lib/run.svelte'
  import StepList from './StepList.svelte'
  import Verdict from './Verdict.svelte'
  import Timings from './Timings.svelte'
  import TraceView from './TraceView.svelte'
  import Changes from './Changes.svelte'

  let { ts }: { ts: TargetState } = $props()
  const r = $derived(ts.report)
  const running = $derived(ts.running ? [ts.running] : !r && run.active ? ['_wait'] : [])
</script>

<div class="tv">
  <div class="title">
    <h2 class="mono">{ts.raw}</h2>
    {#if r}
      <span class="pill bg-skipped">{r.target.proto.toUpperCase()} · {r.target.port}</span>
      {#if r.chosen_ip}<span class="pill bg-skipped mono">{r.chosen_ip}</span>{/if}
    {/if}
  </div>

  {#if r}
    <Verdict verdict={r.verdict} />
  {:else}
    <div class="pending card"><span class="spin s-info"></span> {run.active ? t('web.running') : t('gui.interrupted')}</div>
  {/if}

  <div class="card">
    <div class="card-head"><h3>{t('gui.cascade')}</h3></div>
    {#if ts.steps.length || running.length}
      <StepList steps={ts.steps} running={running.filter((x) => x !== '_wait')} />
      {#if running[0] === '_wait' && !ts.steps.length}<p class="mut">{t('tui.waiting')}</p>{/if}
    {:else}
      <p class="mut">{t('tui.waiting')}</p>
    {/if}
  </div>

  {#if r?.http?.timings}<Timings timings={r.http.timings} proto={r.http.proto} code={r.http.code} />{/if}
  <TraceView traces={ts.traces} live={!r && run.active} />
  {#if r?.compare}<Changes compare={r.compare} />{/if}
</div>

<style>
  .tv { display: flex; flex-direction: column; gap: 14px; }
  .tv :global(.card + .card) { margin-top: 0; }
  .title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .title h2 { font-size: 18px; font-family: var(--mono); margin-right: 4px; word-break: break-all; }
  .pending { display: flex; align-items: center; gap: 10px; color: var(--fg-2); }
  p { margin: 0; }
</style>
