<script lang="ts">
  import { t } from '../lib/i18n.svelte'
  import type { Info, RunRequest } from '../lib/types'

  let {
    info, busy, cancelling, onstart, oncancel,
  }: { info: Info; busy: boolean; cancelling: boolean; onstart: (r: Omit<RunRequest, 'lang'>) => void; oncancel: () => void } = $props()

  let targets = $state(localStorage.getItem('jalon-targets') || '')
  let proto = $state('')
  let traceMode = $state('auto')
  let noTrace = $state(false)
  let family = $state<'both' | 'ipv4' | 'ipv6'>('both')
  let more = $state(false)

  $effect.pre(() => {
    proto = info.proto || ''
    traceMode = info.trace_mode || 'auto'
    noTrace = info.no_trace
  })

  const count = $derived(targets.split(/[\n,]/).map((s) => s.trim()).filter((s) => s && !s.startsWith('#')).length)

  function submit(e: Event) {
    e.preventDefault()
    if (busy || !count) return
    localStorage.setItem('jalon-targets', targets)
    onstart({ targets, proto, trace_mode: traceMode, no_trace: noTrace, ipv4: family === 'ipv4', ipv6: family === 'ipv6' })
  }

  function keydown(e: KeyboardEvent) {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) submit(e)
  }

  const examples = ['https://exemple.be', 'smtp://mail.exemple.be', '10.0.0.5:3389']
  function addExample(x: string) {
    targets = (targets.trim() ? targets.trim() + '\n' : '') + x
  }
</script>

<form class="card form" onsubmit={submit}>
  <label for="targets" class="lbl">{t('web.targets')}</label>
  <textarea id="targets" rows="5" bind:value={targets} onkeydown={keydown} spellcheck="false" autocomplete="off"
    placeholder={'https://exemple.be\nsmtp://mail.exemple.be\n10.0.0.5:3389'}></textarea>
  <div class="ex small mut">
    {t('gui.examples')}
    {#each examples as x}<button type="button" class="chip" onclick={() => addExample(x)}>{x}</button>{/each}
  </div>

  <div class="seg" role="radiogroup" aria-label="IP">
    <button type="button" class:on={family === 'both'} onclick={() => (family = 'both')}>IPv4 + IPv6</button>
    <button type="button" class:on={family === 'ipv4'} onclick={() => (family = 'ipv4')}>IPv4</button>
    <button type="button" class:on={family === 'ipv6'} onclick={() => (family = 'ipv6')}>IPv6</button>
  </div>

  <button type="button" class="ghost more small" onclick={() => (more = !more)} aria-expanded={more}>
    <span class="chev" class:open={more}>›</span> {t('gui.options')}
  </button>
  {#if more}
    <div class="opts">
      <label><span>{t('web.proto')}</span>
        <select bind:value={proto}>
          <option value="">{t('gui.auto')}</option>
          {#each info.protos as p}<option value={p}>{p.toUpperCase()}</option>{/each}
        </select>
      </label>
      <label><span>{t('web.trace_mode')}</span>
        <select bind:value={traceMode} disabled={noTrace}>
          <option value="auto">{t('gui.auto')}</option>
          <option value="icmp">ICMP</option>
          <option value="tcp">TCP SYN</option>
        </select>
      </label>
      <label class="chk"><input type="checkbox" bind:checked={noTrace} /> {t('web.no_trace')}</label>
    </div>
  {/if}

  {#if busy}
    <button type="button" class="danger big" onclick={oncancel} disabled={cancelling}>
      <span class="spin"></span> {cancelling ? t('gui.stopping') : t('gui.stop')}
    </button>
  {:else}
    <button type="submit" class="primary big" disabled={!count}>
      {count > 1 ? t('gui.run_n', count) : t('web.run')}
    </button>
  {/if}
  <div class="small mut hint">{t('gui.shortcut')}</div>
</form>

<style>
  .form { display: flex; flex-direction: column; gap: 10px; }
  .lbl { font-weight: 600; }
  .ex { display: flex; flex-wrap: wrap; gap: 4px; align-items: center; }
  .chip { padding: 0 7px; border-radius: 999px; font-size: 11.5px; font-family: var(--mono); color: var(--fg-2); background: var(--panel-2); border-color: var(--line); }
  .seg { display: flex; border: 1px solid var(--line-2); border-radius: 7px; overflow: hidden; }
  .seg button { flex: 1; justify-content: center; border: 0; border-radius: 0; padding: 5px 6px; font-size: 13px; }
  .seg button + button { border-left: 1px solid var(--line-2); }
  .seg button.on { background: var(--accent-bg); color: var(--accent); font-weight: 600; }
  .more { align-self: flex-start; padding: 2px 4px; color: var(--fg-2); }
  .chev { display: inline-block; transition: transform .15s; font-size: 16px; line-height: 1; }
  .chev.open { transform: rotate(90deg); }
  .opts { display: grid; gap: 8px; padding: 2px 0 4px; }
  .opts label { display: grid; grid-template-columns: 7.5em 1fr; align-items: center; gap: 8px; font-size: 13px; }
  .opts label.chk { display: flex; gap: 6px; }
  .big { justify-content: center; padding: 9px 12px; font-size: 14.5px; }
  .hint { text-align: center; margin-top: -4px; }
</style>
