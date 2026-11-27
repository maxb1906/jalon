<script lang="ts">
  import { onMount } from 'svelte'
  import { api, onEvent, emit, copyText, errText } from './lib/api'
  import { i18n, t, fmtDate } from './lib/i18n.svelte'
  import { run, resetLive, onEngineEvent, loadReport, targetStatus } from './lib/run.svelte'
  import { toast } from './lib/toast.svelte'
  import type { Info, RunRequest } from './lib/types'
  import Logo from './components/Logo.svelte'
  import RunForm from './components/RunForm.svelte'
  import GlobalPanel from './components/GlobalPanel.svelte'
  import TargetView from './components/TargetView.svelte'
  import Synthesis from './components/Synthesis.svelte'
  import HistoryView from './components/HistoryView.svelte'
  import EmptyState from './components/EmptyState.svelte'
  import ReportModal from './components/ReportModal.svelte'
  import Toasts from './components/Toasts.svelte'
  import StatusIcon from './components/StatusIcon.svelte'

  let info = $state<Info | null>(null)
  let view = $state<'run' | 'history'>('run')
  let modal = $state<{ html: string; title: string; id: string } | null>(null)
  let saveMenu = $state(false)
  let fatal = $state('')

  async function setLang(l: string) {
    const cat = await (await api()).Strings(l)
    i18n.cat = cat
    i18n.lang = l
    document.documentElement.lang = l
    localStorage.setItem('jalon-lang', l)
  }

  onMount(() => {
    let off = () => {}
    ;(async () => {
      try {
        const b = await api()
        info = await b.Init()
        await setLang(localStorage.getItem('jalon-lang') || info.lang)
        off = onEvent('jalon:event', (d: RunEvent) => {
          if (run.id === PENDING) early.push(d)
          else handle(d)
        })
        emit('gui:ready')
      } catch (e) {
        fatal = errText(e)
      }
    })()
    return () => off()
  })

  type RunEvent = { run: string; event: any }
  // Les premiers événements peuvent arriver avant la réponse de Start : ils
  // sont gardés le temps de connaître l'identifiant du diagnostic.
  const PENDING = '__pending'
  let early: RunEvent[] = []

  function handle(d: RunEvent) {
    if (d.run !== run.id) return
    onEngineEvent(d.event)
    if (d.event.type === 'run_done') {
      toast(t('web.done'), 'info')
    }
  }

  async function start(r: Omit<RunRequest, 'lang'>) {
    const prev = run.id
    run.id = PENDING
    early = []
    try {
      const id = await (await api()).Start({ ...r, lang: i18n.lang })
      resetLive(id)
      view = 'run'
      for (const d of early) handle(d)
    } catch (e) {
      run.id = prev
      toast(errText(e), 'fail')
    }
    early = []
  }

  async function cancel() {
    run.cancelling = true
    try { await (await api()).Cancel() } catch (e) { toast(errText(e), 'fail') }
  }

  // Identifiant pour les exports : "" = diagnostic en mémoire, sinon historique.
  const srcId = $derived(run.source === 'history' ? run.historyId : '')
  const canExport = $derived(!!run.report)

  async function copyTicket() {
    try {
      const txt = await (await api()).Ticket(srcId)
      toast((await copyText(txt)) ? t('gui.copied') : t('gui.copy_failed'), 'ok')
    } catch (e) { toast(errText(e), 'fail') }
  }

  async function showReport(id: string, title: string) {
    try {
      modal = { html: await (await api()).ReportHTML(id), title, id }
    } catch (e) { toast(errText(e), 'fail') }
  }

  async function openBrowser(id: string) {
    try { await (await api()).OpenReport(id) } catch (e) { toast(errText(e), 'fail') }
  }

  async function save(format: string) {
    saveMenu = false
    try {
      const path = await (await api()).Export(srcId, format)
      if (path) toast(t('cli.report_written', path), 'ok')
    } catch (e) { toast(errText(e), 'fail') }
  }

  async function showHistory(id: string) {
    try {
      loadReport(await (await api()).LoadHistory(id), id)
      view = 'run'
    } catch (e) { toast(errText(e), 'fail') }
  }

  const sel = $derived(run.targets[run.selected] || run.targets[0])
  const multi = $derived(run.targets.length > 1)
  const title = $derived(run.source === 'history' ? t('gui.from_history', fmtDate(run.started)) : run.started ? fmtDate(run.started) : '')
</script>

<svelte:window onclick={() => (saveMenu = false)} />

{#if fatal}
  <div class="fatal card"><StatusIcon status="fail" /> {fatal}</div>
{:else if info}
  <div class="shell">
    <header>
      <div class="brand"><Logo /><div><h1>Jalon</h1><div class="sub">{t('web.subtitle')}</div></div></div>
      <nav>
        <button class="tab" class:on={view === 'run'} onclick={() => (view = 'run')}>
          {t('web.tab_run')}{#if run.active}<span class="spin small-spin"></span>{/if}
        </button>
        <button class="tab" class:on={view === 'history'} onclick={() => (view = 'history')}>{t('web.tab_history')}</button>
      </nav>
      <div class="right">
        <div class="lang" role="radiogroup" aria-label="Langue / Language">
          <button class:on={i18n.lang === 'fr'} onclick={() => setLang('fr')}>FR</button>
          <button class:on={i18n.lang === 'en'} onclick={() => setLang('en')}>EN</button>
        </div>
      </div>
    </header>

    {#if view === 'run'}
      <div class="body">
        <aside>
          <RunForm {info} busy={run.active || run.id === PENDING} cancelling={run.cancelling} onstart={start} oncancel={cancel} />
          <GlobalPanel />
        </aside>
        <main>
          {#if !run.targets.length}
            {#if run.active}
              <div class="card waiting"><span class="spin s-info"></span> {t('web.running')}</div>
            {:else}
              <EmptyState />
            {/if}
          {:else}
            <div class="toolbar">
              <div class="meta">
                {#if run.active}<span class="pill bg-info"><span class="spin small-spin"></span> {t('web.running')}</span>
                {:else if run.report}<span class="pill bg-{run.report.status}"><StatusIcon status={run.report.status} size={12} /> {t('status.' + run.report.status)}</span>{/if}
                <span class="mut small">{title}</span>
              </div>
              <div class="acts">
                <button disabled={!canExport} onclick={copyTicket}>{t('gui.copy_ticket')}</button>
                <button disabled={!canExport} onclick={() => showReport(srcId, t('gui.report'))}>{t('gui.view_report')}</button>
                <div class="menu">
                  <button disabled={!canExport} onclick={(e) => { e.stopPropagation(); saveMenu = !saveMenu }}>{t('gui.save')} ▾</button>
                  {#if saveMenu}
                    <div class="dropdown" role="menu">
                      <button class="ghost" onclick={() => save('html')}>HTML</button>
                      <button class="ghost" onclick={() => save('md')}>Markdown</button>
                      <button class="ghost" onclick={() => save('json')}>JSON</button>
                      <button class="ghost" onclick={() => save('ticket')}>{t('text.ticket')} (.txt)</button>
                    </div>
                  {/if}
                </div>
              </div>
            </div>

            {#if multi}
              <Synthesis />
              <div class="ttabs">
                {#each run.targets as ts, i}
                  <button class="ttab" class:on={i === run.selected} onclick={() => (run.selected = i)}>
                    {#if !ts.report && run.active}<span class="spin small-spin s-info"></span>{:else}<StatusIcon status={targetStatus(ts)} size={13} />{/if}
                    <span class="mono">{ts.raw}</span>
                  </button>
                {/each}
              </div>
            {/if}
            {#if sel}
              {#key run.selected + ':' + run.id + ':' + run.historyId}
                <TargetView ts={sel} />
              {/key}
            {/if}
          {/if}
        </main>
      </div>
    {:else}
      <div class="body single"><main><HistoryView {info} onshow={showHistory} onreport={showReport} /></main></div>
    {/if}

    <footer class="mut small">Jalon {info.version} · GPL-3.0 · {t('web.readonly')}</footer>
  </div>
  {#if modal}
    {@const m = modal}
    <ReportModal html={m.html} title={m.title} onclose={() => (modal = null)} onbrowser={() => openBrowser(m.id)} />
  {/if}
  <Toasts />
{/if}

<style>
  .shell { display: grid; grid-template-rows: auto 1fr auto; height: 100vh; }
  header { display: flex; align-items: center; gap: 24px; padding: 10px 20px; background: var(--panel); border-bottom: 1px solid var(--line); }
  .brand { display: flex; align-items: center; gap: 10px; }
  h1 { font-size: 17px; line-height: 1.1; }
  .sub { font-size: 12px; color: var(--mut); }
  nav { display: flex; gap: 4px; }
  .tab { border: 0; background: transparent; padding: 7px 14px; border-radius: 7px; color: var(--fg-2); font-weight: 500; }
  .tab.on { background: var(--accent-bg); color: var(--accent); font-weight: 600; }
  .right { margin-left: auto; display: flex; gap: 10px; align-items: center; }
  .lang { display: flex; border: 1px solid var(--line-2); border-radius: 7px; overflow: hidden; }
  .lang button { border: 0; border-radius: 0; padding: 4px 10px; font-size: 12.5px; font-weight: 600; color: var(--mut); }
  .lang button.on { background: var(--accent-bg); color: var(--accent); }
  .small-spin { width: 10px; height: 10px; border-width: 2px; margin-left: 4px; }
  .body { display: grid; grid-template-columns: 340px 1fr; min-height: 0; }
  .body.single { grid-template-columns: 1fr; }
  aside { padding: 16px 0 16px 16px; overflow-y: auto; }
  aside :global(.card + .card) { margin-top: 14px; }
  main { padding: 16px 20px; overflow-y: auto; min-width: 0; }
  .toolbar { display: flex; justify-content: space-between; align-items: center; gap: 12px; margin-bottom: 14px; flex-wrap: wrap; }
  .meta { display: flex; align-items: center; gap: 10px; }
  .acts { display: flex; gap: 8px; }
  .menu { position: relative; }
  .dropdown { position: absolute; right: 0; top: calc(100% + 4px); background: var(--panel); border: 1px solid var(--line-2); border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,.12); padding: 4px; display: flex; flex-direction: column; min-width: 180px; z-index: 20; }
  .dropdown button { justify-content: flex-start; }
  .ttabs { display: flex; gap: 6px; flex-wrap: wrap; margin: 14px 0; }
  .ttab { border-radius: 999px; padding: 4px 12px; font-size: 12.5px; }
  .ttab.on { border-color: var(--accent); background: var(--accent-bg); color: var(--accent); }
  .waiting { display: flex; align-items: center; gap: 10px; }
  footer { padding: 6px 20px; border-top: 1px solid var(--line); background: var(--panel); }
  .fatal { margin: 40px auto; max-width: 600px; display: flex; gap: 10px; }
</style>
