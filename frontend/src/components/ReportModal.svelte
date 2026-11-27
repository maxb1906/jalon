<script lang="ts">
  import { t } from '../lib/i18n.svelte'
  let { html, title, onclose, onbrowser }: { html: string; title: string; onclose: () => void; onbrowser: () => void } = $props()

  function key(e: KeyboardEvent) {
    if (e.key === 'Escape') onclose()
  }
</script>

<svelte:window onkeydown={key} />
<div class="back" role="presentation" onclick={(e) => { if (e.target === e.currentTarget) onclose() }}>
  <div class="modal" role="dialog" aria-modal="true" aria-label={title}>
    <div class="bar">
      <h2>{title}</h2>
      <div class="acts">
        <button onclick={onbrowser}>{t('gui.open_browser')}</button>
        <button class="primary" onclick={onclose}>{t('gui.close')}</button>
      </div>
    </div>
    <iframe title={title} srcdoc={html} sandbox=""></iframe>
  </div>
</div>

<style>
  .back { position: fixed; inset: 0; background: rgba(10, 14, 22, .45); display: flex; align-items: stretch; justify-content: center; padding: 28px; z-index: 40; animation: fade .15s; }
  .modal { background: var(--panel); border-radius: 12px; width: min(1100px, 100%); display: flex; flex-direction: column; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,.3); }
  .bar { display: flex; justify-content: space-between; align-items: center; padding: 10px 14px; border-bottom: 1px solid var(--line); gap: 10px; }
  .acts { display: flex; gap: 8px; }
  iframe { flex: 1; border: 0; width: 100%; background: #fff; }
  @keyframes fade { from { opacity: 0; } }
</style>
