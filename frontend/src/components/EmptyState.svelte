<script lang="ts">
  import { t } from '../lib/i18n.svelte'
  const layers = ['env', 'dns', 'trace', 'tcp', 'tls', 'app', 'captive'] as const
</script>

<div class="empty">
  <h2>{t('gui.empty_title')}</h2>
  <p class="mut">{t('gui.empty_text')}</p>
  <ol>
    {#each layers as l, i}
      <li><span class="n">{i + 1}</span><div><b>{t('gui.layer_' + l)}</b><div class="mut small">{t('gui.layer_' + l + '_desc')}</div></div></li>
    {/each}
  </ol>
  <p class="ro small mut">{t('web.readonly')}</p>
</div>

<style>
  .empty { max-width: 620px; margin: 40px auto; }
  h2 { font-size: 20px; margin-bottom: 6px; }
  ol { list-style: none; padding: 0; margin: 22px 0; display: flex; flex-direction: column; gap: 0; }
  li { display: flex; gap: 14px; align-items: flex-start; padding: 9px 0; position: relative; }
  li:not(:last-child)::after { content: ''; position: absolute; left: 13px; top: 38px; bottom: -6px; width: 2px; background: repeating-linear-gradient(var(--stake) 0 6px, transparent 6px 12px); opacity: .5; }
  .n { flex: none; width: 28px; height: 28px; border-radius: 50%; display: grid; place-items: center; background: var(--panel); border: 2px solid var(--stake); color: var(--stake); font-weight: 700; font-size: 13px; }
  .ro { border-top: 1px solid var(--line); padding-top: 12px; }
</style>
