<script lang="ts">
  import { t, ms } from '../lib/i18n.svelte'
  import { run } from '../lib/run.svelte'
  import StepList from './StepList.svelte'

  const env = $derived(run.env)
  const defIface = $derived(env?.ifaces?.find((i) => i.default))
</script>

{#if run.global.length || run.globalRunning.length}
  <div class="card">
    <div class="card-head"><h3>{t('text.common')}</h3></div>
    {#if env}
      <dl class="env">
        <dt>{t('gui.computer')}</dt><dd>{env.hostname} <span class="mut">· {env.os}</span></dd>
        {#if env.local_ipv4 || env.local_ipv6}
          <dt>{t('gui.local_ip')}</dt>
          <dd><span class="mono">{[env.local_ipv4, env.local_ipv6].filter(Boolean).join(' · ')}</span>{#if defIface}<span class="mut"> · {defIface.name}, MTU {defIface.mtu}</span>{/if}</dd>
        {/if}
        {#if env.gateways?.length}
          <dt>{t('gui.gateway')}</dt>
          <dd><span class="mono">{env.gateways.join(', ')}</span>
            {#if env.gateway_ping?.sent}
              <span class="mut">· ping {env.gateway_ping.recv}/{env.gateway_ping.sent}{env.gateway_ping.recv ? ', ' + ms(env.gateway_ping.avg_ms) : ''}</span>
            {/if}
          </dd>
        {/if}
        {#if env.dns_servers?.length}<dt>DNS</dt><dd class="mono">{env.dns_servers.join(', ')}</dd>{/if}
        {#if env.public_ip}<dt>{t('gui.public_ip')}</dt><dd class="mono">{env.public_ip}</dd>{/if}
        <dt>{t('gui.proxy')}</dt>
        <dd>{#if env.proxies?.length || env.pac}<span class="mono">{[...(env.proxies || []).map((p) => p.value), env.pac].filter(Boolean).join(', ')}</span>{:else}<span class="mut">{t('gui.none')}</span>{/if}</dd>
        <dt>{t('col.trace')}</dt>
        <dd>
          <span class="pill {env.privileges.icmp_trace ? 'bg-ok' : 'bg-skipped'}">ICMP</span>
          <span class="pill {env.privileges.tcp_trace ? 'bg-ok' : 'bg-skipped'}">TCP SYN</span>
          {#if !env.privileges.tcp_trace}<span class="mut small">{t('gui.tcp_trace_admin')}</span>{/if}
        </dd>
      </dl>
    {/if}
    <StepList steps={run.global} running={run.globalRunning} compact />
  </div>
{/if}

<style>
  .env { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px; margin: 0 0 10px; padding-bottom: 10px; border-bottom: 1px solid var(--line); font-size: 13px; }
  dt { color: var(--mut); }
  dd { margin: 0; word-break: break-word; }
  .pill { margin-right: 4px; }
</style>
