<script lang="ts">
  import type { Status } from '../lib/types'
  let { status, size = 16 }: { status: Status | undefined; size?: number } = $props()
  const s = $derived(status || 'skipped')
</script>

<svg class="si s-{s}" width={size} height={size} viewBox="0 0 16 16" aria-hidden="true">
  {#if s === 'ok'}
    <circle cx="8" cy="8" r="7" fill="currentColor" />
    <path d="M4.6 8.3l2.2 2.2 4.6-4.8" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
  {:else if s === 'warn'}
    <path d="M8 1.3l7 12.7H1z" fill="currentColor" stroke="currentColor" stroke-width="1" stroke-linejoin="round" />
    <path d="M8 6v3.6" stroke="#fff" stroke-width="1.8" stroke-linecap="round" />
    <circle cx="8" cy="11.9" r="1" fill="#fff" />
  {:else if s === 'fail'}
    <circle cx="8" cy="8" r="7" fill="currentColor" />
    <path d="M5.5 5.5l5 5M10.5 5.5l-5 5" stroke="#fff" stroke-width="1.8" stroke-linecap="round" />
  {:else if s === 'info'}
    <circle cx="8" cy="8" r="7" fill="currentColor" />
    <path d="M8 7.2v4" stroke="#fff" stroke-width="1.8" stroke-linecap="round" />
    <circle cx="8" cy="4.9" r="1" fill="#fff" />
  {:else}
    <circle cx="8" cy="8" r="6.2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="2.4 2" />
  {/if}
</svg>

<style>
  .si { flex: none; display: inline-block; vertical-align: -3px; }
</style>
