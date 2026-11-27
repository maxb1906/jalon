<script lang="ts">
  import { toasts, dismiss } from '../lib/toast.svelte'
  import StatusIcon from './StatusIcon.svelte'
</script>

<div class="toasts" aria-live="polite">
  {#each toasts.list as x (x.id)}
    <div class="toast">
      <StatusIcon status={x.kind} />
      <span class="txt">{x.text}</span>
      {#if x.action}
        <button class="ghost act" onclick={() => { x.action!.run(); dismiss(x.id) }}>{x.action.label}</button>
      {/if}
      <button class="ghost x" aria-label="×" onclick={() => dismiss(x.id)}>×</button>
    </div>
  {/each}
</div>

<style>
  .toasts { position: fixed; right: 18px; bottom: 18px; display: flex; flex-direction: column; gap: 8px; z-index: 50; max-width: 460px; }
  .toast { display: flex; align-items: center; gap: 10px; background: var(--fg); color: var(--bg); padding: 9px 10px 9px 14px; border-radius: 9px; box-shadow: 0 6px 24px rgba(0,0,0,.18); animation: in .18s ease-out; }
  .txt { flex: 1; word-break: break-word; }
  .toast button { color: var(--bg); padding: 2px 8px; }
  .toast button:hover { background: rgba(127,127,127,.25) !important; }
  .act { font-weight: 600; }
  @keyframes in { from { transform: translateY(8px); opacity: 0; } }
</style>
