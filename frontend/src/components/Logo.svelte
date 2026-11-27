<script lang="ts">
  let { size = 26 }: { size?: number } = $props()
</script>

<!-- Un jalon d'arpenteur : piquet rayé rouge et blanc planté au sol. -->
<svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
  <rect x="2" y="2" width="28" height="28" rx="7" fill="var(--accent)" />
  <path d="M7 25.5h18" stroke="#fff" stroke-opacity=".55" stroke-width="1.6" stroke-linecap="round" />
  <rect x="13.6" y="5.5" width="4.8" height="17" rx="1" fill="#fff" />
  <rect x="13.6" y="5.5" width="4.8" height="4.2" rx="1" fill="var(--stake)" />
  <rect x="13.6" y="13.9" width="4.8" height="4.2" fill="var(--stake)" />
  <path d="M13.6 22.5h4.8L16 26z" fill="#fff" />
</svg>
