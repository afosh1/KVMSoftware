<script lang="ts">
  import { page } from '$app/stores';
  import { inTauri } from '$lib/api';

  let { children } = $props();

  const nav = [
    { href: '/', label: 'Setup' },
    { href: '/devices', label: 'Devices' },
    { href: '/layout', label: 'Layout' },
    { href: '/settings', label: 'Sharing' },
    { href: '/files', label: 'Files' },
    { href: '/diagnostics', label: 'Diagnostics' }
  ];
</script>

<div class="app">
  <aside>
    <h1>KVM<span>share</span></h1>
    <nav>
      {#each nav as item}
        <a href={item.href} class:active={$page.url.pathname === item.href}>{item.label}</a>
      {/each}
    </nav>
    {#if !inTauri}
      <p class="demo">demo mode (not running in app)</p>
    {/if}
  </aside>
  <main>
    {@render children()}
  </main>
</div>

<style>
  :global(:root) {
    --bg: #0f1115;
    --panel: #181b22;
    --panel2: #21252e;
    --text: #e6e9ef;
    --muted: #8b93a3;
    --accent: #5b8def;
    --good: #3fb950;
    --warn: #d29922;
    --bad: #f85149;
    --border: #2a2f3a;
  }
  :global(body) {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
  }
  :global(h2) { margin: 0 0 4px; font-size: 20px; }
  :global(.sub) { color: var(--muted); margin: 0 0 20px; }
  :global(button) {
    background: var(--accent); color: #fff; border: 0; border-radius: 6px;
    padding: 8px 14px; font-size: 14px; cursor: pointer;
  }
  :global(button.ghost) { background: var(--panel2); color: var(--text); border: 1px solid var(--border); }
  :global(button.danger) { background: var(--bad); }
  :global(button:disabled) { opacity: 0.5; cursor: not-allowed; }
  .app { display: grid; grid-template-columns: 200px 1fr; min-height: 100vh; }
  aside { background: var(--panel); border-right: 1px solid var(--border); padding: 20px 14px; }
  h1 { font-size: 18px; margin: 0 0 24px; }
  h1 span { color: var(--accent); }
  nav { display: flex; flex-direction: column; gap: 4px; }
  nav a {
    color: var(--muted); text-decoration: none; padding: 8px 12px; border-radius: 6px;
  }
  nav a:hover { background: var(--panel2); color: var(--text); }
  nav a.active { background: var(--accent); color: #fff; }
  main { padding: 28px 32px; overflow: auto; }
  .demo { margin-top: 24px; font-size: 11px; color: var(--warn); }
</style>
