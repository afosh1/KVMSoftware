<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type IdentityInfo, type PermissionState } from '$lib/api';

  let identity = $state<IdentityInfo | null>(null);
  let perms = $state<PermissionState | null>(null);

  onMount(async () => {
    identity = await api.identity();
    perms = await api.permissions();
  });

  function badge(status: string) {
    if (status === 'Granted' || status === 'NotRequired') return 'good';
    if (status === 'Denied') return 'bad';
    return 'warn';
  }
</script>

<h2>Setup</h2>
<p class="sub">Get this device ready to share keyboard, mouse, and clipboard on your LAN.</p>

<section class="card">
  <h3>1. This device</h3>
  {#if identity}
    <div class="kv"><span>Name</span><b>{identity.device_name}</b></div>
    <div class="kv"><span>Platform</span><b>{identity.platform}</b></div>
    <div class="kv"><span>Identity</span><code>{identity.device_id}</code></div>
    <div class="kv"><span>Fingerprint</span><code>{identity.fingerprint.slice(0, 16)}…</code></div>
  {:else}
    <p class="sub">Generating identity…</p>
  {/if}
</section>

<section class="card">
  <h3>2. Permissions</h3>
  <p class="sub">
    The KVM needs OS permission to observe and inject input. On macOS, grant
    <b>Accessibility</b> and <b>Input Monitoring</b> in System Settings → Privacy &amp; Security.
    On Windows no prompt appears, but antivirus may flag low-level input hooks.
    On Linux (X11) no special permission is required.
  </p>
  {#if perms}
    <div class="kv"><span>Input capture</span><span class="pill {badge(perms.capture)}">{perms.capture}</span></div>
    <div class="kv"><span>Input injection</span><span class="pill {badge(perms.injection)}">{perms.injection}</span></div>
  {/if}
</section>

<section class="card">
  <h3>3. Next steps</h3>
  <p class="sub">Pair a nearby device, arrange your screens, then move your cursor to the edge.</p>
  <div class="row">
    <a href="/devices"><button>Pair a device →</button></a>
    <a href="/layout"><button class="ghost">Arrange screens</button></a>
  </div>
</section>

<style>
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 18px 20px; margin-bottom: 16px; max-width: 640px;
  }
  h3 { margin: 0 0 12px; font-size: 15px; }
  .kv { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-top: 1px solid var(--border); }
  .kv:first-of-type { border-top: 0; }
  .kv span { color: var(--muted); }
  code { background: var(--panel2); padding: 2px 6px; border-radius: 4px; font-size: 12px; }
  .pill { padding: 2px 10px; border-radius: 999px; font-size: 12px; }
  .pill.good { background: rgba(63,185,80,0.18); color: var(--good); }
  .pill.warn { background: rgba(210,153,34,0.18); color: var(--warn); }
  .pill.bad { background: rgba(248,81,73,0.18); color: var(--bad); }
  .row { display: flex; gap: 10px; }
  a { text-decoration: none; }
</style>
