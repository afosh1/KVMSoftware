<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, type DeviceInfo } from '$lib/api';

  let devices = $state<DeviceInfo[]>([]);
  let pairing = $state<{ id: string; name: string; fingerprint: string } | null>(null);
  let timer: ReturnType<typeof setInterval>;

  async function refresh() {
    devices = await api.listDevices();
  }
  onMount(() => {
    refresh();
    // Poll so newly discovered (or re-discovered after Remove) peers appear.
    timer = setInterval(refresh, 2000);
  });
  onDestroy(() => clearInterval(timer));

  function startPair(d: DeviceInfo) {
    pairing = { id: d.id, name: d.name, fingerprint: d.fingerprint };
  }
  async function confirmPair() {
    if (!pairing) return;
    await api.confirmPairing(pairing.id, '');
    pairing = null;
    await refresh();
  }
  async function revoke(d: DeviceInfo) {
    await api.revoke(d.id);
    await refresh();
  }
  async function forget(d: DeviceInfo) {
    await api.forget(d.id);
    await refresh();
  }
  async function connect(d: DeviceInfo) {
    await api.connect(d.id);
    await refresh();
  }

  function trustClass(t: string) {
    if (t === 'Trusted') return 'good';
    if (t === 'Paired') return 'warn';
    if (t === 'Revoked') return 'bad';
    return 'muted';
  }
</script>

<h2>Devices</h2>
<p class="sub">Pair with mutual consent. Compare the verification code on both screens before confirming.</p>

{#if pairing}
  <section class="card pair">
    <h3>Pair with {pairing.name}?</h3>
    <p class="sub">
      Check that this fingerprint matches the one shown on their <b>Setup</b> screen
      (ask them to read the first few characters):
    </p>
    <div class="fp">{pairing.fingerprint}</div>
    <div class="row">
      <button onclick={confirmPair}>Pair</button>
      <button class="ghost" onclick={() => (pairing = null)}>Cancel</button>
    </div>
  </section>
{/if}

<div class="list">
  {#each devices as d (d.id)}
    <div class="device">
      <div class="meta">
        <div class="dot {d.connected ? 'on' : 'off'}"></div>
        <div>
          <b>{d.name}</b>
          <div class="small">{d.platform} · {d.fingerprint.slice(0, 12)}…</div>
        </div>
      </div>
      <div class="actions">
        <span class="trust {trustClass(d.trust)}">{d.trust}</span>
        {#if d.trust === 'Untrusted'}
          <button onclick={() => startPair(d)}>Pair</button>
        {:else}
          {#if !d.connected}
            <button class="ghost" onclick={() => connect(d)}>Connect</button>
          {/if}
          <button class="ghost" onclick={() => revoke(d)}>Revoke</button>
        {/if}
        <button class="danger" onclick={() => forget(d)}>Remove</button>
      </div>
    </div>
  {/each}
  {#if devices.length === 0}
    <p class="sub">No devices discovered yet. Make sure both machines are on the same network.</p>
  {/if}
</div>

<style>
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 18px 20px; margin-bottom: 18px; max-width: 640px; }
  .pair .fp { font-family: monospace; font-size: 13px; word-break: break-all; background: var(--panel2); padding: 10px 12px; border-radius: 6px; margin: 8px 0 14px; color: var(--accent); }
  h3 { margin: 0 0 8px; font-size: 15px; }
  .row { display: flex; gap: 10px; align-items: center; }
  .list { display: flex; flex-direction: column; gap: 10px; max-width: 640px; }
  .device { display: flex; justify-content: space-between; align-items: center; background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px; }
  .meta { display: flex; gap: 12px; align-items: center; }
  .small { color: var(--muted); font-size: 12px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; }
  .dot.on { background: var(--good); }
  .dot.off { background: var(--muted); }
  .actions { display: flex; gap: 8px; align-items: center; }
  .trust { font-size: 12px; padding: 2px 10px; border-radius: 999px; }
  .trust.good { background: rgba(63,185,80,0.18); color: var(--good); }
  .trust.warn { background: rgba(210,153,34,0.18); color: var(--warn); }
  .trust.bad { background: rgba(248,81,73,0.18); color: var(--bad); }
  .trust.muted { background: var(--panel2); color: var(--muted); }
</style>
