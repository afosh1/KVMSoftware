<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, onEngineEvent, type Diagnostics, type DeviceInfo } from '$lib/api';

  let diag = $state<Diagnostics | null>(null);
  let devices = $state<DeviceInfo[]>([]);
  let log = $state<string[]>([]);
  let timer: ReturnType<typeof setInterval>;
  let unlisten: () => void = () => {};

  async function refresh() {
    diag = await api.diagnostics();
    devices = await api.listDevices();
  }

  onMount(() => {
    refresh();
    timer = setInterval(refresh, 1000);
    unlisten = onEngineEvent((p) => {
      log = [`${new Date().toLocaleTimeString()}  ${JSON.stringify(p)}`, ...log].slice(0, 50);
    });
  });
  onDestroy(() => {
    clearInterval(timer);
    unlisten();
  });

  // The connected peers, with names.
  let connected = $derived(
    (diag?.connected_peers ?? []).map((id) => ({
      id,
      name: devices.find((d) => d.id === id)?.name ?? id.slice(0, 8)
    }))
  );

  // Friendly description of the current control state.
  let control = $derived.by(() => {
    const f = diag?.focus ?? '';
    if (f.startsWith('RemoteControl')) return { who: 'You are controlling a remote laptop', kind: 'out' };
    if (f.startsWith('Receiving')) return { who: 'A remote laptop is controlling this one', kind: 'in' };
    if (f.startsWith('Switching') || f.startsWith('EdgeArmed')) return { who: 'Switching…', kind: 'mid' };
    if (f.startsWith('Lost')) return { who: 'Connection lost — recovering', kind: 'bad' };
    return { who: 'You have local control', kind: 'local' };
  });

  function sessionClass(s?: string) {
    if (s === 'Active') return 'good';
    if (s === 'Degraded' || s === 'Reconnecting') return 'warn';
    if (s === 'Closed') return 'bad';
    return 'muted';
  }
</script>

<h2>Diagnostics &amp; control</h2>
<p class="sub">Live connection health and who's driving whom. Everything stays local.</p>

<section class="control card {control.kind}">
  <div class="state">{control.who}</div>
  <div class="buttons">
    {#each connected as p (p.id)}
      <button onclick={() => api.manualSwitch(p.id)}>Take control of {p.name}</button>
    {/each}
    <button class="danger" onclick={() => api.release()}>Release / come back</button>
  </div>
  {#if connected.length === 0}
    <p class="sub">No connected laptops yet — pair one in the Devices tab.</p>
  {/if}
</section>

{#if diag}
  <div class="grid">
    <div class="stat"><span>Control</span><b>{diag.focus}</b></div>
    <div class="stat"><span>Session</span><b class="pill {sessionClass(diag.session)}">{diag.session}</b></div>
    <div class="stat"><span>Latency</span><b>{diag.rtt_ms ?? '—'} ms</b></div>
    <div class="stat"><span>Datagram loss</span><b>{diag.loss_pct.toFixed(2)}%</b></div>
    <div class="stat"><span>Connected peers</span><b>{diag.connected_peers.length}</b></div>
  </div>
{/if}

<section class="card">
  <h3>Activity</h3>
  <pre>{log.join('\n') || 'Waiting for events…'}</pre>
</section>

<style>
  .control { margin-bottom: 18px; max-width: 720px; }
  .control .state { font-size: 18px; font-weight: 600; margin-bottom: 12px; }
  .control.out .state { color: var(--accent); }
  .control.in .state { color: var(--warn); }
  .control.bad .state { color: var(--bad); }
  .buttons { display: flex; gap: 8px; flex-wrap: wrap; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; max-width: 720px; margin-bottom: 18px; }
  .stat { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 16px; }
  .stat span { color: var(--muted); display: block; font-size: 12px; }
  .stat b { font-size: 16px; }
  .pill { font-size: 14px; padding: 2px 10px; border-radius: 999px; }
  .pill.good { background: rgba(63,185,80,0.18); color: var(--good); }
  .pill.warn { background: rgba(210,153,34,0.18); color: var(--warn); }
  .pill.bad { background: rgba(248,81,73,0.18); color: var(--bad); }
  .pill.muted { background: var(--panel2); color: var(--muted); }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px; max-width: 720px; }
  h3 { margin: 0 0 10px; font-size: 15px; }
  pre { margin: 0; font-size: 12px; color: var(--muted); white-space: pre-wrap; max-height: 240px; overflow: auto; }
</style>
