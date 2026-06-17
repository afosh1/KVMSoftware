<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, onFileDrop, onEngineEvent, type DeviceInfo } from '$lib/api';

  let devices = $state<DeviceInfo[]>([]);
  let target = $state<string>('');
  let dragOver = $state(false);
  let activity = $state<string[]>([]);
  let unFiles: () => void = () => {};
  let unEvents: () => void = () => {};

  let connected = $derived(devices.filter((d) => d.connected));

  async function refresh() {
    devices = await api.listDevices();
    if (!target && connected.length) target = connected[0].id;
  }

  onMount(async () => {
    await refresh();
    unFiles = await onFileDrop(async (paths) => {
      if (!target) {
        activity = ['Drop ignored — no connected peer selected', ...activity];
        return;
      }
      for (const p of paths) {
        await api.sendFile(target, p);
        activity = [`Sending ${p.split('/').pop()} →`, ...activity].slice(0, 30);
      }
    });
    unEvents = onEngineEvent((p: any) => {
      if (p?.type === 'fileSent') activity = [`Sent ${p.name} ✓`, ...activity].slice(0, 30);
      if (p?.type === 'fileReceived')
        activity = [`Received ${p.name} ${p.ok ? '✓' : '(checksum failed!)'}`, ...activity].slice(0, 30);
    });
  });
  onDestroy(() => {
    unFiles();
    unEvents();
  });
</script>

<h2>File transfer</h2>
<p class="sub">
  Drag files onto the drop zone to send them to a connected laptop. Received files
  land in your <b>Downloads</b> folder. (Enable <b>File transfer</b> in the Sharing tab
  on both devices first.)
</p>

{#if connected.length === 0}
  <p class="sub">No connected laptops. Pair and connect one in the Devices tab.</p>
{:else}
  <div class="picker">
    <label for="target">Send to:</label>
    <select id="target" bind:value={target}>
      {#each connected as d (d.id)}
        <option value={d.id}>{d.name}</option>
      {/each}
    </select>
  </div>

  <div
    class="dropzone"
    class:over={dragOver}
    role="region"
    ondragover={(e) => {
      e.preventDefault();
      dragOver = true;
    }}
    ondragleave={() => (dragOver = false)}
    ondrop={() => (dragOver = false)}
  >
    <div class="big">⬇</div>
    <div>Drop files here to send to <b>{connected.find((d) => d.id === target)?.name}</b></div>
  </div>
{/if}

<section class="card">
  <h3>Transfers</h3>
  <pre>{activity.join('\n') || 'No transfers yet.'}</pre>
</section>

<style>
  .picker { display: flex; gap: 10px; align-items: center; margin-bottom: 14px; }
  select { background: var(--panel2); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 7px 10px; }
  .dropzone {
    border: 2px dashed var(--border); border-radius: 12px; padding: 48px; text-align: center;
    color: var(--muted); background: var(--panel); margin-bottom: 18px; max-width: 640px;
    transition: border-color 0.1s, background 0.1s;
  }
  .dropzone.over { border-color: var(--accent); background: var(--panel2); color: var(--text); }
  .big { font-size: 40px; margin-bottom: 8px; color: var(--accent); }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px; max-width: 640px; }
  h3 { margin: 0 0 10px; font-size: 15px; }
  pre { margin: 0; font-size: 12px; color: var(--muted); white-space: pre-wrap; max-height: 220px; overflow: auto; }
</style>
