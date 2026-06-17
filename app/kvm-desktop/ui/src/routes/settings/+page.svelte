<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type DeviceInfo, type ClipboardPolicy } from '$lib/api';

  let devices = $state<DeviceInfo[]>([]);
  let selected = $state<string>('');
  let policy = $state<ClipboardPolicy>({ share_text: true, share_images: false, share_files: false });
  let exclusive = $state(false);

  async function toggleExclusive() {
    await api.setExclusive(exclusive);
  }

  onMount(async () => {
    devices = (await api.listDevices()).filter((d) => d.trust !== 'Untrusted');
    if (devices.length) {
      selected = devices[0].id;
      policy = await api.getPolicy(selected);
    }
  });

  async function pick(id: string) {
    selected = id;
    policy = await api.getPolicy(id);
  }
  async function save() {
    if (selected) await api.setPolicy(selected, policy);
  }
</script>

<h2>Sharing &amp; privacy</h2>
<p class="sub">Control what each paired device can share. Both ends must agree — anything off here is blocked, in either direction.</p>

<section class="card" style="margin-bottom:16px">
  <label class="toggle">
    <input type="checkbox" bind:checked={exclusive} onchange={toggleExclusive} />
    <div>
      <b>Exclusive control (true extended desktop)</b>
      <p class="sub">
        While you drive another laptop, suppress input on this one — only the active
        machine responds (instead of both cursors moving). Linux/X11 only for now.
        <b>Press Ctrl+Alt+Q to release</b> if the cursor ever gets stuck.
      </p>
    </div>
  </label>
</section>

{#if devices.length === 0}
  <p class="sub">No paired devices yet.</p>
{:else}
  <div class="picker">
    {#each devices as d (d.id)}
      <button class:active={selected === d.id} class="ghost" onclick={() => pick(d.id)}>{d.name}</button>
    {/each}
  </div>

  <section class="card">
    <label class="toggle">
      <input type="checkbox" bind:checked={policy.share_text} onchange={save} />
      <div>
        <b>Shared clipboard (text)</b>
        <p class="sub">Copy on one device, paste on another. On by default.</p>
      </div>
    </label>
    <label class="toggle">
      <input type="checkbox" bind:checked={policy.share_images} onchange={save} />
      <div>
        <b>Clipboard images</b>
        <p class="sub">Off by default — images can be large and sensitive.</p>
      </div>
    </label>
    <label class="toggle">
      <input type="checkbox" bind:checked={policy.share_files} onchange={save} />
      <div>
        <b>File transfer</b>
        <p class="sub">Off by default. Requires a fully-trusted device.</p>
      </div>
    </label>
  </section>
{/if}

<style>
  .picker { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .picker button.active { background: var(--accent); color: #fff; border-color: var(--accent); }
  .card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 6px 20px; max-width: 640px; }
  .toggle { display: flex; gap: 14px; align-items: flex-start; padding: 16px 0; border-top: 1px solid var(--border); }
  .toggle:first-child { border-top: 0; }
  .toggle input { width: 18px; height: 18px; margin-top: 3px; }
  .toggle p { margin: 2px 0 0; }
</style>
