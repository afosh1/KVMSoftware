<script lang="ts">
  import { onMount } from 'svelte';
  import { api, type DeviceInfo } from '$lib/api';

  // 2D arrangement: drag each screen into a grid cell. Screens in adjacent cells
  // become seams (left↔right and top↔bottom), so the cursor can cross in any
  // direction — not just side-by-side.
  const COLS = 4;
  const ROWS = 3;

  type Pos = { col: number; row: number };
  let placements = $state<Record<string, Pos>>({});
  let labels = $state<Record<string, string>>({});
  let dragId = $state<string | null>(null);
  let saved = $state(false);

  onMount(async () => {
    const me = await api.identity();
    const peers = (await api.listDevices()).filter(
      (d) => d.trust === 'Trusted' || d.trust === 'Paired'
    );
    const next: Record<string, Pos> = {};
    const lab: Record<string, string> = {};
    next[me.device_id] = { col: 0, row: 1 };
    lab[me.device_id] = `${me.device_name} (this)`;
    peers.forEach((d: DeviceInfo, i: number) => {
      next[d.id] = { col: Math.min(i + 1, COLS - 1), row: 1 };
      lab[d.id] = d.name;
    });
    placements = next;
    labels = lab;
  });

  function deviceAt(col: number, row: number): string | null {
    return (
      Object.keys(placements).find(
        (id) => placements[id].col === col && placements[id].row === row
      ) ?? null
    );
  }

  function onDrop(col: number, row: number) {
    if (!dragId) return;
    const occupant = deviceAt(col, row);
    if (occupant && occupant !== dragId) {
      // swap the two screens' cells
      placements[occupant] = placements[dragId];
    }
    placements[dragId] = { col, row };
    placements = { ...placements };
    dragId = null;
    saved = false;
  }

  async function save() {
    await api.saveLayout({
      placements: Object.entries(placements).map(([id, p]) => ({
        id,
        col: p.col,
        row: p.row
      }))
    });
    saved = true;
  }
</script>

<h2>Screen layout</h2>
<p class="sub">
  Drag each screen into the cell that matches where it physically sits. Screens in
  neighbouring cells are linked, so your cursor can cross between them in that
  direction (left, right, up or down).
</p>

<div class="grid" style="--cols:{COLS}; --rows:{ROWS}">
  {#each Array.from({ length: ROWS }) as _, row}
    {#each Array.from({ length: COLS }) as _, col}
      {@const id = deviceAt(col, row)}
      <div
        class="cell"
        class:filled={!!id}
        role="gridcell"
        tabindex="-1"
        ondragover={(e) => e.preventDefault()}
        ondrop={() => onDrop(col, row)}
      >
        {#if id}
          <div class="screen" draggable="true" ondragstart={() => (dragId = id)} role="button" tabindex="0">
            {labels[id]}
          </div>
        {/if}
      </div>
    {/each}
  {/each}
</div>

<div class="row">
  <button onclick={save} disabled={Object.keys(placements).length === 0}>Save arrangement</button>
  {#if saved}<span class="ok">Saved ✓</span>{/if}
</div>

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(var(--cols), 1fr);
    grid-template-rows: repeat(var(--rows), 96px);
    gap: 8px;
    background: var(--panel);
    border: 1px dashed var(--border);
    border-radius: 12px;
    padding: 16px;
    margin-bottom: 18px;
    max-width: 720px;
  }
  .cell {
    border: 1px dashed var(--border);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .cell.filled {
    border-style: solid;
  }
  .screen {
    width: 100%;
    height: 100%;
    background: var(--panel2);
    border: 2px solid var(--accent);
    border-radius: 8px;
    display: flex;
    align-items: center;
    justify-content: center;
    text-align: center;
    font-size: 13px;
    cursor: grab;
    user-select: none;
    padding: 4px;
  }
  .screen:active {
    cursor: grabbing;
  }
  .row {
    display: flex;
    gap: 12px;
    align-items: center;
  }
  .ok {
    color: var(--good);
  }
</style>
