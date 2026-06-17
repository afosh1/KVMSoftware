// Thin wrapper over the Tauri command/event bridge.
//
// When NOT running inside Tauri (e.g. `vite dev` in a browser, or CI build),
// calls resolve to demo data so the UI is developable standalone.

import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';

export const inTauri =
  typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

export interface IdentityInfo {
  device_id: string;
  device_name: string;
  fingerprint: string;
  platform: string;
}

export interface DeviceInfo {
  id: string;
  name: string;
  platform: string;
  fingerprint: string;
  trust: 'Untrusted' | 'PairingInProgress' | 'Paired' | 'Trusted' | 'Revoked';
  connected: boolean;
}

export interface ClipboardPolicy {
  share_text: boolean;
  share_images: boolean;
  share_files: boolean;
}

export interface Diagnostics {
  focus: string;
  session: string;
  connected_peers: string[];
  rtt_ms: number | null;
  loss_pct: number;
}

export interface PermissionState {
  capture: string;
  injection: string;
}

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!inTauri) return demo<T>(cmd);
  return invoke<T>(cmd, args);
}

export const api = {
  identity: () => call<IdentityInfo>('get_identity'),
  permissions: () => call<PermissionState>('get_permissions'),
  listDevices: () => call<DeviceInfo[]>('list_devices'),
  beginPairing: (peerId: string) => call<string>('begin_pairing', { peerId }),
  confirmPairing: (peerId: string, code: string) =>
    call<void>('confirm_pairing', { peerId, code }),
  revoke: (peerId: string) => call<void>('revoke_device', { peerId }),
  forget: (peerId: string) => call<void>('forget_device', { peerId }),
  rename: (peerId: string, name: string) =>
    call<void>('rename_device', { peerId, name }),
  connect: (peerId: string) => call<void>('connect_device', { peerId }),
  getPolicy: (peerId: string) => call<ClipboardPolicy>('get_policy', { peerId }),
  setPolicy: (peerId: string, policy: ClipboardPolicy) =>
    call<void>('set_policy', { peerId, policy }),
  saveLayout: (graph: unknown) => call<void>('save_layout', { graph }),
  manualSwitch: (target: string) => call<void>('manual_switch', { target }),
  release: () => call<void>('release'),
  setExclusive: (enabled: boolean) => call<void>('set_exclusive_control', { enabled }),
  sendFile: (peerId: string, path: string) => call<void>('send_file', { peerId, path }),
  diagnostics: () => call<Diagnostics>('diagnostics')
};

/// Subscribe to OS file drops onto the window. Returns an unlisten function.
export async function onFileDrop(cb: (paths: string[]) => void): Promise<() => void> {
  if (!inTauri) return () => {};
  const { getCurrentWebview } = await import('@tauri-apps/api/webview');
  const un = await getCurrentWebview().onDragDropEvent((event) => {
    if (event.payload.type === 'drop') cb(event.payload.paths);
  });
  return un;
}

export function onEngineEvent(cb: (payload: unknown) => void): () => void {
  if (!inTauri) return () => {};
  const un = listen('engine-event', (e) => cb(e.payload));
  return () => {
    void un.then((f) => f());
  };
}

// --- demo data for standalone development ---
function demo<T>(cmd: string): T {
  const data: Record<string, unknown> = {
    get_identity: {
      device_id: '11111111-1111-1111-1111-111111111111',
      device_name: 'this-laptop',
      fingerprint: 'ab12cd34ef56'.padEnd(64, '0'),
      platform: 'linux'
    },
    get_permissions: { capture: 'Granted', injection: 'Granted' },
    list_devices: [
      {
        id: '22222222-2222-2222-2222-222222222222',
        name: 'studio-mac',
        platform: 'macos',
        fingerprint: 'ff00ff00'.padEnd(64, '0'),
        trust: 'Trusted',
        connected: true
      },
      {
        id: '33333333-3333-3333-3333-333333333333',
        name: 'desk-windows',
        platform: 'windows',
        fingerprint: '99aa99aa'.padEnd(64, '0'),
        trust: 'Untrusted',
        connected: false
      }
    ],
    get_policy: { share_text: true, share_images: false, share_files: false },
    diagnostics: {
      focus: 'LocalControl',
      session: 'Active',
      connected_peers: ['22222222-2222-2222-2222-222222222222'],
      rtt_ms: 3,
      loss_pct: 0.0
    },
    begin_pairing: '428193'
  };
  return (data[cmd] ?? null) as T;
}
