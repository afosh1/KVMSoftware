import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  // Tauri expects a fixed dev port and shouldn't clear the terminal.
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true
  }
});
