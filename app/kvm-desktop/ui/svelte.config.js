import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  preprocess: vitePreprocess(),
  kit: {
    // SPA mode: Tauri serves the prebuilt static bundle.
    adapter: adapter({ fallback: 'index.html' })
  }
};

export default config;
