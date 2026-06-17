# App icons

Tauri's bundler expects the icon set referenced in `tauri.conf.json`
(`32x32.png`, `128x128.png`, `128x128@2x.png`, `icon.icns`, `icon.ico`).

Generate the whole set from a single 1024×1024 source PNG:

```sh
pnpm -C app/kvm-desktop install
pnpm -C app/kvm-desktop tauri icon path/to/source-1024.png
```

This writes all required sizes/formats into this directory. They are required
for `tauri build` (the release bundle) but **not** for `cargo check`/`cargo test`
or `tauri dev`.
