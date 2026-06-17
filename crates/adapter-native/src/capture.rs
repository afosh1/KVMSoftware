//! Global input capture via `rdev` (cross-platform).
//!
//! `rdev::listen` runs a blocking OS event loop, so we drive it on a dedicated
//! thread and forward mapped events to the sink. A `running` flag gates
//! forwarding (the engine only wants events while it is the controller).
//!
//! KNOWN LIMITATION (on-hardware completion item): `rdev::listen` *observes*
//! events without suppressing them, so while controlling a remote peer the local
//! machine still reacts to the same input. Exclusive grab/suppression
//! (`rdev`'s unstable grab, or evdev/CGEventTap/`SetWindowsHookEx` directly) is
//! the platform-specific hardening step. The trait boundary is unchanged.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use kvm_adapter_api::{EventSink, InputCapture, LocalInput, PermissionStatus, Result};

use crate::keymap::{button_from_rdev, rdev_key_to_evdev};

#[derive(Default)]
pub struct RdevCapture {
    running: Arc<AtomicBool>,
    started: bool,
    #[cfg(target_os = "linux")]
    grabber: std::sync::Mutex<Option<crate::linux::X11Grabber>>,
}

impl RdevCapture {
    pub fn new() -> Self {
        Self::default()
    }
}

fn map_event(event: rdev::Event) -> Option<LocalInput> {
    use rdev::EventType::*;
    match event.event_type {
        KeyPress(k) => rdev_key_to_evdev(k).map(|code| LocalInput::Key {
            code,
            pressed: true,
        }),
        KeyRelease(k) => rdev_key_to_evdev(k).map(|code| LocalInput::Key {
            code,
            pressed: false,
        }),
        ButtonPress(b) => button_from_rdev(b).map(|button| LocalInput::Button {
            button,
            pressed: true,
        }),
        ButtonRelease(b) => button_from_rdev(b).map(|button| LocalInput::Button {
            button,
            pressed: false,
        }),
        MouseMove { x, y } => Some(LocalInput::MouseMoveAbs {
            x: x as i32,
            y: y as i32,
        }),
        Wheel { delta_x, delta_y } => Some(LocalInput::Wheel {
            dx: delta_x as i32,
            dy: delta_y as i32,
        }),
    }
}

impl InputCapture for RdevCapture {
    fn start(&mut self, sink: EventSink) -> Result<()> {
        // rdev::listen cannot be cleanly stopped; we start it once and gate
        // forwarding via the `running` flag.
        self.running.store(true, Ordering::SeqCst);
        if self.started {
            return Ok(());
        }
        self.started = true;
        let running = self.running.clone();
        std::thread::Builder::new()
            .name("kvm-capture".into())
            .spawn(move || {
                let cb = move |event: rdev::Event| {
                    if !running.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Some(li) = map_event(event) {
                        sink(li);
                    }
                };
                if let Err(e) = rdev::listen(cb) {
                    tracing::error!(?e, "rdev capture loop ended");
                }
            })
            .map_err(|e| kvm_adapter_api::AdapterError::Backend(e.to_string()))?;
        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        Ok(())
    }

    fn set_exclusive(&self, on: bool) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let mut g = self.grabber.lock().unwrap();
            if on {
                if g.is_none() {
                    *g = Some(crate::linux::X11Grabber::new()?);
                }
                if let Some(grab) = g.as_ref() {
                    grab.grab()?;
                }
            } else if let Some(grab) = g.as_ref() {
                grab.ungrab()?;
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Exclusive grab on Windows/macOS is a future item (rdev unstable
            // grab / CGEventTap suppression / low-level-hook eat).
            let _ = on;
            Ok(())
        }
    }

    fn permission_status(&self) -> PermissionStatus {
        #[cfg(target_os = "macos")]
        {
            // macOS requires Accessibility + Input Monitoring; we can't query it
            // synchronously here, so report NotDetermined and let the wizard
            // guide the user.
            PermissionStatus::NotDetermined
        }
        #[cfg(not(target_os = "macos"))]
        {
            PermissionStatus::NotRequired
        }
    }
}
