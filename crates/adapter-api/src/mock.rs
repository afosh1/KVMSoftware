//! In-memory mock adapters for testing the engine and domain end-to-end with no
//! hardware or permissions. Always compiled (the engine's integration tests use
//! them), and cheap.

use std::sync::{Arc, Mutex};

use crate::{
    Clipboard, CursorGeometry, EventSink, InputCapture, InputInjection, LocalInput, Monitor,
    MouseButton, PermissionStatus, Point, Rect, Result,
};

/// Records every injected action so tests can assert on what was driven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InjectionCall {
    MoveAbs(i32, i32),
    MoveRel(i32, i32),
    Button(MouseButton, bool),
    Wheel(i32, i32),
    Key(u32, bool),
    ReleaseAll,
}

#[derive(Clone, Default)]
pub struct MockInjection {
    calls: Arc<Mutex<Vec<InjectionCall>>>,
}

impl MockInjection {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn calls(&self) -> Vec<InjectionCall> {
        self.calls.lock().unwrap().clone()
    }
    pub fn release_all_count(&self) -> usize {
        self.calls()
            .iter()
            .filter(|c| matches!(c, InjectionCall::ReleaseAll))
            .count()
    }
    fn push(&self, c: InjectionCall) {
        self.calls.lock().unwrap().push(c);
    }
}

impl InputInjection for MockInjection {
    fn move_abs(&self, x: i32, y: i32) -> Result<()> {
        self.push(InjectionCall::MoveAbs(x, y));
        Ok(())
    }
    fn move_rel(&self, dx: i32, dy: i32) -> Result<()> {
        self.push(InjectionCall::MoveRel(dx, dy));
        Ok(())
    }
    fn button(&self, b: MouseButton, pressed: bool) -> Result<()> {
        self.push(InjectionCall::Button(b, pressed));
        Ok(())
    }
    fn wheel(&self, dx: i32, dy: i32) -> Result<()> {
        self.push(InjectionCall::Wheel(dx, dy));
        Ok(())
    }
    fn key(&self, code: u32, pressed: bool) -> Result<()> {
        self.push(InjectionCall::Key(code, pressed));
        Ok(())
    }
    fn release_all(&self) -> Result<()> {
        self.push(InjectionCall::ReleaseAll);
        Ok(())
    }
    fn permission_status(&self) -> PermissionStatus {
        PermissionStatus::NotRequired
    }
}

/// Capture mock: tests inject simulated OS events via [`MockCapture::emit`].
#[derive(Clone, Default)]
pub struct MockCapture {
    sink: Arc<Mutex<Option<EventSink>>>,
    exclusive: Arc<Mutex<bool>>,
}

impl MockCapture {
    pub fn new() -> Self {
        Self::default()
    }
    /// Simulate the OS delivering an input event. No-op if not started.
    pub fn emit(&self, ev: LocalInput) {
        let sink = self.sink.lock().unwrap().clone();
        if let Some(sink) = sink {
            sink(ev);
        }
    }
    pub fn is_running(&self) -> bool {
        self.sink.lock().unwrap().is_some()
    }
    /// Whether exclusive (local-input-suppressing) grab is currently engaged.
    pub fn is_exclusive(&self) -> bool {
        *self.exclusive.lock().unwrap()
    }
}

impl InputCapture for MockCapture {
    fn start(&mut self, sink: EventSink) -> Result<()> {
        *self.sink.lock().unwrap() = Some(sink);
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        *self.sink.lock().unwrap() = None;
        Ok(())
    }
    fn set_exclusive(&self, on: bool) -> Result<()> {
        *self.exclusive.lock().unwrap() = on;
        Ok(())
    }
    fn permission_status(&self) -> PermissionStatus {
        PermissionStatus::NotRequired
    }
}

#[derive(Clone, Default)]
pub struct MockClipboard {
    text: Arc<Mutex<Option<String>>>,
}

impl MockClipboard {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&self, text: &str) {
        *self.text.lock().unwrap() = Some(text.to_string());
    }
    /// Current clipboard contents (test convenience).
    pub fn current(&self) -> Option<String> {
        self.text.lock().unwrap().clone()
    }
}

impl Clipboard for MockClipboard {
    fn read_text(&self) -> Result<Option<String>> {
        Ok(self.text.lock().unwrap().clone())
    }
    fn write_text(&self, text: &str) -> Result<()> {
        *self.text.lock().unwrap() = Some(text.to_string());
        Ok(())
    }
}

/// Geometry mock with a configurable monitor set and a movable cursor.
#[derive(Clone)]
pub struct MockGeometry {
    monitors: Vec<Monitor>,
    cursor: Arc<Mutex<Point>>,
    hidden: Arc<Mutex<bool>>,
}

impl MockGeometry {
    /// A single 1920x1080 primary monitor with the cursor centered.
    pub fn single_1080p() -> Self {
        Self::single(1920, 1080, 1.0)
    }

    /// A single primary monitor of the given size/scale, cursor centered.
    pub fn single(w: i32, h: i32, scale: f32) -> Self {
        MockGeometry {
            monitors: vec![Monitor {
                index: 0,
                bounds: Rect { x: 0, y: 0, w, h },
                scale,
                is_primary: true,
            }],
            cursor: Arc::new(Mutex::new(Point { x: w / 2, y: h / 2 })),
            hidden: Arc::new(Mutex::new(false)),
        }
    }
    pub fn set_cursor(&self, x: i32, y: i32) {
        *self.cursor.lock().unwrap() = Point { x, y };
    }
    /// Whether the local cursor is currently hidden (test convenience).
    pub fn is_hidden(&self) -> bool {
        *self.hidden.lock().unwrap()
    }
}

impl CursorGeometry for MockGeometry {
    fn cursor_position(&self) -> Result<Point> {
        Ok(*self.cursor.lock().unwrap())
    }
    fn warp_cursor(&self, x: i32, y: i32) -> Result<()> {
        *self.cursor.lock().unwrap() = Point { x, y };
        Ok(())
    }
    fn monitors(&self) -> Result<Vec<Monitor>> {
        Ok(self.monitors.clone())
    }
    fn hide_cursor(&self) -> Result<()> {
        *self.hidden.lock().unwrap() = true;
        Ok(())
    }
    fn show_cursor(&self) -> Result<()> {
        *self.hidden.lock().unwrap() = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn injection_records_calls_including_release_all() {
        let inj = MockInjection::new();
        inj.key(30, true).unwrap();
        inj.move_rel(5, -5).unwrap();
        inj.release_all().unwrap();
        assert_eq!(
            inj.calls(),
            vec![
                InjectionCall::Key(30, true),
                InjectionCall::MoveRel(5, -5),
                InjectionCall::ReleaseAll,
            ]
        );
        assert_eq!(inj.release_all_count(), 1);
    }

    #[test]
    fn capture_emits_to_sink_after_start() {
        let mut cap = MockCapture::new();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        assert!(!cap.is_running());
        cap.start(Arc::new(move |ev| seen2.lock().unwrap().push(ev)))
            .unwrap();
        assert!(cap.is_running());
        cap.emit(LocalInput::Key {
            code: 1,
            pressed: true,
        });
        cap.stop().unwrap();
        cap.emit(LocalInput::Key {
            code: 2,
            pressed: true,
        }); // dropped (stopped)
        assert_eq!(
            *seen.lock().unwrap(),
            vec![LocalInput::Key {
                code: 1,
                pressed: true
            }]
        );
    }

    #[test]
    fn clipboard_and_geometry_mocks() {
        let cb = MockClipboard::new();
        assert_eq!(cb.read_text().unwrap(), None);
        cb.write_text("hello").unwrap();
        assert_eq!(cb.read_text().unwrap(), Some("hello".to_string()));

        let geo = MockGeometry::single_1080p();
        assert_eq!(geo.cursor_position().unwrap(), Point { x: 960, y: 540 });
        geo.warp_cursor(0, 0).unwrap();
        assert_eq!(geo.cursor_position().unwrap(), Point { x: 0, y: 0 });
        assert_eq!(geo.monitors().unwrap().len(), 1);
    }
}
