//! Clipboard via `arboard` (cross-platform).
//!
//! The arboard handle is created lazily and **kept alive** for the process
//! lifetime. This matters on X11: the clipboard selection is owned by a live
//! connection, so dropping the handle would lose ownership and break paste.

use std::borrow::Cow;
use std::sync::Mutex;

use kvm_adapter_api::{AdapterError, Clipboard, ClipboardImage, Result};

#[derive(Default)]
pub struct ArboardClipboard {
    inner: Mutex<Option<arboard::Clipboard>>,
}

impl ArboardClipboard {
    pub fn new() -> Self {
        Self::default()
    }

    fn ensure(&self) -> Result<()> {
        let mut guard = self.inner.lock().unwrap();
        if guard.is_none() {
            let cb = arboard::Clipboard::new().map_err(|e| AdapterError::Backend(e.to_string()))?;
            *guard = Some(cb);
        }
        Ok(())
    }
}

impl Clipboard for ArboardClipboard {
    fn read_text(&self) -> Result<Option<String>> {
        self.ensure()?;
        let mut guard = self.inner.lock().unwrap();
        let cb = guard.as_mut().expect("ensured");
        match cb.get_text() {
            Ok(t) => Ok(Some(t)),
            // An empty/non-text clipboard is not an error for our purposes.
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(AdapterError::Backend(e.to_string())),
        }
    }

    fn write_text(&self, text: &str) -> Result<()> {
        self.ensure()?;
        let mut guard = self.inner.lock().unwrap();
        let cb = guard.as_mut().expect("ensured");
        cb.set_text(text.to_owned())
            .map_err(|e| AdapterError::Backend(e.to_string()))
    }

    fn read_image(&self) -> Result<Option<ClipboardImage>> {
        self.ensure()?;
        let mut guard = self.inner.lock().unwrap();
        let cb = guard.as_mut().expect("ensured");
        match cb.get_image() {
            Ok(img) => Ok(Some(ClipboardImage {
                width: img.width as u32,
                height: img.height as u32,
                rgba: img.bytes.into_owned(),
            })),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(e) => Err(AdapterError::Backend(e.to_string())),
        }
    }

    fn write_image(&self, image: &ClipboardImage) -> Result<()> {
        self.ensure()?;
        let mut guard = self.inner.lock().unwrap();
        let cb = guard.as_mut().expect("ensured");
        let data = arboard::ImageData {
            width: image.width as usize,
            height: image.height as usize,
            bytes: Cow::Borrowed(&image.rgba),
        };
        cb.set_image(data)
            .map_err(|e| AdapterError::Backend(e.to_string()))
    }
}
