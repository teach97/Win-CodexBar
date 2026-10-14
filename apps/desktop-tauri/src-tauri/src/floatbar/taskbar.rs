//! Native taskbar parenting and monitor-relative placement for the FloatBar.

#[cfg(not(windows))]
use codexbar::settings::Settings;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct TaskbarSnapshot {
    pub id: String,
    pub name: String,
    pub primary: bool,
    pub width: u32,
    pub height: u32,
}

#[cfg(any(windows, test))]
fn horizontal_position(available: i32, width: i32, percent: u8) -> i32 {
    let span = (available - width).max(0);
    (f64::from(span) * f64::from(percent.min(100)) / 100.0).round() as i32
}

#[cfg(windows)]
mod platform {
    use super::{TaskbarSnapshot, horizontal_position};
    use codexbar::settings::Settings;
    use raw_window_handle::HasWindowHandle;
    use std::ffi::c_void;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Rect {
        left: i32,
        top: i32,
        right: i32,
        bottom: i32,
    }

    #[repr(C)]
    struct MonitorInfo {
        size: u32,
        monitor: Rect,
        work: Rect,
        flags: u32,
        device: [u8; 32],
    }

    struct Taskbar {
        hwnd: isize,
        snapshot: TaskbarSnapshot,
    }

    #[derive(Clone)]
    struct Config {
        monitor: String,
        position: u8,
    }

    #[derive(Clone, Copy)]
    struct SavedWindow {
        hwnd: isize,
        style: isize,
        extended_style: isize,
        left: i32,
        top: i32,
    }

    static DOCKED: AtomicBool = AtomicBool::new(false);
    static CONFIG: Mutex<Option<Config>> = Mutex::new(None);
    static SAVED_WINDOW: Mutex<Option<SavedWindow>> = Mutex::new(None);

    const GWL_STYLE: i32 = -16;
    const GWL_EXSTYLE: i32 = -20;
    const WS_CHILD: isize = 0x4000_0000;
    const WS_POPUP: isize = 0x8000_0000;
    const WS_OVERLAPPEDWINDOW: isize = 0x00cf_0000;
    const WS_EX_TOPMOST: isize = 0x0000_0008;
    const WS_EX_APPWINDOW: isize = 0x0004_0000;
    const SWP_NOACTIVATE: u32 = 0x0010;
    const SWP_FRAMECHANGED: u32 = 0x0020;
    const SWP_NOSIZE: u32 = 0x0001;
    const SWP_NOZORDER: u32 = 0x0004;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn taskbars() -> Vec<Taskbar> {
        let primary_class = wide("Shell_TrayWnd");
        let secondary_class = wide("Shell_SecondaryTrayWnd");
        let mut handles = Vec::new();
        // SAFETY: Both class names are NUL-terminated and live for every call.
        unsafe {
            let primary = FindWindowW(primary_class.as_ptr(), std::ptr::null());
            if primary != 0 {
                handles.push(primary);
            }
            let mut previous = 0;
            loop {
                let handle = FindWindowExW(0, previous, secondary_class.as_ptr(), std::ptr::null());
                if handle == 0 {
                    break;
                }
                handles.push(handle);
                previous = handle;
            }
        }
        handles
            .into_iter()
            .filter_map(|hwnd| {
                let mut info = MonitorInfo {
                    size: std::mem::size_of::<MonitorInfo>() as u32,
                    monitor: Rect::default(),
                    work: Rect::default(),
                    flags: 0,
                    device: [0; 32],
                };
                // SAFETY: HWNDs are queried without dereferencing; info is a correctly
                // sized writable MONITORINFOEXA buffer. Device identifiers are ASCII.
                if unsafe { GetMonitorInfoA(MonitorFromWindow(hwnd, 2), &mut info) } == 0 {
                    return None;
                }
                let length = info.device.iter().position(|c| *c == 0).unwrap_or(32);
                let id = String::from_utf8_lossy(&info.device[..length]).into_owned();
                Some(Taskbar {
                    hwnd,
                    snapshot: TaskbarSnapshot {
                        name: id.trim_start_matches(r"\\.\").to_string(),
                        id,
                        primary: info.flags & 1 != 0,
                        width: (info.monitor.right - info.monitor.left).max(0) as u32,
                        height: (info.monitor.bottom - info.monitor.top).max(0) as u32,
                    },
                })
            })
            .collect()
    }

    pub fn list() -> Vec<TaskbarSnapshot> {
        taskbars().into_iter().map(|bar| bar.snapshot).collect()
    }

    pub fn is_docked() -> bool {
        DOCKED.load(Ordering::Acquire)
    }

    pub fn forget_window() {
        *SAVED_WINDOW.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub fn stop() {
        DOCKED.store(false, Ordering::Release);
        *CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn hwnd(window: &tauri::WebviewWindow) -> Result<isize, String> {
        let handle = window.window_handle().map_err(|e| e.to_string())?;
        match handle.as_raw() {
            raw_window_handle::RawWindowHandle::Win32(handle) => Ok(handle.hwnd.get()),
            _ => Err("The floating bar does not have a Windows window handle.".into()),
        }
    }

    pub fn apply(window: &tauri::WebviewWindow, settings: &Settings) -> Result<(), String> {
        let docked = settings.float_bar_taskbar_docked && settings.float_bar_style == "taskbar";
        let config = Config {
            monitor: settings.float_bar_taskbar_monitor.clone(),
            position: settings.float_bar_taskbar_position,
        };
        on_main_thread(window, move |window| {
            apply_on_main_thread(window, docked, config)
        })
    }

    fn on_main_thread<F>(window: &tauri::WebviewWindow, operation: F) -> Result<(), String>
    where
        F: FnOnce(&tauri::WebviewWindow) -> Result<(), String> + Send + 'static,
    {
        let target = window.clone();
        let (send, receive) = std::sync::mpsc::channel();
        window
            .run_on_main_thread(move || {
                let _ = send.send(operation(&target));
            })
            .map_err(|e| e.to_string())?;
        receive.recv().map_err(|e| e.to_string())?
    }

    fn apply_on_main_thread(
        window: &tauri::WebviewWindow,
        docked: bool,
        config: Config,
    ) -> Result<(), String> {
        if !docked {
            stop();
            return detach(window);
        }
        *CONFIG.lock().unwrap_or_else(|e| e.into_inner()) = Some(config);
        DOCKED.store(true, Ordering::Release);
        window.set_always_on_top(false).map_err(|e| e.to_string())?;
        refresh_on_main_thread(window)
    }

    pub fn refresh(window: &tauri::WebviewWindow) -> Result<(), String> {
        on_main_thread(window, refresh_on_main_thread)
    }

    fn refresh_on_main_thread(window: &tauri::WebviewWindow) -> Result<(), String> {
        let config = CONFIG.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let Some(config) = config else { return Ok(()) };
        let bars = taskbars();
        let bar = bars
            .iter()
            .find(|bar| bar.snapshot.id == config.monitor)
            .or_else(|| bars.iter().find(|bar| bar.snapshot.primary))
            .or_else(|| bars.first())
            .ok_or("No Windows taskbar is available.")?;
        let child = hwnd(window)?;
        let mut client = Rect::default();
        let mut bounds = Rect::default();
        // SAFETY: HWNDs are native handles and both output RECT buffers outlive the calls.
        if unsafe { GetClientRect(bar.hwnd, &mut client) } == 0
            || unsafe { GetWindowRect(child, &mut bounds) } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let available_width = (client.right - client.left).max(1);
        let available_height = (client.bottom - client.top).max(1);
        let width = (bounds.right - bounds.left).clamp(1, available_width);
        let x = horizontal_position(available_width, width, config.position);
        let mut attach = false;
        // SAFETY: All operations target our FloatBar HWND; the shell HWND is only
        // its parent. Never change the shell's styles, layout, or process.
        unsafe {
            if GetParent(child) != bar.hwnd {
                if AreDpiAwarenessContextsEqual(
                    GetWindowDpiAwarenessContext(child),
                    GetWindowDpiAwarenessContext(bar.hwnd),
                ) == 0
                {
                    return Err(
                        "The taskbar and floating bar use incompatible display scaling.".into(),
                    );
                }
                let mut saved = SAVED_WINDOW.lock().unwrap_or_else(|e| e.into_inner());
                if saved.is_none_or(|saved| saved.hwnd != child) {
                    *saved = Some(SavedWindow {
                        hwnd: child,
                        style: GetWindowLongPtrW(child, GWL_STYLE),
                        extended_style: GetWindowLongPtrW(child, GWL_EXSTYLE),
                        left: bounds.left,
                        top: bounds.top,
                    });
                }
                drop(saved);
                let style = GetWindowLongPtrW(child, GWL_STYLE);
                SetWindowLongPtrW(
                    child,
                    GWL_STYLE,
                    (style & !(WS_POPUP | WS_OVERLAPPEDWINDOW)) | WS_CHILD,
                );
                let extended = GetWindowLongPtrW(child, GWL_EXSTYLE);
                SetWindowLongPtrW(
                    child,
                    GWL_EXSTYLE,
                    extended & !(WS_EX_TOPMOST | WS_EX_APPWINDOW),
                );
                SetLastError(0);
                SetParent(child, bar.hwnd);
                if GetParent(child) != bar.hwnd {
                    let error = std::io::Error::last_os_error().to_string();
                    let _ = detach(window);
                    return Err(error);
                }
                attach = true;
            }
            let mut current = Rect::default();
            GetClientRect(child, &mut current);
            let mut point = Point {
                x: bounds.left,
                y: bounds.top,
            };
            ScreenToClient(bar.hwnd, &mut point);
            if (attach
                || point.x != x
                || point.y != 0
                || current.right != width
                || current.bottom != available_height)
                && SetWindowPos(
                    child,
                    0,
                    x,
                    0,
                    width,
                    available_height,
                    SWP_NOACTIVATE | if attach { SWP_FRAMECHANGED } else { 0 },
                ) == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        Ok(())
    }

    fn detach(window: &tauri::WebviewWindow) -> Result<(), String> {
        let child = hwnd(window)?;
        let saved = SAVED_WINDOW
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        let Some(saved) = saved.filter(|saved| saved.hwnd == child) else {
            return Ok(());
        };
        // SAFETY: Restore only our captured HWND styles/position, without activation.
        unsafe {
            SetLastError(0);
            SetParent(child, 0);
            if GetParent(child) != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            SetWindowLongPtrW(child, GWL_STYLE, saved.style);
            SetWindowLongPtrW(child, GWL_EXSTYLE, saved.extended_style);
            if SetWindowPos(
                child,
                0,
                saved.left,
                saved.top,
                0,
                0,
                SWP_NOACTIVATE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED,
            ) == 0
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        window.set_always_on_top(true).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[repr(C)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn FindWindowW(class: *const u16, name: *const u16) -> isize;
        fn FindWindowExW(parent: isize, after: isize, class: *const u16, name: *const u16)
        -> isize;
        fn MonitorFromWindow(hwnd: isize, flags: u32) -> isize;
        fn GetMonitorInfoA(monitor: isize, info: *mut MonitorInfo) -> i32;
        fn GetClientRect(hwnd: isize, rect: *mut Rect) -> i32;
        fn GetWindowRect(hwnd: isize, rect: *mut Rect) -> i32;
        fn ScreenToClient(hwnd: isize, point: *mut Point) -> i32;
        fn GetWindowLongPtrW(hwnd: isize, index: i32) -> isize;
        fn SetWindowLongPtrW(hwnd: isize, index: i32, value: isize) -> isize;
        fn GetParent(hwnd: isize) -> isize;
        fn SetParent(hwnd: isize, parent: isize) -> isize;
        fn GetWindowDpiAwarenessContext(hwnd: isize) -> *mut c_void;
        fn AreDpiAwarenessContextsEqual(first: *mut c_void, second: *mut c_void) -> i32;
        fn SetWindowPos(
            hwnd: isize,
            after: isize,
            x: i32,
            y: i32,
            width: i32,
            height: i32,
            flags: u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetLastError(error: u32);
    }
}

#[cfg(windows)]
pub use platform::{apply, forget_window, is_docked, list, refresh, stop};

#[cfg(not(windows))]
pub fn list() -> Vec<TaskbarSnapshot> {
    Vec::new()
}
#[cfg(not(windows))]
pub fn is_docked() -> bool {
    false
}
#[cfg(not(windows))]
pub fn forget_window() {}
#[cfg(not(windows))]
pub fn stop() {}
#[cfg(not(windows))]
pub fn apply(_: &tauri::WebviewWindow, _: &Settings) -> Result<(), String> {
    Ok(())
}
#[cfg(not(windows))]
pub fn refresh(_: &tauri::WebviewWindow) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_use_the_remaining_taskbar_span() {
        assert_eq!(horizontal_position(2560, 200, 0), 0);
        assert_eq!(horizontal_position(2560, 200, 50), 1180);
        assert_eq!(horizontal_position(2560, 200, 100), 2360);
    }

    #[test]
    fn oversized_widgets_and_invalid_percentages_stay_inside() {
        assert_eq!(horizontal_position(100, 200, 50), 0);
        assert_eq!(horizontal_position(1920, 200, 255), 1720);
    }
}
