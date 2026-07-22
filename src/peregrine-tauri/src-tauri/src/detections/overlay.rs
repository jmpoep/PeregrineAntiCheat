use serde::Serialize;
use windows::core::BOOL;
use windows::Win32::Foundation::{HWND, LPARAM, RECT};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowLongW, GetWindowRect, GetWindowTextW,
    GetWindowThreadProcessId, IsWindowVisible, GWL_EXSTYLE, WS_EX_LAYERED, WS_EX_TOPMOST,
    WS_EX_TRANSPARENT,
};

#[derive(Debug, Clone, Serialize)]
pub struct OverlayWindow {
    pub hwnd: u64,
    pub class_name: String,
    pub title: String,
    pub pid: u32,
    pub layered: bool,
    pub transparent: bool,
    pub topmost: bool,
    pub near_fullscreen: bool,
}

struct EnumCtx {
    self_pid: u32,
    hits: Vec<OverlayWindow>,
}

fn screen_metrics() -> (i32, i32) {
    use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};
    unsafe {
        (
            GetSystemMetrics(SM_CXSCREEN),
            GetSystemMetrics(SM_CYSCREEN),
        )
    }
}

unsafe extern "system" fn enum_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let ctx = &mut *(lparam.0 as *mut EnumCtx);

    if !IsWindowVisible(hwnd).as_bool() {
        return BOOL(1);
    }

    let mut pid: u32 = 0;
    GetWindowThreadProcessId(hwnd, Some(&mut pid));
    if pid == 0 || pid == ctx.self_pid {
        return BOOL(1);
    }

    let ex = GetWindowLongW(hwnd, GWL_EXSTYLE) as u32;
    let layered = (ex & WS_EX_LAYERED.0) != 0;
    let transparent = (ex & WS_EX_TRANSPARENT.0) != 0;
    let topmost = (ex & WS_EX_TOPMOST.0) != 0;

    let mut rect = RECT::default();
    if GetWindowRect(hwnd, &mut rect).is_err() {
        return BOOL(1);
    }

    let (sw, sh) = screen_metrics();
    let ww = rect.right - rect.left;
    let wh = rect.bottom - rect.top;
    // Near-fullscreen: covers >= 90% of either dimension and large area
    let near_fullscreen = sw > 0
        && sh > 0
        && ww as f32 >= sw as f32 * 0.9
        && wh as f32 >= sh as f32 * 0.9;

    // Heuristic: interesting overlays are layered and/or transparent, or topmost+fullscreen.
    let interesting = layered || transparent || (topmost && near_fullscreen);
    if !interesting {
        return BOOL(1);
    }

    // Skip common OS shells / desktop chrome
    let mut class_buf = [0u16; 256];
    let class_len = GetClassNameW(hwnd, &mut class_buf);
    let class_name = if class_len > 0 {
        String::from_utf16_lossy(&class_buf[..class_len as usize])
    } else {
        String::new()
    };

    let skip_classes = [
        "Shell_TrayWnd",
        "Shell_SecondaryTrayWnd",
        "Progman",
        "WorkerW",
        "Windows.UI.Core.CoreWindow",
        "XamlExplorerHostIslandWindow",
        "ApplicationFrameWindow",
    ];
    if skip_classes.iter().any(|c| class_name.eq_ignore_ascii_case(c)) {
        return BOOL(1);
    }

    let mut title_buf = [0u16; 512];
    let title_len = GetWindowTextW(hwnd, &mut title_buf);
    let title = if title_len > 0 {
        String::from_utf16_lossy(&title_buf[..title_len as usize])
    } else {
        String::new()
    };

    ctx.hits.push(OverlayWindow {
        hwnd: hwnd.0 as usize as u64,
        class_name,
        title,
        pid,
        layered,
        transparent,
        topmost,
        near_fullscreen,
    });

    BOOL(1)
}

pub fn detect_overlays() -> Vec<OverlayWindow> {
    let mut ctx = EnumCtx {
        self_pid: std::process::id(),
        hits: Vec::new(),
    };

    let _ = unsafe {
        EnumWindows(
            Some(enum_proc),
            LPARAM(&mut ctx as *mut EnumCtx as isize),
        )
    };

    ctx.hits
}
