use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const PIPE_NAME: &str = r"\\.\pipe\peregrine_ipc";
const BUF_SIZE: u32 = 65536;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;

pub type IpcMessage = serde_json::Value;
pub type IpcReceiver = std::sync::mpsc::Receiver<IpcMessage>;

pub fn start_ipc_server(stop: Arc<AtomicBool>) -> IpcReceiver {
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        use windows::core::PCWSTR;
        use windows::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows::Win32::Storage::FileSystem::ReadFile;
        use windows::Win32::System::Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe,
            PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
        };

        let wide: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();

        // SYSTEM + Administrators full access; Authenticated Users read/write
        // so medium-IL injected game processes can still send telemetry.
        // Everyone (WD) is intentionally not granted access.
        let sddl: Vec<u16> =
            "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;AU)\0".encode_utf16().collect();
        let mut sd_ptr: *mut windows::Win32::Security::SECURITY_DESCRIPTOR =
            std::ptr::null_mut();
        unsafe {
            let _ = windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                windows::core::PCWSTR(sddl.as_ptr()),
                1,
                &mut sd_ptr as *mut _ as *mut _,
                None,
            );
        }

        let mut sa = windows::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd_ptr as *mut _,
            bInheritHandle: false.into(),
        };

        while !stop.load(Ordering::Relaxed) {
            let pipe = unsafe {
                CreateNamedPipeW(
                    PCWSTR(wide.as_ptr()),
                    windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(
                        PIPE_ACCESS_DUPLEX,
                    ),
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                    PIPE_UNLIMITED_INSTANCES,
                    BUF_SIZE,
                    BUF_SIZE,
                    0,
                    Some(&mut sa),
                )
            };

            if pipe == INVALID_HANDLE_VALUE {
                std::thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }

            if unsafe { ConnectNamedPipe(pipe, None) }.is_err() {
                let _ = unsafe { CloseHandle(pipe) };
                continue;
            }

            eprintln!("[DBG] IPC client connected");

            let tx2 = tx.clone();
            let stop2 = stop.clone();
            let raw = pipe.0 as usize;

            std::thread::spawn(move || {
                use windows::Win32::Foundation::HANDLE;
                let pipe = HANDLE(raw as *mut _);
                let mut buf = vec![0u8; BUF_SIZE as usize];
                let mut leftover = Vec::new();

                while !stop2.load(Ordering::Relaxed) {
                    let mut read = 0u32;
                    let ok =
                        unsafe { ReadFile(pipe, Some(&mut buf), Some(&mut read), None) };
                    if ok.is_err() || read == 0 {
                        break;
                    }

                    leftover.extend_from_slice(&buf[..read as usize]);

                    // Split on JSON boundaries (each message is one {...} object)
                    while let Some(end) = find_json_end(&leftover) {
                        let chunk = &leftover[..=end];
                        if let Ok(s) = std::str::from_utf8(chunk) {
                            if let Ok(msg) = serde_json::from_str::<serde_json::Value>(s) {
                                let _ = tx2.send(msg);
                            }
                        }
                        leftover = leftover[end + 1..].to_vec();
                    }
                }

                let _ = unsafe { DisconnectNamedPipe(pipe) };
                let _ = unsafe { CloseHandle(pipe) };
                eprintln!("[DBG] IPC client disconnected");
            });
        }
    });

    rx
}

fn find_json_end(data: &[u8]) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;

    for (i, &b) in data.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        if b == b'\\' && in_string {
            escape = true;
            continue;
        }
        if b == b'"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        }
    }
    None
}
