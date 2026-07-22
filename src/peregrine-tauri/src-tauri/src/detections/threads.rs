use super::pe::*;
use serde::Serialize;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Threading::{
    OpenThread, ResumeThread, SuspendThread, THREAD_ACCESS_RIGHTS, THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};

#[derive(Debug, Clone, Serialize)]
pub struct ThreadInfo {
    pub tid: u32,
    pub rip: u64,
    pub start_address: u64,
    pub rip_module: Option<String>,
    pub start_module: Option<String>,
    pub suspicious: bool,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
}

#[repr(C)]
#[allow(non_snake_case)]
struct M128A {
    Low: u64,
    High: i64,
}

#[repr(C, align(16))]
#[allow(non_snake_case)]
struct CONTEXT64 {
    P1Home: u64,
    P2Home: u64,
    P3Home: u64,
    P4Home: u64,
    P5Home: u64,
    P6Home: u64,
    ContextFlags: u32,
    MxCsr: u32,
    SegCs: u16,
    SegDs: u16,
    SegEs: u16,
    SegFs: u16,
    SegGs: u16,
    SegSs: u16,
    EFlags: u32,
    Dr0: u64,
    Dr1: u64,
    Dr2: u64,
    Dr3: u64,
    Dr6: u64,
    Dr7: u64,
    Rax: u64,
    Rcx: u64,
    Rdx: u64,
    Rbx: u64,
    Rsp: u64,
    Rbp: u64,
    Rsi: u64,
    Rdi: u64,
    R8: u64,
    R9: u64,
    R10: u64,
    R11: u64,
    R12: u64,
    R13: u64,
    R14: u64,
    R15: u64,
    Rip: u64,
    FltSave: [u8; 512],
    VectorRegister: [M128A; 26],
    VectorControl: u64,
    DebugControl: u64,
    LastBranchToRip: u64,
    LastBranchFromRip: u64,
    LastExceptionToRip: u64,
    LastExceptionFromRip: u64,
}

const CONTEXT_AMD64: u32 = 0x00100000;
const CONTEXT_FULL: u32 = CONTEXT_AMD64 | 0x07 | 0x10;

extern "system" {
    fn GetThreadContext(hThread: HANDLE, lpContext: *mut CONTEXT64) -> i32;
    fn NtQueryInformationThread(
        ThreadHandle: HANDLE,
        ThreadInformationClass: u32,
        ThreadInformation: *mut u64,
        ThreadInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

const THREAD_QUERY_SET_WIN32_START_ADDRESS: u32 = 9;

/// Enable SeDebugPrivilege so OpenThread/OpenProcess work on other sessions' processes.
pub fn enable_debug_privilege() {
    use windows::Win32::Foundation::LUID;
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            eprintln!("[ThreadScan] OpenProcessToken failed");
            return;
        }

        let mut luid = LUID::default();
        let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        if LookupPrivilegeValueW(None, windows::core::PCWSTR(name.as_ptr()), &mut luid).is_err() {
            let _ = CloseHandle(token);
            eprintln!("[ThreadScan] LookupPrivilegeValue SeDebugPrivilege failed");
            return;
        }

        let mut tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let ok = AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None);
        let _ = CloseHandle(token);
        if ok.is_err() {
            eprintln!("[ThreadScan] AdjustTokenPrivileges failed");
        } else {
            eprintln!("[ThreadScan] SeDebugPrivilege enabled");
        }
    }
}

struct SuspendGuard {
    handle: HANDLE,
    suspended: bool,
}

impl SuspendGuard {
    fn suspend(handle: HANDLE) -> Self {
        let prev = unsafe { SuspendThread(handle) };
        let suspended = prev != u32::MAX;
        Self { handle, suspended }
    }
}

impl Drop for SuspendGuard {
    fn drop(&mut self) {
        if self.suspended {
            let _ = unsafe { ResumeThread(self.handle) };
        }
    }
}

fn open_thread_best_effort(tid: u32) -> Option<(HANDLE, bool)> {
    // (handle, can_suspend_for_context)
    let attempts: &[(THREAD_ACCESS_RIGHTS, bool)] = &[
        (
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            true,
        ),
        (
            THREAD_SUSPEND_RESUME
                | THREAD_GET_CONTEXT
                | THREAD_QUERY_INFORMATION
                | THREAD_QUERY_LIMITED_INFORMATION,
            true,
        ),
        (
            THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
            false,
        ),
        (
            THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
            false,
        ),
        (THREAD_QUERY_LIMITED_INFORMATION, false),
    ];

    for &(access, can_ctx) in attempts {
        match unsafe { OpenThread(access, false, tid) } {
            Ok(h) if h != INVALID_HANDLE_VALUE => return Some((h, can_ctx)),
            _ => continue,
        }
    }
    None
}

fn query_start_address(th: HANDLE) -> u64 {
    let mut start_addr: u64 = 0;
    let status = unsafe {
        NtQueryInformationThread(
            th,
            THREAD_QUERY_SET_WIN32_START_ADDRESS,
            &mut start_addr,
            8,
            std::ptr::null_mut(),
        )
    };
    if status < 0 {
        0
    } else {
        start_addr
    }
}

fn module_for(modules: &[ModuleEntry], addr: u64) -> Option<String> {
    if addr == 0 {
        return None;
    }
    modules
        .iter()
        .find(|m| addr >= m.base as u64 && addr < (m.base + m.size) as u64)
        .map(|m| m.name().to_string())
}

pub fn check_all_threads(pid: u32) -> Result<Vec<ThreadInfo>, String> {
    enable_debug_privilege();

    let proc = ProcessHandle::open(pid).ok_or_else(|| {
        format!("OpenProcess({pid}) failed — is the PID correct and process still alive?")
    })?;
    let modules = proc.modules();
    eprintln!(
        "[ThreadScan] PID {} modules={} (for range checks)",
        pid,
        modules.len()
    );

    let self_tid = unsafe { windows::Win32::System::Threading::GetCurrentThreadId() };

    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
        .map_err(|e| format!("CreateToolhelp32Snapshot: {e}"))?;
    if snap == INVALID_HANDLE_VALUE {
        return Err("CreateToolhelp32Snapshot returned INVALID_HANDLE_VALUE".into());
    }

    let mut results = Vec::new();
    let mut te = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut matched = 0u32;
    let mut open_fail = 0u32;

    if unsafe { Thread32First(snap, &mut te) }.is_err() {
        let _ = unsafe { CloseHandle(snap) };
        return Err("Thread32First failed".into());
    }

    loop {
        if te.th32OwnerProcessID == pid {
            matched += 1;
            let tid = te.th32ThreadID;

            let Some((th, can_ctx)) = open_thread_best_effort(tid) else {
                open_fail += 1;
                eprintln!("[ThreadScan] OpenThread failed for TID {tid}");
                // Still report the TID so the scan is not empty; mark suspicious if we
                // cannot inspect (better than silent zero).
                results.push(ThreadInfo {
                    tid,
                    rip: 0,
                    start_address: 0,
                    rip_module: None,
                    start_module: None,
                    suspicious: false,
                    dr0: 0,
                    dr1: 0,
                    dr2: 0,
                    dr3: 0,
                    dr6: 0,
                    dr7: 0,
                });
                if unsafe { Thread32Next(snap, &mut te) }.is_err() {
                    break;
                }
                continue;
            };

            let start_addr = query_start_address(th);

            let mut rip: u64 = 0;
            let mut dr0 = 0u64;
            let mut dr1 = 0u64;
            let mut dr2 = 0u64;
            let mut dr3 = 0u64;
            let mut dr6 = 0u64;
            let mut dr7 = 0u64;
            let mut have_ctx = false;

            if can_ctx && tid != self_tid {
                let guard = SuspendGuard::suspend(th);
                if guard.suspended {
                    let mut ctx: CONTEXT64 = unsafe { std::mem::zeroed() };
                    ctx.ContextFlags = CONTEXT_FULL;
                    let ok = unsafe { GetThreadContext(th, &mut ctx) };
                    if ok != 0 {
                        rip = ctx.Rip;
                        dr0 = ctx.Dr0;
                        dr1 = ctx.Dr1;
                        dr2 = ctx.Dr2;
                        dr3 = ctx.Dr3;
                        dr6 = ctx.Dr6;
                        dr7 = ctx.Dr7;
                        have_ctx = true;
                    } else {
                        eprintln!("[ThreadScan] GetThreadContext failed TID {tid}");
                    }
                } else {
                    eprintln!("[ThreadScan] SuspendThread failed TID {tid}");
                }
            }

            let start_mod = module_for(&modules, start_addr);
            let rip_mod = if have_ctx {
                module_for(&modules, rip)
            } else {
                None
            };

            // Start address outside known modules = classic remote shellcode thread.
            // RIP outside modules (when we have context) = same class of finding.
            let suspicious = (start_addr != 0 && start_mod.is_none())
                || (have_ctx && rip != 0 && rip_mod.is_none());

            results.push(ThreadInfo {
                tid,
                rip,
                start_address: start_addr,
                rip_module: rip_mod,
                start_module: start_mod,
                suspicious,
                dr0,
                dr1,
                dr2,
                dr3,
                dr6,
                dr7,
            });

            let _ = unsafe { CloseHandle(th) };
        }

        if unsafe { Thread32Next(snap, &mut te) }.is_err() {
            break;
        }
    }

    let _ = unsafe { CloseHandle(snap) };
    eprintln!(
        "[ThreadScan] PID {pid}: matched={matched} open_fail={open_fail} results={}",
        results.len()
    );
    Ok(results)
}
