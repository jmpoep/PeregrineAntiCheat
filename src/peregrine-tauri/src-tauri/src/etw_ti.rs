use std::mem::size_of;
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Diagnostics::Etw::*;

const ETW_TI_GUID: GUID = GUID::from_u128(0xf4e1897c_bb5d_5668_f1d8_040f4d8dd344);
const SESSION_NAME: &str = "PeregrineETWThreatIntel";

const KW_ALLOCVM_REMOTE: u64 = 0x4;
const KW_PROTECTVM_REMOTE: u64 = 0x40;
const KW_MAPVIEW_REMOTE: u64 = 0x400;
const KW_QUEUEAPC_REMOTE: u64 = 0x1000;
const KW_SETCTX_REMOTE: u64 = 0x4000;
const KW_READVM_REMOTE: u64 = 0x20000;
const KW_WRITEVM_REMOTE: u64 = 0x80000;
// Suspend/resume have different field layouts, skip for now
// const KW_SUSPEND_THREAD: u64 = 0x100000;
// const KW_RESUME_THREAD: u64 = 0x200000;

#[derive(Debug, Clone, serde::Serialize)]
pub struct TiEvent {
    pub event_type: String,
    pub caller_pid: u32,
    pub target_pid: u32,
    pub base_address: u64,
    pub region_size: u64,
    pub protection: u32,
}

pub type TiReceiver = mpsc::Receiver<TiEvent>;

static mut TX: Option<mpsc::Sender<TiEvent>> = None;

unsafe extern "system" fn trace_callback(record: *mut EVENT_RECORD) {
    if record.is_null() {
        return;
    }
    let ev = unsafe { &*record };
    let kw = ev.EventHeader.EventDescriptor.Keyword;
    let data = ev.UserData as *const u8;
    let data_len = ev.UserDataLength as usize;

    if data.is_null() || data_len < 40 {
        return;
    }

    let event_type = if kw & KW_ALLOCVM_REMOTE != 0 {
        "ALLOCVM_REMOTE"
    } else if kw & KW_PROTECTVM_REMOTE != 0 {
        "PROTECTVM_REMOTE"
    } else if kw & KW_MAPVIEW_REMOTE != 0 {
        "MAPVIEW_REMOTE"
    } else if kw & KW_QUEUEAPC_REMOTE != 0 {
        "QUEUEAPC_REMOTE"
    } else if kw & KW_SETCTX_REMOTE != 0 {
        "SETTHREADCONTEXT_REMOTE"
    } else if kw & KW_READVM_REMOTE != 0 {
        "READVM_REMOTE"
    } else if kw & KW_WRITEVM_REMOTE != 0 {
        "WRITEVM_REMOTE"
    } else {
        return;
    };

    // ALLOCVM/PROTECTVM/MAPVIEW: fields start at offset 0
    // READVM/WRITEVM/QUEUEAPC/SETTHREADCONTEXT: OperationStatus (u32) prepended, +4
    let base_off: usize = match kw {
        k if k & (KW_READVM_REMOTE | KW_WRITEVM_REMOTE | KW_QUEUEAPC_REMOTE | KW_SETCTX_REMOTE) != 0 => 4,
        _ => 0,
    };

    // Common layout after base_off:
    //   +0:  CallingProcessId (u32)
    //   +4:  CallingProcessCreateTime (i64=8)
    //   +12: CallingProcessStartKey (u64=8)
    //   +20: CallingProcessSignatureLevel (u8)
    //   +21: CallingProcessSectionSignatureLevel (u8)
    //   +22: CallingProcessProtection (u8)
    //   +23: CallingThreadId (u32)
    //   +27: CallingThreadCreateTime (i64=8)
    //   +35: TargetProcessId (u32)
    //   +39: TargetProcessCreateTime (i64=8)
    //   +47: TargetProcessStartKey (u64=8)
    //   +55: TargetProcessSignatureLevel (u8)
    //   +56: TargetProcessSectionSignatureLevel (u8)
    //   +57: TargetProcessProtection (u8)
    //   +58: BaseAddress (u64)
    //   +66: RegionSize/BytesCopied (u64)
    //   +74: AllocationType (u32) [ALLOCVM/MAPVIEW only]
    //   +78: ProtectionMask (u32) [ALLOCVM/PROTECTVM/MAPVIEW only]

    let r32 = |off: usize| -> u32 {
        let o = base_off + off;
        if o + 4 > data_len { 0 } else { unsafe { std::ptr::read_unaligned(data.add(o) as *const u32) } }
    };
    let r64 = |off: usize| -> u64 {
        let o = base_off + off;
        if o + 8 > data_len { 0 } else { unsafe { std::ptr::read_unaligned(data.add(o) as *const u64) } }
    };

    let ti = TiEvent {
        event_type: event_type.to_string(),
        caller_pid: r32(0),
        target_pid: r32(35),
        base_address: r64(58),
        region_size: r64(66),
        protection: if base_off + 82 <= data_len { r32(78) } else { 0 },
    };

    unsafe {
        if let Some(ref tx) = TX {
            let _ = tx.send(ti);
        }
    }
}

pub fn start_etw_session(stop: Arc<AtomicBool>) -> Result<TiReceiver, String> {
    let (tx, rx) = mpsc::channel();
    unsafe { TX = Some(tx); }

    let wide: Vec<u16> = SESSION_NAME.encode_utf16().chain(std::iter::once(0)).collect();

    let props_size = size_of::<EVENT_TRACE_PROPERTIES>();
    let total = props_size + wide.len() * 2;
    let mut buf = vec![0u8; total];
    let props = buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

    unsafe {
        (*props).Wnode.BufferSize = total as u32;
        (*props).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*props).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*props).LoggerNameOffset = props_size as u32;
        copy_nonoverlapping(wide.as_ptr(), buf.as_mut_ptr().add(props_size) as *mut u16, wide.len());
    }

    // Stop leftover session
    let mut stop_buf = buf.clone();
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(wide.as_ptr()),
            stop_buf.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        );
    }

    // Start trace
    let mut handle = CONTROLTRACE_HANDLE::default();
    let err = unsafe { StartTraceW(&mut handle, PCWSTR(wide.as_ptr()), props) };
    if err != WIN32_ERROR(0) {
        return Err(format!("StartTraceW failed: {:?}", err));
    }

    // Enable TI provider
    let enable_kw = KW_ALLOCVM_REMOTE | KW_PROTECTVM_REMOTE | KW_MAPVIEW_REMOTE
        | KW_QUEUEAPC_REMOTE | KW_SETCTX_REMOTE | KW_READVM_REMOTE
        | KW_WRITEVM_REMOTE;

    let err = unsafe {
        EnableTraceEx2(
            handle, &ETW_TI_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            5, // TRACE_LEVEL_VERBOSE
            enable_kw, 0, 0, None,
        )
    };
    if err != WIN32_ERROR(0) {
        let mut sb = buf.clone();
        unsafe { ControlTraceW(handle, PCWSTR::null(), sb.as_mut_ptr() as *mut _, EVENT_TRACE_CONTROL_STOP); }
        return Err(format!("EnableTraceEx2 failed (need PPL?): {:?}", err));
    }

    // Open trace
    let mut wide_mut = wide.clone();
    let mut logfile: EVENT_TRACE_LOGFILEW = unsafe { std::mem::zeroed() };
    logfile.LoggerName = PWSTR(wide_mut.as_mut_ptr());
    logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    logfile.Anonymous2.EventRecordCallback = Some(trace_callback);

    let trace_handle = unsafe { OpenTraceW(&mut logfile) };
    if trace_handle.Value == u64::MAX {
        let mut sb = buf.clone();
        unsafe { ControlTraceW(handle, PCWSTR::null(), sb.as_mut_ptr() as *mut _, EVENT_TRACE_CONTROL_STOP); }
        return Err("OpenTraceW failed".into());
    }

    // ProcessTrace blocks — dedicated thread
    std::thread::spawn(move || {
        unsafe { ProcessTrace(&[trace_handle], None, None); }
    });

    // Cleanup on stop
    let buf2 = buf;
    let wide2 = wide;
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        unsafe {
            CloseTrace(trace_handle);
            ControlTraceW(handle, PCWSTR(wide2.as_ptr()), buf2.as_ptr() as *mut _, EVENT_TRACE_CONTROL_STOP);
        }
    });

    Ok(rx)
}
