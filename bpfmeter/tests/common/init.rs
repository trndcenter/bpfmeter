use std::{
    io::{BufRead, BufReader},
    process::{Child, Command, Stdio},
    sync::{Mutex, atomic::AtomicBool, atomic::Ordering::Relaxed},
};

struct BpfTrace(Child);

static BPF_TRACE: Mutex<Option<BpfTrace>> = Mutex::new(None);

const BPF_PROG_SYSCALL_TRACEPOINT: &str = "sys_enter_openat";

//#[ctor::ctor]
#[allow(dead_code)] // fix linter for now
fn wait_bpftrace_start() {
    let Ok(bpftrace) = which::which("bpftrace") else {
        panic!("bpftrace is not installed");
    };
    let mut bpftrace = Command::new(bpftrace)
        .args(["-v", "-e", &format!("tracepoint:syscalls:{BPF_PROG_SYSCALL_TRACEPOINT} {{ @bpfmeter_map[comm] = count(); }}")])
        .stderr(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Cannot start bpftrace");

    let stdout = BufReader::new(bpftrace.stdout.take().unwrap());

    BPF_TRACE.lock().unwrap().replace(BpfTrace(bpftrace));

    static STARTED: AtomicBool = AtomicBool::new(false);

    let h = std::thread::spawn(move || {
        for line in stdout.lines().map_while(Result::ok) {
            if line.contains("Program ID:") {
                STARTED.store(true, Relaxed);
                break;
            }
        }
    });

    for _ in 0..10 {
        if STARTED.load(Relaxed) || h.is_finished() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }

    assert!(STARTED.load(Relaxed), "bpftrace is not started properly");
}

#[ctor::dtor]
fn shutdown_bpftrace() {
    if let Some(BpfTrace(mut bpftrace)) = BPF_TRACE.lock().unwrap().take() {
        bpftrace.kill().expect("Cannot kill bpftrace");
    }
}
