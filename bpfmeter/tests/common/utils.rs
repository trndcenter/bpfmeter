use std::process::Child;

pub struct ChildGuard(pub Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Err(e) = self.0.kill() {
            eprintln!("Failed to kill child process: {}", e);
        }
    }
}

pub fn get_next_port() -> u16 {
    static PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(9100);
    PORT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}
