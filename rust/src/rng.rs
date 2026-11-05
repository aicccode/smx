//! The operating system's CSPRNG, and nothing else. There is no fallback generator: when the OS
//! source is unavailable every caller gets an error.
//!
//! Each call goes straight to the kernel (or its documented user-space interface) without keeping
//! state in the process, which keeps this correct across `fork` and thread use. No file descriptor
//! is kept open either, since a daemon closing all its descriptors could otherwise redirect reads
//! to an unrelated file.

/// The OS random source failed or does not exist on this target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RngError;

/// Fills `dest` with random bytes, or fails. `dest` is unspecified on failure.
pub(crate) fn fill(dest: &mut [u8]) -> Result<(), RngError> {
    imp::fill(dest)
}

/// Linux and Android: the `getrandom` system call, which blocks until the kernel pool is ready
/// (reading /dev/urandom would not). It is called through `syscall` because the libc wrapper does
/// not exist on every C library version Rust supports.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        all(target_arch = "x86_64", target_pointer_width = "64"),
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "powerpc64",
        target_arch = "loongarch64",
    )
))]
mod imp {
    use super::RngError;
    use core::ffi::{c_long, c_uint};

    #[cfg(target_arch = "x86_64")]
    const SYS_GETRANDOM: c_long = 318;
    #[cfg(target_arch = "x86")]
    const SYS_GETRANDOM: c_long = 355;
    #[cfg(any(
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    ))]
    const SYS_GETRANDOM: c_long = 278;
    #[cfg(target_arch = "arm")]
    const SYS_GETRANDOM: c_long = 384;
    #[cfg(target_arch = "s390x")]
    const SYS_GETRANDOM: c_long = 349;
    #[cfg(target_arch = "powerpc64")]
    const SYS_GETRANDOM: c_long = 359;

    const EPERM: i32 = 1;
    const EINTR: i32 = 4;
    const ENOSYS: i32 = 38;
    /// A signal storm must not spin here forever.
    const MAX_INTERRUPTS: u32 = 1024;

    unsafe extern "C" {
        fn syscall(number: c_long, ...) -> c_long;
    }

    pub(super) fn fill(dest: &mut [u8]) -> Result<(), RngError> {
        let mut interrupts = 0;
        let mut rest = &mut *dest;
        while !rest.is_empty() {
            let flags: c_uint = 0;
            // SAFETY: the buffer is valid for `rest.len()` bytes; the kernel writes at most that.
            let got = unsafe { syscall(SYS_GETRANDOM, rest.as_mut_ptr(), rest.len(), flags) };
            if got > 0 && got as usize <= rest.len() {
                rest = &mut rest[got as usize..];
                continue;
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(EINTR) if got < 0 && interrupts < MAX_INTERRUPTS => interrupts += 1,
                // Kernels before 3.17, or a sandbox filtering the call.
                Some(ENOSYS | EPERM) if got < 0 => return super::read_device(dest),
                _ => return Err(RngError),
            }
        }
        Ok(())
    }
}

/// Other Linux architectures and the remaining Unix systems: the random device, opened per call.
#[cfg(all(
    unix,
    not(target_vendor = "apple"),
    not(all(
        any(target_os = "linux", target_os = "android"),
        any(
            all(target_arch = "x86_64", target_pointer_width = "64"),
            target_arch = "x86",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "riscv64",
            target_arch = "s390x",
            target_arch = "powerpc64",
            target_arch = "loongarch64",
        )
    ))
))]
mod imp {
    use super::RngError;

    pub(super) fn fill(dest: &mut [u8]) -> Result<(), RngError> {
        super::read_device(dest)
    }
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn read_device(dest: &mut [u8]) -> Result<(), RngError> {
    use std::io::Read;
    use std::os::unix::fs::FileTypeExt;
    let mut device = std::fs::File::open("/dev/urandom").map_err(|_| RngError)?;
    // A regular file planted in a chroot or container must not become the key source.
    let metadata = device.metadata().map_err(|_| RngError)?;
    if !metadata.file_type().is_char_device() {
        return Err(RngError);
    }
    device.read_exact(dest).map_err(|_| RngError)
}

/// macOS and iOS: CommonCrypto's generator, part of libSystem.
#[cfg(target_vendor = "apple")]
mod imp {
    use super::RngError;
    use core::ffi::c_void;

    unsafe extern "C" {
        fn CCRandomGenerateBytes(bytes: *mut c_void, count: usize) -> i32;
    }

    pub(super) fn fill(dest: &mut [u8]) -> Result<(), RngError> {
        // SAFETY: the buffer is valid for `dest.len()` bytes.
        let status = unsafe { CCRandomGenerateBytes(dest.as_mut_ptr().cast(), dest.len()) };
        if status == 0 { Ok(()) } else { Err(RngError) }
    }
}

/// Windows: the system-preferred generator of the CNG API.
#[cfg(windows)]
mod imp {
    use super::RngError;
    use core::ffi::c_void;

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 2;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, count: u32, flags: u32) -> i32;
    }

    pub(super) fn fill(dest: &mut [u8]) -> Result<(), RngError> {
        for chunk in dest.chunks_mut(u32::MAX as usize) {
            // SAFETY: the buffer is valid for `chunk.len()` bytes, which fits in a u32.
            let status = unsafe {
                BCryptGenRandom(
                    core::ptr::null_mut(),
                    chunk.as_mut_ptr(),
                    chunk.len() as u32,
                    BCRYPT_USE_SYSTEM_PREFERRED_RNG,
                )
            };
            // NTSTATUS: negative values are errors.
            if status < 0 {
                return Err(RngError);
            }
        }
        Ok(())
    }
}

/// WASI: `random_get`.
#[cfg(target_os = "wasi")]
mod imp {
    use super::RngError;

    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        fn random_get(buffer: *mut u8, length: usize) -> u16;
    }

    pub(super) fn fill(dest: &mut [u8]) -> Result<(), RngError> {
        // SAFETY: the buffer is valid for `dest.len()` bytes.
        let errno = unsafe { random_get(dest.as_mut_ptr(), dest.len()) };
        if errno == 0 { Ok(()) } else { Err(RngError) }
    }
}

/// Everything else, notably wasm32-unknown-unknown: no secure source is reachable without a new
/// dependency, so operations that need randomness fail.
#[cfg(not(any(unix, windows, target_os = "wasi")))]
mod imp {
    use super::RngError;

    pub(super) fn fill(_dest: &mut [u8]) -> Result<(), RngError> {
        Err(RngError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_looks_random() {
        let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
        fill(&mut a).unwrap();
        fill(&mut b).unwrap();
        assert_ne!(a, [0u8; 64]);
        assert_ne!(a, b);
        fill(&mut []).unwrap();
        // More than one call's worth on any system.
        let mut big = vec![0u8; 1 << 20];
        fill(&mut big).unwrap();
        assert!(big.iter().filter(|&&x| x == 0).count() < 1 << 13);
    }

    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn device_fallback_works() {
        let mut a = [0u8; 64];
        read_device(&mut a).unwrap();
        assert_ne!(a, [0u8; 64]);
    }
}
