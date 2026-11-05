//! Crate-internal constant-time and memory-wiping helpers.

use core::sync::atomic::{Ordering, compiler_fence};

/// Hides a mask from the optimizer. Without this LLVM can and does turn mask arithmetic on secret
/// values back into conditional branches (seen on table lookups with rustc 1.99). On targets
/// without inline assembly `black_box` is best effort only.
#[inline(always)]
pub(crate) fn ct_barrier(mut value: u64) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        // SAFETY: an empty template that only claims to transform the register.
        unsafe {
            core::arch::asm!(
                "/* {0} */",
                inout(reg) value,
                options(pure, nomem, nostack, preserves_flags)
            );
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        value = core::hint::black_box(value);
    }
    value
}

/// Equality of byte strings that does not stop at the first difference. Only the lengths, which
/// are public here, decide early.
#[inline(never)]
pub(crate) fn eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    ct_barrier(u64::from(diff)) == 0
}

/// Overwrites a value in a way the optimizer must keep. Best effort: copies the compiler made
/// earlier (spills, moves, registers) are out of reach.
#[inline]
pub(crate) fn wipe<T: Copy>(value: &mut T, zero: T) {
    // SAFETY: the reference is valid for writes and `T` is `Copy`, so nothing needs dropping.
    unsafe { core::ptr::write_volatile(value, zero) };
    compiler_fence(Ordering::SeqCst);
}

/// `wipe` for a run-time sized buffer.
pub(crate) fn wipe_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: the reference is valid for writes.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_bytes_compares_everything() {
        assert!(eq_bytes(&[], &[]));
        assert!(eq_bytes(&[1, 2, 3], &[1, 2, 3]));
        assert!(!eq_bytes(&[1, 2, 3], &[1, 2]));
        assert!(!eq_bytes(&[], &[0]));
        for i in 0..3 {
            let mut other = [1, 2, 3];
            other[i] ^= 0x80;
            assert!(!eq_bytes(&[1, 2, 3], &other));
        }
    }

    #[test]
    fn wiping_clears() {
        let mut value = [7u64; 4];
        wipe(&mut value, [0; 4]);
        assert_eq!(value, [0; 4]);
        let mut bytes = vec![9u8; 40];
        wipe_bytes(&mut bytes);
        assert!(bytes.iter().all(|&b| b == 0));
    }
}
