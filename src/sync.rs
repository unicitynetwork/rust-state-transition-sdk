//! Synchronization primitives for no_std environments
//!
//! This module provides critical section implementation for zkvm targets.
//! RISC Zero zkvm is single-threaded, so we use a no-op critical section.

#[cfg(all(not(feature = "std"), feature = "zkvm"))]
mod zkvm_critical_section {
    use critical_section::RawRestoreState;

    struct SingleThreadedCriticalSection;
    critical_section::set_impl!(SingleThreadedCriticalSection);

    unsafe impl critical_section::Impl for SingleThreadedCriticalSection {
        unsafe fn acquire() -> RawRestoreState {
            // No-op for single-threaded zkvm environment
            ()
        }

        unsafe fn release(_token: RawRestoreState) {
            // No-op for single-threaded zkvm environment
        }
    }
}
