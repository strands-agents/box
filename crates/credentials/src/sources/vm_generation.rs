//! The host's virtual machine generation counter, which changes when the machine is restored from a
//! snapshot or cloned.

/// The current generation, or `None` when the host exposes no counter.
#[cfg(target_os = "linux")]
pub(in crate::sources) fn current() -> Option<u32> {
    use std::sync::OnceLock;

    static COUNTER: OnceLock<Option<linux::Counter>> = OnceLock::new();
    COUNTER
        .get_or_init(|| linux::Counter::map(std::path::Path::new(linux::DEVICE)))
        .as_ref()
        .map(linux::Counter::read)
}

/// The current generation, or `None` when the host exposes no counter.
#[cfg(not(target_os = "linux"))]
pub(in crate::sources) fn current() -> Option<u32> {
    None
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileTypeExt;
    use std::path::Path;
    use std::ptr::NonNull;

    /// The character device that holds the generation counter.
    pub(super) const DEVICE: &str = "/dev/sysgenid";

    const LENGTH: usize = std::mem::size_of::<u32>();

    /// A read-only shared mapping of the counter, held for the life of the process.
    pub(super) struct Counter(NonNull<u32>);

    // SAFETY: the mapping is read-only and never unmapped, so any thread may read it.
    unsafe impl Send for Counter {}
    // SAFETY: as above; a read is one volatile load of a value the kernel updates.
    unsafe impl Sync for Counter {}

    impl Counter {
        /// Map the first four bytes of `path`, or `None` when it is absent, shorter than four bytes,
        /// or cannot be mapped.
        pub(super) fn map(path: &Path) -> Option<Self> {
            let file = std::fs::File::open(path).ok()?;
            let metadata = file.metadata().ok()?;
            if !metadata.file_type().is_char_device() && metadata.len() < LENGTH as u64 {
                return None;
            }
            // SAFETY: a fresh read-only shared mapping of an open descriptor; the result is checked
            // against `MAP_FAILED` before use, and the mapping outlives the descriptor.
            let address = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    LENGTH,
                    libc::PROT_READ,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            if address == libc::MAP_FAILED {
                return None;
            }
            NonNull::new(address.cast::<u32>()).map(Self)
        }

        /// The counter as a little-endian `u32`.
        pub(super) fn read(&self) -> u32 {
            // SAFETY: the mapping is page-aligned, at least four bytes long, and never unmapped.
            u32::from_le(unsafe { std::ptr::read_volatile(self.0.as_ptr()) })
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Seek, SeekFrom, Write};

        #[test]
        fn a_mapped_counter_reads_the_current_value_after_a_change() {
            let path = std::env::temp_dir().join(format!("box-generation-{}", std::process::id()));
            let mut file = std::fs::File::create(&path).expect("create the counter file");
            file.write_all(&1u32.to_le_bytes())
                .expect("write generation 1");
            file.flush().expect("flush");

            let counter = Counter::map(&path).expect("a regular file maps");
            assert_eq!(counter.read(), 1);

            file.seek(SeekFrom::Start(0)).expect("seek");
            file.write_all(&2u32.to_le_bytes())
                .expect("write generation 2");
            file.flush().expect("flush");
            assert_eq!(counter.read(), 2, "the mapping shows the new generation");

            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn a_short_counter_file_maps_to_none() {
            let path =
                std::env::temp_dir().join(format!("box-generation-short-{}", std::process::id()));
            std::fs::write(&path, [1u8, 0]).expect("write a short counter file");
            assert!(Counter::map(&path).is_none());
            let _ = std::fs::remove_file(&path);
        }

        #[test]
        fn an_absent_counter_maps_to_none() {
            let path = std::env::temp_dir().join("box-generation-does-not-exist");
            assert!(Counter::map(&path).is_none());
        }
    }
}
