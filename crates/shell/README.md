# Box Shell kernel

This crate supplies the filesystem, effect checks, and host adapters used by the hosted Shell. `ShellKernel` executes a call against a `Filesystem`; the embedder supplies decisions and any host processes or network operations.

## Protected storage paths on Linux

A file descriptor is an open operating-system handle. The Linux-only `StorageView` and `StoragePath` types let an embedder supply an already protected workload filesystem view. `StorageView::new` reserves logical file or directory destinations. `StorageView::install` accepts a retained file descriptor for the sealed filesystem root from a trusted launcher, and `Filesystem::with_storage` attaches the shared view before constructing a call kernel.

Reserved paths remain unavailable before root installation and after closure. Operations resolve through the retained protected root and continue through the existing effect checks. Without a storage view, filesystem requests use the ordinary host and memory routing.

This crate does not mount external storage, compile Box configuration, or grant access when a destination is listed. The embedder must prepare the filesystem restrictions and manage the view lifetime. Core configuration and asynchronous mount integration are separate consumers of this surface.
