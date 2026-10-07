//! The images a Mach-O executable loads from outside the shared cache.

use std::path::{Path, PathBuf};

use crate::error::ContainmentError;

const MH_MAGIC_64: u32 = 0xfeed_facf;
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_RPATH: u32 = 0x8000_001c;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
const HEADER_BYTES: usize = 32;
const MAXIMUM_COMMAND_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_IMAGES: usize = 512;

/// The system image prefixes, which the closure leaves to the shared cache and the runtime minimum.
const SYSTEM_IMAGE_PREFIXES: &[&str] = &["/usr/lib/", "/System/", "/Library/Apple/"];

/// What one image asks dyld for.
#[derive(Default)]
struct ImageLoads {
    /// Each install name the image loads, and whether the load is weak.
    dylibs: Vec<(String, bool)>,
    rpaths: Vec<String>,
}

fn refusal(reason: String) -> ContainmentError {
    ContainmentError::ApplyFailed {
        backend: super::seatbelt::MECHANISM.to_string(),
        reason,
    }
}

/// Every image `executable` loads from outside the shared cache, through each image's own loads,
/// each as the spelling the load requests. Empty for a static binary or a script.
pub(crate) fn dylib_closure(executable: &Path) -> Result<Vec<PathBuf>, ContainmentError> {
    let executable_directory = executable
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .to_path_buf();
    let executable_loads = image_loads(executable)?;
    let executable_rpaths = executable_loads.rpaths.clone();
    let mut requested: Vec<PathBuf> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    let mut pending: Vec<(PathBuf, ImageLoads)> =
        vec![(executable.to_path_buf(), executable_loads)];
    while let Some((image, loads)) = pending.pop() {
        if requested.len() > MAXIMUM_IMAGES {
            return Err(refusal(format!(
                "'{}' loads more than {MAXIMUM_IMAGES} images; refusing rather than walking on",
                executable.display()
            )));
        }
        let image_directory = image
            .parent()
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf();
        let outer_rpaths: &[String] = if image == executable {
            &[]
        } else {
            &executable_rpaths
        };
        for (name, weak) in &loads.dylibs {
            if is_system_image(name) {
                continue;
            }
            let found = resolve_install_name(
                name,
                &image_directory,
                &executable_directory,
                &loads.rpaths,
                outer_rpaths,
            );
            let Some(found) = found else {
                if *weak {
                    continue;
                }
                return Err(refusal(format!(
                    "'{}' loads '{}', which resolves to no file through @rpath {:?}; the profile \
                     would deny the load",
                    image.display(),
                    name,
                    loads.rpaths
                )));
            };
            if is_system_image(&found.to_string_lossy()) {
                continue;
            }
            let identity = found.canonicalize().unwrap_or_else(|_| found.clone());
            if seen.contains(&identity) {
                continue;
            }
            seen.push(identity);
            let inner = image_loads(&found)?;
            requested.push(found.clone());
            pending.push((found, inner));
        }
    }
    Ok(requested)
}

fn is_system_image(name: &str) -> bool {
    SYSTEM_IMAGE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// The file an install name denotes: `@executable_path` and `@loader_path` expand to their
/// directories, `@rpath` tries each run-path search entry in order, and an absolute name is itself.
fn resolve_install_name(
    name: &str,
    loader_directory: &Path,
    executable_directory: &Path,
    image_rpaths: &[String],
    executable_rpaths: &[String],
) -> Option<PathBuf> {
    // `@loader_path` in a run-path entry names the directory of the image that carries the entry,
    // so each entry expands against its own owner rather than against the image being resolved.
    let expand = |spelling: &str, owner: &Path| -> Option<PathBuf> {
        if let Some(rest) = spelling.strip_prefix("@executable_path/") {
            return Some(normalized(&executable_directory.join(rest)));
        }
        if let Some(rest) = spelling.strip_prefix("@loader_path/") {
            return Some(normalized(&owner.join(rest)));
        }
        if spelling == "@executable_path" {
            return Some(normalized(executable_directory));
        }
        if spelling == "@loader_path" {
            return Some(normalized(owner));
        }
        if spelling.starts_with('@') {
            return None;
        }
        Path::new(spelling)
            .is_absolute()
            .then(|| normalized(Path::new(spelling)))
    };
    if let Some(rest) = name.strip_prefix("@rpath/") {
        return image_rpaths
            .iter()
            .map(|entry| (entry, loader_directory))
            .chain(
                executable_rpaths
                    .iter()
                    .map(|entry| (entry, executable_directory)),
            )
            .filter_map(|(entry, owner)| expand(entry, owner))
            .map(|directory| directory.join(rest))
            .find(|candidate| candidate.is_file());
    }
    expand(name, loader_directory).filter(|candidate| candidate.is_file())
}

/// The path with `.` and `..` folded lexically, and every symbolic link left in place.
fn normalized(path: &Path) -> PathBuf {
    let mut folded = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                folded.pop();
            }
            other => folded.push(other.as_os_str()),
        }
    }
    folded
}

/// Read what one image asks dyld for. A file that is not a 64-bit Mach-O asks for nothing.
fn image_loads(path: &Path) -> Result<ImageLoads, ContainmentError> {
    use std::io::{Read as _, Seek as _};

    let mut file = std::fs::File::open(path).map_err(|source| {
        refusal(format!(
            "opening '{}' to resolve the images it loads: {source}",
            path.display()
        ))
    })?;
    let mut magic = [0u8; 8];
    if file.read_exact(&mut magic).is_err() {
        return Ok(ImageLoads::default());
    }
    let mut slice_offset: u64 = 0;
    let fat_magic = u32::from_be_bytes(magic[..4].try_into().unwrap_or_default());
    if fat_magic == FAT_MAGIC || fat_magic == FAT_MAGIC_64 {
        let count = usize::try_from(u32::from_be_bytes(
            magic[4..8].try_into().unwrap_or_default(),
        ))
        .unwrap_or(0)
        .min(64);
        let (entry_bytes, wide) = if fat_magic == FAT_MAGIC {
            (20, false)
        } else {
            (32, true)
        };
        let mut table = vec![0u8; count * entry_bytes];
        if file.read_exact(&mut table).is_err() {
            return Ok(ImageLoads::default());
        }
        let mut chosen = None;
        for entry in table.chunks_exact(entry_bytes) {
            let cputype = u32::from_be_bytes(entry[0..4].try_into().unwrap_or_default());
            let offset = if wide {
                u64::from_be_bytes(entry[8..16].try_into().unwrap_or_default())
            } else {
                u64::from(u32::from_be_bytes(
                    entry[8..12].try_into().unwrap_or_default(),
                ))
            };
            if cputype == CPU_TYPE_ARM64 {
                chosen = Some(offset);
                break;
            }
            chosen.get_or_insert(offset);
        }
        let Some(offset) = chosen else {
            return Ok(ImageLoads::default());
        };
        slice_offset = offset;
        if file.seek(std::io::SeekFrom::Start(offset)).is_err()
            || file.read_exact(&mut magic).is_err()
        {
            return Ok(ImageLoads::default());
        }
    }
    if u32::from_le_bytes(magic[..4].try_into().unwrap_or_default()) != MH_MAGIC_64 {
        return Ok(ImageLoads::default());
    }
    let mut header = [0u8; HEADER_BYTES];
    if file.seek(std::io::SeekFrom::Start(slice_offset)).is_err()
        || file.read_exact(&mut header).is_err()
    {
        return Ok(ImageLoads::default());
    }
    let command_count = u32::from_le_bytes(header[16..20].try_into().unwrap_or_default());
    let command_bytes = usize::try_from(u32::from_le_bytes(
        header[20..24].try_into().unwrap_or_default(),
    ))
    .unwrap_or(0);
    if command_bytes > MAXIMUM_COMMAND_BYTES {
        return Err(refusal(format!(
            "'{}' claims {command_bytes} bytes of load commands, above the \
             {MAXIMUM_COMMAND_BYTES}-byte ceiling; refusing rather than allocating it",
            path.display()
        )));
    }
    let mut commands = vec![0u8; command_bytes];
    if file.read_exact(&mut commands).is_err() {
        return Ok(ImageLoads::default());
    }

    let mut loads = ImageLoads::default();
    let mut cursor = 0usize;
    for _ in 0..command_count {
        let Some(head) = commands.get(cursor..cursor + 8) else {
            break;
        };
        let command = u32::from_le_bytes(head[0..4].try_into().unwrap_or_default());
        let size = usize::try_from(u32::from_le_bytes(
            head[4..8].try_into().unwrap_or_default(),
        ))
        .unwrap_or(0);
        if size < 8 {
            break;
        }
        let Some(body) = commands.get(cursor..cursor + size) else {
            break;
        };
        let string_at_offset_field = |body: &[u8]| -> Option<String> {
            let offset =
                usize::try_from(u32::from_le_bytes(body.get(8..12)?.try_into().ok()?)).ok()?;
            let text = body.get(offset..)?.split(|byte| *byte == 0).next()?;
            let name = String::from_utf8(text.to_vec()).ok()?;
            (!name.is_empty()).then_some(name)
        };
        match command {
            LC_LOAD_DYLIB | LC_LAZY_LOAD_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB => {
                if let Some(name) = string_at_offset_field(body) {
                    loads.dylibs.push((name, false));
                }
            }
            LC_LOAD_WEAK_DYLIB => {
                if let Some(name) = string_at_offset_field(body) {
                    loads.dylibs.push((name, true));
                }
            }
            LC_RPATH => {
                if let Some(entry) = string_at_offset_field(body) {
                    loads.rpaths.push(entry);
                }
            }
            _ => {}
        }
        cursor += size;
    }
    Ok(loads)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal 64-bit Mach-O carrying the load commands the walk reads. Not runnable.
    pub(crate) fn synthetic_macho(dylibs: &[(&str, bool)], rpaths: &[&str]) -> Vec<u8> {
        let mut commands: Vec<u8> = Vec::new();
        let mut count: u32 = 0;
        let mut push = |kind: u32, text: &str, fixed: usize| {
            let mut body = text.as_bytes().to_vec();
            body.push(0);
            while !(fixed + body.len()).is_multiple_of(8) {
                body.push(0);
            }
            let size = u32::try_from(fixed + body.len()).expect("a small command");
            commands.extend_from_slice(&kind.to_le_bytes());
            commands.extend_from_slice(&size.to_le_bytes());
            commands.extend_from_slice(&u32::try_from(fixed).expect("small").to_le_bytes());
            commands.extend_from_slice(&vec![0u8; fixed - 12]);
            commands.extend_from_slice(&body);
            count += 1;
        };
        for (name, weak) in dylibs {
            let kind = if *weak {
                LC_LOAD_WEAK_DYLIB
            } else {
                LC_LOAD_DYLIB
            };
            push(kind, name, 24);
        }
        for entry in rpaths {
            push(LC_RPATH, entry, 12);
        }
        let mut image = Vec::new();
        image.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        image.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
        image.extend_from_slice(&2u32.to_le_bytes());
        image.extend_from_slice(&count.to_le_bytes());
        image.extend_from_slice(&u32::try_from(commands.len()).expect("small").to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
        image.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(image.len(), HEADER_BYTES);
        image.extend_from_slice(&commands);
        image
    }

    pub(crate) fn planted_image(root: &Path, relative: &str, image: &[u8]) -> PathBuf {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().expect("a parent")).expect("the image directory");
        std::fs::write(&path, image).expect("the image");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("+x");
        }
        path
    }

    /// The walk follows `@rpath` through `@loader_path`, recurses into each image, and names no
    /// system image.
    #[test]
    fn the_closure_follows_rpath_transitively_and_skips_the_shared_cache() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "bin/app",
            &synthetic_macho(
                &[
                    ("/usr/lib/libSystem.B.dylib", false),
                    ("@rpath/libapp.dylib", false),
                ],
                &["@loader_path/../lib"],
            ),
        );
        let libapp = planted_image(
            &root,
            "lib/libapp.dylib",
            &synthetic_macho(
                &[
                    ("@loader_path/libinner.dylib", false),
                    ("@rpath/libabsent.dylib", true),
                ],
                &[],
            ),
        );
        let libinner = planted_image(&root, "lib/libinner.dylib", &synthetic_macho(&[], &[]));

        let closure = dylib_closure(&app).expect("the closure resolves");

        assert_eq!(closure, vec![libapp, libinner], "{closure:?}");
    }

    /// An executable run-path entry expands `@loader_path` against the executable's own directory,
    /// not against the directory of the image whose load is being resolved.
    #[test]
    fn an_executable_run_path_expands_against_the_executable() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "bin/app",
            &synthetic_macho(
                &[("@rpath/nested/libmid.dylib", false)],
                &["@loader_path/../lib"],
            ),
        );
        let libmid = planted_image(
            &root,
            "lib/nested/libmid.dylib",
            &synthetic_macho(&[("@rpath/libleaf.dylib", false)], &[]),
        );
        let libleaf = planted_image(&root, "lib/libleaf.dylib", &synthetic_macho(&[], &[]));

        let closure = dylib_closure(&app).expect("the closure resolves");

        assert_eq!(closure, vec![libmid, libleaf], "{closure:?}");
    }

    /// A run-path entry spelled exactly `@loader_path`, with no trailing slash, names the directory
    /// of the image that carries it.
    #[test]
    fn a_bare_loader_path_run_path_expands_to_the_owner_directory() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "bin/app",
            &synthetic_macho(&[("@executable_path/../lib/libnode.dylib", false)], &[]),
        );
        let libnode = planted_image(
            &root,
            "lib/libnode.dylib",
            &synthetic_macho(&[("@rpath/libabsl.dylib", false)], &["@loader_path"]),
        );
        let libabsl = planted_image(&root, "lib/libabsl.dylib", &synthetic_macho(&[], &[]));

        let closure = dylib_closure(&app).expect("the closure resolves");

        assert_eq!(closure, vec![libnode, libabsl], "{closure:?}");
    }

    /// A run-path entry spelled exactly `@executable_path`, with no trailing slash, names the
    /// directory of the executable rather than the directory of the image that carries the entry.
    #[test]
    fn a_bare_executable_path_run_path_expands_to_the_executable_directory() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "bin/app",
            &synthetic_macho(&[("@executable_path/../lib/libnode.dylib", false)], &[]),
        );
        let libnode = planted_image(
            &root,
            "lib/libnode.dylib",
            &synthetic_macho(&[("@rpath/libplug.dylib", false)], &["@executable_path"]),
        );
        let libplug = planted_image(&root, "bin/libplug.dylib", &synthetic_macho(&[], &[]));

        let closure = dylib_closure(&app).expect("the closure resolves");

        assert_eq!(closure, vec![libnode, libplug], "{closure:?}");
    }

    /// A candidate that names a directory is not a resolution, so the walk takes the next run-path
    /// entry and the directory never enters the closure.
    #[test]
    fn a_bare_run_path_candidate_that_is_a_directory_is_not_a_resolution() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "bin/app",
            &synthetic_macho(&[("@executable_path/../lib/libnode.dylib", false)], &[]),
        );
        let libnode = planted_image(
            &root,
            "lib/libnode.dylib",
            &synthetic_macho(
                &[("@rpath/libplug.dylib", false)],
                &["@loader_path", "@loader_path/../other"],
            ),
        );
        let shadow = root.join("lib/libplug.dylib");
        std::fs::create_dir_all(&shadow).expect("a directory of the library's name");
        let libplug = planted_image(&root, "other/libplug.dylib", &synthetic_macho(&[], &[]));

        let closure = dylib_closure(&app).expect("the closure resolves");

        assert_eq!(closure, vec![libnode, libplug], "{closure:?}");
        assert!(
            !closure.contains(&shadow),
            "a directory never enters the closure: {closure:?}"
        );
    }

    /// A bare run-path entry that holds no candidate refuses the image by name, rather than drop it.
    #[test]
    fn a_bare_run_path_entry_that_resolves_to_nothing_refuses_the_image() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "bin/app",
            &synthetic_macho(&[("@executable_path/../lib/libnode.dylib", false)], &[]),
        );
        planted_image(
            &root,
            "lib/libnode.dylib",
            &synthetic_macho(&[("@rpath/libmissing.dylib", false)], &["@loader_path"]),
        );

        let error = dylib_closure(&app).expect_err("a missing strong load is refused");

        let text = error.to_string();
        assert!(text.contains("libmissing.dylib"), "{text}");
        assert!(text.contains("@loader_path"), "{text}");
    }

    /// A strong load that resolves to nothing is refused by name rather than left for dyld.
    #[test]
    fn an_unresolved_strong_load_is_refused_by_name() {
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().canonicalize().expect("canonical");
        let app = planted_image(
            &root,
            "bin/app",
            &synthetic_macho(
                &[("@rpath/libmissing.dylib", false)],
                &["@loader_path/../lib"],
            ),
        );

        let error = dylib_closure(&app).expect_err("a missing strong load is refused");

        assert!(
            error.to_string().contains("libmissing.dylib"),
            "the refusal names the image: {error}"
        );
    }

    /// A script, a static binary, or a truncated file loads nothing and refuses nothing.
    #[test]
    fn a_non_macho_file_loads_nothing() {
        let directory = tempfile::tempdir().expect("tempdir");
        for (name, bytes) in [
            ("script", b"#!/bin/sh\n".to_vec()),
            ("truncated", MH_MAGIC_64.to_le_bytes().to_vec()),
            ("elf", b"\x7fELF\x02\x01\x01\x00".to_vec()),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, &bytes).expect("fixture");
            let closure = dylib_closure(&path).unwrap_or_else(|error| panic!("{name}: {error}"));
            assert!(closure.is_empty(), "{name} must load nothing");
        }
    }
}
