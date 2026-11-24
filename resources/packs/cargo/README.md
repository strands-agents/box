# cargo in a box (`@box/cargo`)

The `@box/cargo` pack lets the agent run the `cargo` that your `PATH` finds: a rustup proxy, or a
toolchain's own `cargo`.

## Where cargo keeps its files

cargo keeps the packages it downloads in its own folder in the profile's storage (its `CARGO_HOME`),
`~/.strands/box/storage/<profile>/default/tool/cargo/cargo`, which the agent cannot write, and its
build output in the project's `target` (`CARGO_TARGET_DIR`). Add `/target` to the project's
`.gitignore`.

To find your toolchains, `box` reads `RUSTUP_HOME` and `CARGO_HOME` from the shell where you run
`box`, and uses `~/.rustup` and `~/.cargo` when they aren't set. They set the pack's `rust.home`
and `rust.cargo_home` options, which `box profile show` lists. In the box, rustup keeps its home in
the pack's own storage, which links to your toolchains and `settings.toml`
([Limitations](#limitations) says what that means).

## Linking on Linux

cargo links with `cc`, which runs `ld` and `as`. Build scripts that compile C also run `ar`. The pack
names all four as helpers, so the box shows each one by the name `PATH` finds, read-only. It also
reads `/usr/libexec/gcc`, where Fedora, RHEL, Amazon Linux and current Ubuntu keep GCC's own
programs (older Debian keeps them in `/usr/lib/gcc`), and `/usr/include`, the C headers that build
scripts compile against. The start files, C libraries and `/usr/lib/gcc` need no grant:
Box Core reads `/lib`, `/lib64`, `/usr/lib` and `/usr/lib64` for every tool.

| Host | What it needs |
| --- | --- |
| GCC in `/usr` (Amazon Linux, Fedora, RHEL, Debian, Ubuntu) | nothing |
| clang as `cc` | nothing |
| GCC outside `/usr`, such as RHEL's `gcc-toolset` | its two folders in the profile, below |
| No `cc` | install `gcc`, or `build-essential` on Debian and Ubuntu |

For a GCC outside `/usr`, add its folders to the cargo tool in your profile:

```toml
[tool.cargo.filesystem]
read = [
    "/opt/rh/gcc-toolset-13/root/usr/libexec/gcc",
    "/opt/rh/gcc-toolset-13/root/usr/lib/gcc",
]
```

## Compiling on macOS

On macOS, the pack points cargo at the compiler in the developer folder that `xcode-select -p`
reports. It sets `SDKROOT`, and the linker, `CC_`, `CXX_`, and `AR_` variables of the
`aarch64_apple_darwin` and `x86_64_apple_darwin` targets. These win over a plain `CC`, so to use
another compiler on macOS, set those names in `[tool.cargo.env]` in your profile.

## Limitations

The agent can write `.cargo/config.toml` in your project, and `cargo` on your machine runs what it
says. Check that file before you run `cargo` outside the box.

A `build.rs` or a proc macro can change cargo's `CARGO_HOME` in storage, and every project of the
profile then builds with what it changed. The agent cannot run a program that `cargo install` puts
there.

In the box, rustup's home is cargo's own folder in the profile's storage,
`~/.strands/box/storage/<profile>/default/tool/cargo/rustup`. It links to your own toolchains and
`settings.toml`, read-only, and holds each toolchain that a project pins and you lack. A `build.rs`
can change what is there, and every project of the profile then runs it in the box. Your own
rustup home stays read-only, so `rustup update`, `rustup default`, and `rustup component add` on
your toolchains stop in the box, and `cargo` outside the box never runs what the box installed. To
start over, delete `~/.strands/box/storage/<profile>/default/tool/cargo`.

Every project of the profile shares that folder, and rustup takes no lock on it. Two boxes of one
profile that install the same toolchain at the same time can break it, and then every project of
the profile stops on it. Delete the folder above, and the next run installs the toolchain again.

On macOS, rustup cannot trust the box's certificate. So there rustup downloads from
`http://static.rust-lang.org`, and the box's gateway makes the `https://` call and checks the
server's certificate itself (`upgrade_http` in the pack). rustup still checks each file against the
hash in its channel manifest.
