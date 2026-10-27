# git pack corpus

Each row is one command line, and what the shell grammar of `../valid/git.pack.toml` reads
it as. `Fields` lists, in TOML, each field that does not hold its default: a Bool `false`, an
empty set, or an absent string. `—` means none. An `unmodeled` row has no fields and no effects.
Rows marked "verified" were checked against git 2.50.

| Command line | Action | Fields | Effects | Note |
|---|---|---|---|---|
| `git push -f origin main` | push | force = true, refspec = ["main"], remote = "origin" | force_push, network |  |
| `git push -uf origin main` | push | force = true, refspec = ["main"], remote = "origin", set_upstream = true | force_push, network |  |
| `git push origin main --force` | push | force = true, refspec = ["main"], remote = "origin" | force_push, network |  |
| `git push --force-with-lease origin main` | push | force_with_lease = "", refspec = ["main"], remote = "origin" | force_push, network |  |
| `git push --force-with-lease=main:abc123 origin main` | push | force_with_lease = "main:abc123", refspec = ["main"], remote = "origin" | force_push, network |  |
| `git push --force-with-lease origin` | push | force_with_lease = "", remote = "origin" | force_push, network | An optional value never takes the next word |
| `git push origin +main` | push | refspec = ["+main"], remote = "origin" | force_push, network |  |
| `git push origin '+refs/heads/*:refs/heads/*'` | push | refspec = ["+refs/heads/*:refs/heads/*"], remote = "origin" | force_push, network |  |
| `git -C app push -f origin main` | push | directory = "app", force = true, refspec = ["main"], remote = "origin" | force_push, network |  |
| `git push -n -f origin main` | push | dry_run = true, force = true, refspec = ["main"], remote = "origin" | network |  |
| `git push -fn origin main` | push | dry_run = true, force = true, refspec = ["main"], remote = "origin" | network | The same as the row above: removes win, in any order |
| `git push origin :old-topic` | push | refspec = [":old-topic"], remote = "origin" | delete_remote_ref, network |  |
| `git push -d origin old-topic` | push | delete = true, refspec = ["old-topic"], remote = "origin" | delete_remote_ref, network |  |
| `git push --mirror backup` | push | mirror = true, remote = "backup" | delete_remote_ref, force_push, network |  |
| `git push --prune origin 'refs/heads/*:refs/heads/*'` | push | prune = true, refspec = ["refs/heads/*:refs/heads/*"], remote = "origin" | delete_remote_ref, network |  |
| `git push --repo=upstream` | push | repo = "upstream" | network | `remote` is absent, so a policy that reads only `remote` misses this push |
| `git push -o ci.skip origin` | push | push_option = ["ci.skip"], remote = "origin" | network |  |
| `git push --receive-pack=/tmp/x ../local.git main` | push | receive_pack = "/tmp/x", refspec = ["main"], remote = "../local.git" | network, run_program |  |
| `git push origin -- -f` | push | refspec = ["-f"], remote = "origin" | network | After `--`, every word is an operand, so `-f` is a refspec and not `--force` |
| `git push --dele origin main` | unmodeled | — | — | Git takes `--dele` as `--delete` (verified); the parser does no prefix matching |
| `git push --no-force origin main` | unmodeled | — | — | The pack does not declare the negation |
| `git push --dry-run=yes` | unmodeled | — | — | A flag with no value is given a value (git: "takes no value", verified) |
| `git -c core.sshCommand=/tmp/x push origin main` | push | config = ["core.sshCommand=/tmp/x"], refspec = ["main"], remote = "origin" | network, override_config |  |
| `git --exec-path=/tmp/evil push` | unmodeled | — | — | `--exec-path` not declared on purpose |
| `git -C a -C b status` | unmodeled | — | — | Non-repeated value option given twice (git would cd into `a/b`) |
| `git -Capp status` | status | directory = "app" | — | Git refuses `-Capp` (verified); over-acceptance is harmless |
| `git -C push status` | status | directory = "push" | — | The value is taken before the command word |
| `git --git-dir ../o/.git --work-tree ../o log` | log | git_dir = "../o/.git", work_tree = "../o" | — | The separate-word form (verified) |
| `git status -C .` | unmodeled | — | — | Global option after the subcommand (git: "unknown switch", verified) |
| `git commit -am "fix parser"` | commit | all = true, message = ["fix parser"] | — | A value option ends the cluster and takes the next word (verified) |
| `git commit -m"msg"` | commit | message = ["msg"] | — | The value is attached to the flag |
| `git commit -mmsg` | commit | message = ["msg"] | — | The value is attached to the flag |
| `git commit -m=foo` | unmodeled | — | — | Short value option with attached `=`; git reads `=foo` (verified), clap reads `foo` |
| `git commit -m a -m b` | commit | message = ["a", "b"] | — | A repeated option |
| `git commit -m` | unmodeled | — | — | The value is missing |
| `git commit --amend --no-edit` | commit | amend = true, no_edit = true | rewrite_history |  |
| `git commit -n -m wip` | commit | message = ["wip"], no_verify = true | skip_hooks | For commit, `-n` is `--no-verify` |
| `git commit --amen --no-edit` | unmodeled | — | — | Prefix of `--amend`; git accepts it (verified) |
| `git commit --amend --dry-run` | commit | amend = true, dry_run = true | — |  |
| `git reset --hard HEAD~1` | reset | commit = "HEAD~1", hard = true | discard_changes |  |
| `git reset HEAD -- src/lib.rs` | reset | commit = "HEAD", pathspec = ["src/lib.rs"] | — |  |
| `git reset -- HEAD` | reset | pathspec = ["HEAD"] | — | Commit absent (`--` splits the groups) |
| `git rebase -i --autosquash main` | rebase | autosquash = true, interactive = true, upstream = "main" | rewrite_history |  |
| `git rebase -x "cargo test" origin/main` | rebase | exec = ["cargo test"], upstream = "origin/main" | rewrite_history, run_program |  |
| `git rebase --abort` | rebase | abort = true | — |  |
| `git clean -fdx` | clean | directories = true, force = true, ignored = true | discard_changes |  |
| `git clean -nfd` | clean | directories = true, dry_run = true, force = true | — |  |
| `git clean -i` | clean | interactive = true | discard_changes |  |
| `git checkout -- src/main.rs` | checkout | pathspec = ["src/main.rs"] | discard_changes |  |
| `git checkout .` | checkout | target = "." | discard_changes |  |
| `git checkout -b topic origin/main` | checkout | create = "topic", target = "origin/main" | — |  |
| `git checkout src/main.rs` | checkout | target = "src/main.rs" | — | Known gap: git restores the file; the parser cannot tell a path from a branch |
| `git checkout -` | checkout | target = "-" | — | A lone `-` is an operand |
| `git switch -c feature` | switch | create = "feature" | — |  |
| `git switch -f main` | switch | discard_changes = true, target = "main" | discard_changes |  |
| `git status -sb` | status | branch = true, short = true | — |  |
| `git status -uno` | status | untracked_files = "no" | — | Optional value, attached |
| `git status -u no` | status | pathspec = ["no"], untracked_files = "" | — |  |
| `git log -5 --oneline` | unmodeled | — | — | The pack has no `-<n>` form |
| `git log -n5 --oneline main` | log | max_count = "5", oneline = true, revision = ["main"] | — | A string: the parser does not check that the value is a number |
| `git log --max-count=many` | log | max_count = "many" | — | No `type = "long"`, so the value is not checked |
| `git log -p -- src/` | log | patch = true, path = ["src/"] | — |  |
| `git log --output=/tmp/x` | log | output = "/tmp/x" | write_file |  |
| `git diff --no-index /etc/passwd /dev/null` | diff | commit = ["/dev/null", "/etc/passwd"], no_index = true | read_outside_repo |  |
| `git diff --cached -- src` | diff | cached = true, path = ["src"] | — |  |
| `git diff --ext-diff HEAD~1` | diff | commit = ["HEAD~1"], ext_diff = true | run_program |  |
| `git add -A` | add | all = true | — |  |
| `git add -- -weird-name` | add | pathspec = ["-weird-name"] | — |  |
| `git fetch -n origin` | fetch | no_tags = true, remote = "origin" | network | For fetch, `-n` is not dry-run |
| `git fetch --upload-pack=/tmp/x origin` | fetch | remote = "origin", upload_pack = "/tmp/x" | network, run_program |  |
| `git pull --rebase` | pull | rebase = "" | network, rewrite_history |  |
| `git pull -r origin main` | pull | rebase = "", refspec = ["main"], remote = "origin" | network, rewrite_history |  |
| `git pull --rebase=false origin main` | pull | rebase = "false", refspec = ["main"], remote = "origin" | network |  |
| `git --no-pager -c color.ui=always log` | log | config = ["color.ui=always"], no_pager = true | override_config |  |
| `git frobnicate` | unmodeled | — | — | An unknown subcommand |
| `git ci -m x` | unmodeled | — | — | A git configuration alias, which the parser cannot see |
| `git` | unmodeled | — | — | No command word |
| `git --version` | unmodeled | — | — | No command word |
| `git push --help` | unmodeled | — | — | `--help` not declared |
| `git -C app push -uf origin main` | push | directory = "app", force = true, refspec = ["main"], remote = "origin", set_upstream = true | force_push, network | A global option, a cluster, and operands |
| `git push --forc origin main` | unmodeled | — | — | A shortened long option |
| `git push -- origin main` | push | refspec = ["main"], remote = "origin" | network | `--` before the operands, with no `--` in the usage |
| `git status -usb` | status | untracked_files = "sb" | — | An optional value takes the rest of its cluster |
| `git -- status` | unmodeled | — | — | `--` before the command words |
| `git +stable status` | unmodeled | — | — | The git pack has no `[+<toolchain>]` |
