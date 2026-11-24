# Instructions for Codex in this box

Every file in the project is reached through shell commands. The `apply_patch` tool and direct
file reads fail with "Operation not permitted", so read a file with `cat` or `sed -n`, and change
one with shell commands such as `printf '...' >> file` or `sed -i ''`. When a command reports
"policy denied this operation", quote that line to the user and stop.
