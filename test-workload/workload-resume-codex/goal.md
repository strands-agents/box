# Workload: work that a later thread resumes (run one of two)

The project directory is `{{PROJECT}}`. This thread will be stopped, and a later
invocation will resume it and ask you what you did here.

Remember this token: `{{NONCE}}`. Do not write the token into any file in this
run. Repeat it in your reply.

Do all of this, in order, with your shell tool, one command per step. Do not use
`apply_patch` or any file-editing tool in this task.

1. `mkdir d1`
2. `mkdir d2`
3. `mkdir d3`
4. `ls`

Never use `mkdir -p`, and create no other directory. The box enforces a budget
on directory creation. If a `mkdir` is refused, do not retry it; say so in your
reply and continue with the next step.

Reply with the token and the names of the directories `ls` showed.
