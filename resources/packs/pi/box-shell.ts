// A pi extension that @box/pi loads with `-e`. It replaces pi's bash tool and its `!` commands with
// ones that start the shell in BOX_SHELL_PATH, this run's box bash, so each command goes through
// the box's policy. pi's own tool starts `shellPath` from settings.json, which every run of a profile
// shares and which a trusted project's .pi/settings.json overrides; this one reads neither.
// shellCommandPrefix still applies: it runs inside the box's bash, so the policy checks it too.
// pack.toml's [agent] comment says why the process title patch is a separate preload, not here.
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createBashTool, createLocalBashOperations } from "@earendil-works/pi-coding-agent";

export default function (pi: ExtensionAPI) {
	const shellPath = process.env.BOX_SHELL_PATH;
	if (!shellPath) return;
	// pi's settings are readable only after the extension loads, so each call reads the prefix.
	// pi before 0.99 has no getSettings, so there the box's bash runs without the prefix.
	const tool = (cwd: string) =>
		createBashTool(cwd, { shellPath, commandPrefix: pi.getSettings?.().shellCommandPrefix });
	// Inactive until pi's own tool selection asks for bash, so --no-builtin-tools, --tools, and a
	// defaultTools setting turn it off as they turn off pi's built-in bash.
	pi.registerTool({
		...createBashTool(process.cwd(), { shellPath }),
		defaultActive: false,
		execute: (id, params, signal, onUpdate, ctx) =>
			tool(ctx.cwd).execute(id, params, signal, onUpdate, ctx),
	});
	// pi has already added shellCommandPrefix to the command it hands these operations.
	pi.on("user_bash", () => ({ operations: createLocalBashOperations({ shellPath }) }));
}
