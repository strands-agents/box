// Node loads this file before pi, through `--import` in the box's command. It changes two Node calls
// pi makes at startup, and nothing else:
//
// - `process.title`: pi sets its process title, and in a box that call ends the Node process. The
//   setter does nothing here.
// - `fs.utimes`, `fs.futimes`, `fs.lutimes`, their `Sync` forms, and `fs.promises.utimes` and
//   `fs.promises.lutimes`: pi's credential and model stores probe the timestamp precision of a lock
//   file through these, and Box does not let the agent change file timestamps inside a write grant.
//   Each one reports success here without touching the file. Node has no `fs.promises.futimes`; its
//   promise form is a method on an open file handle, which pi's stores do not use.
import fs from "node:fs";

Object.defineProperty(process, "title", { get: () => "pi", set: () => {} });

const succeed = () => undefined;
const succeedWithCallback = (...args) => args.at(-1)(null);
const succeedAsync = async () => undefined;

for (const name of ["utimes", "futimes", "lutimes"]) {
  fs[name] = succeedWithCallback;
  fs[`${name}Sync`] = succeed;
}
fs.promises.utimes = succeedAsync;
fs.promises.lutimes = succeedAsync;
