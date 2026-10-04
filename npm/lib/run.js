"use strict";

// Runs the prebuilt aes256 binary for this platform with the user's arguments,
// preceded by `command` (`encrypt` or `decrypt`) when one is given.

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"];

module.exports = function run(command) {
  const platform = `${process.platform}-${process.arch}`;
  const binary = path.join(__dirname, "..", "vendor", platform, "aes256");
  if (!fs.existsSync(binary)) {
    console.error(
      `encryptor: no binary for ${platform}. Supported: Linux and macOS on x64 and arm64.`
    );
    process.exit(1);
  }

  const args = process.argv.slice(2);
  if (command) {
    args.unshift(command);
  }

  const child = spawn(binary, args, { stdio: "inherit" });

  // The binary handles Ctrl-C and similar signals itself, wiping keys and
  // removing partial files before it exits. Stay alive until it has, passing
  // on any signal sent only to this process.
  for (const signal of SIGNALS) {
    process.on(signal, () => child.kill(signal));
  }

  child.on("error", (error) => {
    console.error(`encryptor: could not run ${binary}: ${error.message}`);
    process.exit(1);
  });
  child.on("exit", (code, signal) => {
    if (signal) {
      // Die from the same signal so the shell sees it, as if the binary had
      // been run directly.
      process.removeAllListeners(signal);
      process.kill(process.pid, signal);
    }
    process.exit(code ?? 1);
  });
};
