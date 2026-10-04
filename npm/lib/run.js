"use strict";

// Runs the prebuilt encryptor binary for this platform with the user's
// arguments, under `name`: encrypt, decrypt, encryptor or the old aes256. The
// binary tells from its name what to do, as it does when run through a link.

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"];

module.exports = function run(name) {
  const platform = `${process.platform}-${process.arch}`;
  const binary = path.join(__dirname, "..", "vendor", platform, "encryptor");
  if (!fs.existsSync(binary)) {
    console.error(
      `encryptor: no binary for ${platform}. Supported: Linux and macOS on x64 and arm64.`
    );
    process.exit(1);
  }

  const child = spawn(binary, process.argv.slice(2), { stdio: "inherit", argv0: name });

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
