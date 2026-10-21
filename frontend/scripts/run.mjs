// Lance next dev|start sur le port PORT (variable d'env, sinon .env.local, sinon 3001).
// Next ne lit pas PORT depuis .env.local avant de choisir son port : on le passe avec -p.
import { existsSync, readFileSync } from "node:fs";
import { spawn } from "node:child_process";

const mode = process.argv[2];
let port = process.env.PORT;
if (!port && existsSync(".env.local")) {
  port = readFileSync(".env.local", "utf8").match(/^PORT=(\d+)/m)?.[1];
}
port ??= "3001";

spawn("npx", ["next", mode, "-p", port], { stdio: "inherit", shell: true });
