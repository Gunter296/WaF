import { spawn } from "node:child_process";

for (const script of ["migrate.mjs", "seed.mjs"]) {
  const result = await new Promise((resolve) => {
    const child = spawn(process.execPath, [`scripts/${script}`], { stdio: "inherit", env: process.env });
    child.once("exit", (code) => resolve(code ?? 1));
    child.once("error", () => resolve(1));
  });
  if (result !== 0) process.exit(Number(result));
}

const server = spawn(process.execPath, ["node_modules/next/dist/bin/next", "start", "-p", "3000"], { stdio: "inherit", env: process.env });
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => server.kill(signal));
server.once("exit", (code) => process.exit(code ?? 0));
