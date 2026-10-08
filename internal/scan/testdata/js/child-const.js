import { execSync as run } from "node:child_process";
run("echo hello", { stdio: "inherit" });
