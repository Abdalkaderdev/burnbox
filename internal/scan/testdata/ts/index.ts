import * as cp from "child_process";

const total: number = eval("1 + 1");
const name: string = process.argv[2] ?? "world";
cp.spawnSync(`echo ${name}`, { shell: true, stdio: "inherit" });
const re = /a/;
re.exec("abc");
console.log(total);
