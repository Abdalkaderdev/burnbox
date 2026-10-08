const cp = require("child_process");
const words = ["echo", "hello"];
cp.execSync(words.join(" "), { stdio: "inherit" });
