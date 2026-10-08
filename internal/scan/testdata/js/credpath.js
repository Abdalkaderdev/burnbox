const os = require("os");
const path = require("path");
const where = path.join(os.homedir(), ".ssh", "known_hosts");
console.log("path only, never opened:", where);
