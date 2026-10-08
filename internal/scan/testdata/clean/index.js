const https = require("https");

function greet(name) {
  return "Hello, " + name + "!";
}

const docs = "https://example.com/" + "docs";
const pattern = /h(\d+)/;
console.log(greet("world"), docs, pattern.exec("h1"));
module.exports = { greet };
