const body = ["return", "a + b"].join(" ");
const add = new Function("a", "b", body);
console.log(add(1, 2));
