var fuzz = require("./fuzz.js");

function log(b) {
  console.log(new Uint8Array(b))
}

fuzz.fuzz_havoc(new ArrayBuffer(8), log);
