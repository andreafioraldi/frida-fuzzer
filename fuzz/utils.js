/*

   frida-fuzzer - frida agent instrumentation
   ------------------------------------------

   Written and maintained by Andrea Fioraldi <andreafioraldi@gmail.com>
   Based on American Fuzzy Lop by Michal Zalewski

   Copyright 2019 Andrea Fioraldi. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

exports.hex_to_arrbuf = function(hexstr) {

  var buf = [];
  for(var i = 0; i < hexstr.length; i+=2)
      buf.push(parseInt(hexstr.substring(i, i + 2), 16));

  buf = new Uint8Array(buf);
  return buf.buffer;

}

exports.UR = function(n) {

  return Math.floor(Math.random() * n);

}

exports.locate_diffs = function (buf1, buf2) {

    var a = new Uint8Array(buf1);
    var b = new Uint8Array(buf2);

    var f_loc = null;
    var l_loc = null;
    var range = Math.min(a.byteLength, b.byteLength);

    for (var i = 0; i < range; i++) {
        if (a[i] !== b[i]) {
            if (f_loc === null) f_loc = i;
            l_loc = i;
        }
    }

    return [f_loc, l_loc];

}
