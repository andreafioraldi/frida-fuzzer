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

exports.UR = function(n) {

  return Math.floor(Math.random() * n);

}

exports.hex_to_arrbuf = function(hexstr) {

  var buf = [];
  for(var i = 0; i < hexstr.length; i+=2)
      buf.push(parseInt(hexstr.substring(i, i + 2), 16));

  buf = new Uint8Array(buf);
  return buf.buffer;

}

exports.str_to_uint8arr = function (str) {
    // from https://gist.github.com/lihnux/2aa4a6f5a9170974f6aa

    var utf8 = [];
    for (var i = 0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
            utf8.push(0xc0 | (charcode >> 6),
                      0x80 | (charcode & 0x3f));
        }
        else if (charcode < 0xd800 || charcode >= 0xe000) {
            utf8.push(0xe0 | (charcode >> 12),
                      0x80 | ((charcode>>6) & 0x3f),
                      0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
            i++;
            // UTF-16 encodes 0x10000-0x10FFFF by
            // subtracting 0x10000 and splitting the
            // 20 bits of 0x0-0xFFFFF into two halves
            charcode = 0x10000 + (((charcode & 0x3ff)<<10)
                      | (str.charCodeAt(i) & 0x3ff));
            utf8.push(0xf0 | (charcode >>18),
                      0x80 | ((charcode>>12) & 0x3f),
                      0x80 | ((charcode>>6) & 0x3f),
                      0x80 | (charcode & 0x3f));
        }
    }

    return new Uint8Array(utf8);

}

exports.uint8arr_to_str = (function () {
    // from https://stackoverflow.com/questions/8936984/uint8array-to-string-in-javascript

    var char_cache = new Array(128);  // Preallocate the cache for the common single byte chars
    var char_from_codept = String.fromCharCode;
    var result = [];

    return function (array) {
        var codept, byte1;
        var buff_len = array.length;

        result.length = 0;

        for (var i = 0; i < buff_len;) {
            byte1 = array[i++];

            if (byte1 <= 0x7F) {
                codept = byte1;
            } else if (byte1 <= 0xDF) {
                codept = ((byte1 & 0x1F) << 6) | (array[i++] & 0x3F);
            } else if (byte1 <= 0xEF) {
                codept = ((byte1 & 0x0F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F);
            } else if (String.fromCodePoint) {
                codept = ((byte1 & 0x07) << 18) | ((array[i++] & 0x3F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F);
            } else {
                codept = 63;    // Cannot convert four byte code points, so use "?" instead
                i += 3;
            }

            result.push(char_cache[codept] || (char_cache[codept] = char_from_codept(codept)));
        }

        return result.join('');
    };
})();

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
