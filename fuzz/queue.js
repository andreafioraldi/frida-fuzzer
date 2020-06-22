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

var config  = require("./config.js");
var bitmap = require("./bitmap.js");
var utils  = require("./utils.js");
var stages = require("./stages.js");

/* struct QEntry {
  u8* buf;
  u8* trace_mini;
  u32 size;
  u32 exec_ms;
  u32 tc_ref;
  u8 favored;
  u8 was_fuzzed;
}; */
var QENTRY_FIELD_BUF = 0;
var QENTRY_FIELD_TRACE_MINI = QENTRY_FIELD_BUF + Process.pointerSize;
var QENTRY_FIELD_SIZE = QENTRY_FIELD_TRACE_MINI + Process.pointerSize;
var QENTRY_FIELD_EXEC_MS = QENTRY_FIELD_SIZE + 4;
var QENTRY_FIELD_TC_REF = QENTRY_FIELD_EXEC_MS + 4;
var QENTRY_FIELD_FAVORED = QENTRY_FIELD_TC_REF + 4;
var QENTRY_FIELD_WAS_FUZZED = QENTRY_FIELD_FAVORED + 1;
var QENTRY_BYTES = ((QENTRY_FIELD_WAS_FUZZED + 1) + 7) & (-8);

function QEntry(buf, size, exec_ms) {

  var _ptr = Memory.alloc(QENTRY_BYTES);
  this.ptr = _ptr;

  // Beware! Assigning buf does not maintaint the reference, the caller must hold it
  var props = {

    get buf() { 
      return _ptr.readPointer();
    },
    set buf(val) {
      _ptr.writePointer(val);
    },
    get trace_mini() {
      return _ptr.add(QENTRY_FIELD_TRACE_MINI).readPointer();
    },
    set trace_mini(val) {
      _ptr.add(QENTRY_FIELD_TRACE_MINI).writePointer(val);
    },
    get size() {
      return _ptr.add(QENTRY_FIELD_SIZE).readU32();
    },
    set size(val) {
      _ptr.add(QENTRY_FIELD_SIZE).writeU32(val);
    },
    get exec_ms() {
      return _ptr.add(QENTRY_FIELD_EXEC_MS).readU32();
    },
    set exec_ms(val) {
      _ptr.add(QENTRY_FIELD_EXEC_MS).writeU32(val);
    },
    get tc_ref() {
      return _ptr.add(QENTRY_FIELD_TC_REF).readU32();
    },
    set tc_ref(val) {
      _ptr.add(QENTRY_FIELD_TC_REF).writeU32(val);
    },
    get favored() {
      return _ptr.add(QENTRY_FIELD_FAVORED).readU32();
    },
    set favored(val) {
      val = +val; // to int
      _ptr.add(QENTRY_FIELD_FAVORED).writeU32(val);
    },
    get was_fuzzed() {
      return _ptr.add(QENTRY_FIELD_WAS_FUZZED).readU32();
    },
    set was_fuzzed(val) {
      val = +val; // to int
      _ptr.add(QENTRY_FIELD_WAS_FUZZED).writeU32(val);
    },

  };

  if (buf instanceof Uint8Array)
    buf = buf.buffer;
  if (buf instanceof ArrayBuffer) {
    this._bufref = buf; // maintain a reference while using the backing ptr
    buf = buf.unwrap();
  } else if (buf instanceof NativePointer) {
    this._bufref = buf; // maintain a reference to avoid gc
  } else {
    throw "Invalid type for buf";
  }

  props.buf = buf;
  props.size = size;
  props.exec_ms = exec_ms;
  props.favored = false;
  props.was_fuzzed = false;
  // You should never touch trace_mini, see update_bitmap_score_body
  props.trace_mini = ptr(0);
  props.tc_ref = 0;

  Object.assign(this, props);

}

var temp_v_size = config.MAP_SIZE >> 3;
var temp_v = Memory.alloc(temp_v_size);

var queue = [];

var bytes_size = 0;

/* cur.buf is not guaranteed to be !== null, use always the buf provided as
   argument to functions */
exports.cur = null;
exports.cur_idx = -1;

exports.pending_favored = 0;
exports.favoreds = 0;

exports.size = function () {

  return queue.length;

};

exports.last = function () {

  return queue[queue.length -1];

};

exports.next = function () {

  if (exports.cur_idx === queue.length -1)
    exports.cur_idx = 0;
  else
    exports.cur_idx++;
  
  var q = queue[exports.cur_idx];
  var buf = undefined;
  
  if (q.buf.isNull()) {

    send({
      "event": "get",
      "num": exports.cur_idx,
      "stage": stages.stage_name,
      "cur": exports.cur_idx,
      "total_execs": stages.total_execs,
      "pending_fav": exports.pending_favored,
      "favs": exports.favoreds,
      "map_rate": bitmap.map_rate,
    });
    
    var op = recv("input", function (val) {
      buf = utils.hex_to_arrbuf(val.buf);
    });

    op.wait();
    
    if (bytes_size + buf.byteLength < config.QUEUE_CACHE_MAX_SIZE) {

      // cache it if it fills in cache
      bytes_size += buf.byteLength;
      q.buf = buf;

    }
    
  } else {

    buf = ArrayBuffer.wrap(q.buf, q.size);
  
  }

  exports.cur = q;
  // note that prune_memory does not delete cur.buf so this operation is safe
  // for any other stuffs, buf must be copied
  return buf;

}

exports.get = function (idx) {

  return queue[idx];

}

/*
exports.download = function (idx) {

  var q = queue[idx];
  if (q.buf.isNull()) {

    send({
      "event": "get",
      "num": idx,
      "stage": stages.stage_name,
      "cur": exports.cur_idx,
      "total_execs": stages.total_execs,
    });
    
    var buf = undefined;
    var op = recv("input", function (val) {
      q.buf = utils.hex_to_arrbuf(val.buf);
    });

    op.wait();
    
  }
  
  return q;

}
*/

// Delete half of the occupied memory
function prune_memory() {

  var c = 0;
  for (; c < queue.length && bytes_size >= (config.QUEUE_CACHE_MAX_SIZE / 2); ++c) {
  
    var r = UR(queue.length);
    var not_del = true;

    for(var i = r; not_del && i < queue.length; ++i) {
      if (i == exports.cur_idx || queue[i].buf.isNull())
        continue;
      queue[i].buf = ptr(0);
      queue[i]._bufref = undefined;
      not_del = false;
    }
    
    for(var i = 0; not_del && i < r; ++i) {
      if (i == exports.cur_idx || queue[i].buf.isNull())
        continue;
      queue[i].buf = ptr(0);
      queue[i]._bufref = undefined;
      not_del = false;
    }
  
  }

}

exports.add = function (/* ArrayBuffer */ buf, exec_ms, has_new_cov) {

  if (buf.byteLength >= config.QUEUE_CACHE_MAX_SIZE) {
    
    queue.push(new QEntry(ptr(0), buf.byteLength, exec_ms));
    
  } else {

    bytes_size += buf.byteLength;
    
    if (bytes_size >= config.QUEUE_CACHE_MAX_SIZE)
      prune_memory();
    
    if (bytes_size >= config.QUEUE_CACHE_MAX_SIZE) {
      // prune_memory was ineffective
      bytes_size -= buf.byteLength;
      queue.push(new QEntry(ptr(0), buf.byteLength, exec_ms));
    } else {
      queue.push(new QEntry(buf.slice(0), buf.byteLength, exec_ms));
    }

  }

  send({
    "event": "interesting",
    "num": (queue.length -1),
    "exec_ms": exec_ms,
    "new_cov": has_new_cov,
    "stage": stages.stage_name,
    "cur": exports.cur_idx,
    "total_execs": stages.total_execs,
    "pending_fav": exports.pending_favored,
    "favs": queue.favoreds,
    "map_rate": bitmap.map_rate,
  }, buf);

}

/* As always, cur.buf is not guaranteed to be !== null */
exports.splice_target = function (buf) {

  var tid = utils.UR(queue.length);
  var t = queue[tid];
  
  while (tid < queue.length && (queue[tid].size < 2 || tid === exports.cur_idx))
    ++tid;
  
  if (tid === queue.length)
    return null;
  
  t = queue[tid];
  var new_buf = null;

  if (t.buf.isNull()) { // fallback to the python fuzz driver 
  
    send({
      "event": "splice",
      "num": exports.cur_idx,
      "cycle": stages.splice_cycle,
      "stage": stages.stage_name,
      "cur": exports.cur_idx,
      "total_execs": stages.total_execs,
      "pending_fav": exports.pending_favored,
      "favs": queue.favoreds,
      "map_rate": bitmap.map_rate,
    });
    
    var op = recv("splice", function (val) {
      if (val.buf !== null && val.buf !== undefined)
        new_buf = utils.hex_to_arrbuf(val.buf);
      stages.splice_cycle = val.cycle; // important to keep
    });

    op.wait();
    
    return new_buf;
  
  } else {
  
    new_buf = ArrayBuffer.wrap(t.buf, t.size).slice(0);
    stages.splice_cycle++;
    
  }
  
  /*send({
    "event": "status",
    "stage": stages.stage_name,
    "cur": exports.cur_idx,
    "total_execs": stages.total_execs,
  });*/
  
  var diff = utils.locate_diffs(buf, new_buf);
  if (diff[0] === null || diff[1] < 2 || diff[0] === diff[1])
      return null;

  var split_at = diff[0] + utils.UR(diff[1] - diff[0]);
  new Uint8Array(new_buf).set(new Uint8Array(buf.slice(0, split_at)), 0);
  return new_buf;

}

exports.__cm = new CModule(`

#include <stdint.h>
#include <stdio.h>

#define MAP_SIZE __MAP_SIZE__

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

struct __attribute__((packed)) QEntry {

  u8* buf;
  u8* trace_mini;
  u32 size;
  u32 exec_ms;
  u32 tc_ref;
  u8 favored;
  u8 was_fuzzed;

};

u64 cull_body(struct QEntry** top_rated, u8* temp_v) {

  u32 pending_favored = 0;
  u32 favoreds = 0;
  
  u32 i;
  for (i = 0; i < (MAP_SIZE >> 3); ++i) {
    temp_v[i] = 0xff;
  }

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */
  
  for (i = 0; i < MAP_SIZE; ++i) {
    
    if (top_rated[i] != NULL && (temp_v[i >> 3] & (1 << (i & 7))) != 0) {

      u32 j = MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) {
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];
      }

      if (!top_rated[i]->was_fuzzed)
        pending_favored++;

      top_rated[i]->favored = 1;
      favoreds++;

    }

  }

  return (pending_favored << 32) | favoreds;

}

`.replace("__MAP_SIZE__", ""+config.MAP_SIZE)
);

var cull_body = new NativeFunction(
  exports.__cm.cull_body,
  "uint",
  ["pointer", "pointer"]
);

exports.cull = function () {

  if (!bitmap.score_changed) return;
  bitmap.score_changed = false;

  for (var i = 0; i < queue.length; ++i)
    queue[i].favored = 0;

  var r = cull_body(bitmap.top_rated, temp_v);
  exports.favoreds = r & 0xffffffff;
  exports.pending_favored = (r >> 32) & 0xffffffff;

}

