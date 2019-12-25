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
var state = require("./state.js");
var bitmap = require("./bitmap.js");
var utils  = require("./utils.js");

var temp_v_size = config.MAP_SIZE >> 3;
var temp_v = Memory.alloc(temp_v_size);

var queue = [];

var bytes_size = 0;

/* cur.buf is not guaranteed to be !== null, use always the buf provided as
   argument to functions */
exports.cur = null;
exports.cur_idx = -1;

exports.pending_favored = 0;

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
  var buf = q.buf;
  
  if (buf === null) {

    send({
      "event": "get",
      "num": exports.cur_idx,
      "stage": state.stage_name,
      "cur": exports.cur_idx,
      "total_execs": state.total_execs,
      "pending_fav": exports.pending_favored,
      "map_rate": bitmap.map_rate,
    });
    
    var buf = undefined;
    var op = recv("input", function (val) {
      buf = utils.hex_to_arrbuf(val.buf);
    });

    op.wait();
    
    if (bytes_size + buf.byteLength < config.QUEUE_CACHE_MAX_SIZE) {
      // cache it if it fills in cache
      bytes_size += buf.byteLength;
      q.buf = buf;
    }
    
  }

  exports.cur = q;
  return buf;

}

exports.get = function (idx) {

  return queue[idx];

}

/*
exports.download = function (idx) {

  var q = queue[idx];
  if (q.buf === null) {

    send({
      "event": "get",
      "num": idx,
      "stage": state.stage_name,
      "cur": exports.cur_idx,
      "total_execs": state.total_execs,
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

  while (bytes_size >= (config.QUEUE_CACHE_MAX_SIZE / 2)) {
  
    var r = UR(queue.length);
    var not_del = true;

    for(var i = r; not_del && i < queue.length; ++i) {
      if (i == exports.cur_idx || queue[i].buf === null)
        continue;
      queue[i].buf = null;
      not_del = false;
    }
    
    for(var i = 0; not_del && i < r; ++i) {
      if (i == exports.cur_idx || queue[i].buf === null)
        continue;
      queue[i].buf = null;
      not_del = false;
    }
  
  }

}

exports.add = function (buf, exec_us, has_new_cov) {

  if (buf.byteLength >= config.QUEUE_CACHE_MAX_SIZE) {
    
    queue.push({
      buf: null,
      size: buf.byteLength,
      exec_us: exec_us,
      favored: false,
      was_fuzzed: false,
      trace_mini: null,
      tc_ref: 0,
    });
    
  } else {

    bytes_size += buf.byteLength;
    
    if (bytes_size >= config.QUEUE_CACHE_MAX_SIZE)
      prune_memory();

    queue.push({
      buf: buf.slice(0),
      size: buf.byteLength,
      exec_us: exec_us,
      favored: false,
      was_fuzzed: false,
      trace_mini: null,
      tc_ref: 0,
    });

  }

  send({
    "event": "interesting",
    "num": (queue.length -1),
    "exec_us": exec_us,
    "new_cov": has_new_cov,
    "stage": state.stage_name,
    "cur": exports.cur_idx,
    "total_execs": state.total_execs,
    "pending_fav": exports.pending_favored,
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

  if (t.buf === null) { // fallback to the python fuzz driver 
  
    send({
      "event": "splice",
      "num": exports.cur_idx,
      "cycle": state.splice_cycle,
      "stage": state.stage_name,
      "cur": exports.cur_idx,
      "total_execs": state.total_execs,
      "pending_fav": exports.pending_favored,
      "map_rate": bitmap.map_rate,
    });
    
    var op = recv("splice", function (val) {
      if (val.buf !== null && val.buf !== undefined)
        new_buf = utils.hex_to_arrbuf(val.buf);
      state.splice_cycle = val.cycle; // important to keep
    });

    op.wait();
    
    return new_buf;
  
  } else {
  
    new_buf = t.buf.slice(0);
    state.splice_cycle++;
    
  }
  
  /*send({
    "event": "status",
    "stage": state.stage_name,
    "cur": exports.cur_idx,
    "total_execs": state.total_execs,
  });*/
  
  var diff = utils.locate_diffs(buf, new_buf);
  if (diff[0] === null || diff[1] < 2 || diff[0] === diff[1])
      return null;

  var split_at = diff[0] + utils.UR(diff[1] - diff[0]);
  new Uint8Array(new_buf).set(new Uint8Array(buf.slice(0, split_at)), 0);
  return new_buf;

}


exports.cull = function () {

  if (!bitmap.score_changed) return;

  bitmap.score_changed = false;
  exports.pending_favored = 0;
  
  var top_rated = bitmap.top_rated;
  
  var i;
  for (i = 0; i < temp_v_size; i += 4)
    temp_v.add(i).writeU32(0xffffffff);
  
  var temp_v_arr = new Uint8Array(ArrayBuffer.wrap(temp_v, temp_v_size));
  
  for (i = 0; i < queue.length; ++i)
    queue[i].favored = false;

  /* Let's see if anything in the bitmap isn't captured in temp_v.
     If yes, and if it has a top_rated[] contender, let's use it. */

  for (i = 0; i < config.MAP_SIZE; i++) {
  
    if (top_rated[i] !== undefined && (temp_v_arr[i >> 3] & (1 << (i & 7))) !== 0) {

      var j = config.MAP_SIZE >> 3;

      /* Remove all bits belonging to the current entry from temp_v. */

      while (j--) {
        if (top_rated[i].trace_mini[j])
          temp_v_arr[j] &= ~top_rated[i].trace_mini[j];
      }

      if (!top_rated[i].favored && !top_rated[i].was_fuzzed) exports.pending_favored++;

      top_rated[i].favored = true;
      // favored++;

      

    }
  
  }

}
