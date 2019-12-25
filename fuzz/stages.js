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
var mutator = require("./mutator.js");
var utils = require("./utils.js");
var state = require("./state.js");
var bitmap = require("./bitmap.js");
var queue = require("./queue.js");

var zeroed_bits = new Uint8Array(config.MAP_SIZE); // TODO memset(..., 0, ...)
var last_status_ts = 0;

function common_fuzz_stuff(/* ArrayBuffer */ buf, callback) {

  Memory.writeByteArray(bitmap.trace_bits, zeroed_bits);

  var ts_0 = (new Date()).getTime();

  try {
    callback(buf);
  } catch (err) {
    //console.log(err.stack)
    if (err.type !== undefined) {
      send({
        "event": "crash",
        "err": err,
        "stage": state.stage_name,
        "cur": queue.cur_idx,
        "total_execs": state.total_execs,
        "pending_fav": queue.pending_favored,
        "map_rate": bitmap.map_rate,
      }, buf);
    } else if (err.$handle != undefined) {
      send({
        "event": "exception",
        "err": err.message,
        "stage": state.stage_name,
        "cur": queue.cur_idx,
        "total_execs": state.total_execs,
        "pending_fav": queue.pending_favored,
        "map_rate": bitmap.map_rate,
      }, buf);
    }
    throw err;
  }

  var ts_1 = (new Date()).getTime();
  var exec_us = ts_1 - ts_0;
  
  bitmap.classify_counts(bitmap.trace_bits, bitmap.count_class_lookup16);
  
  state.exec_speed = exec_us;
  ++state.total_execs;
  
  if (bitmap.save_if_interesting(buf, exec_us)) {
  
    if ((ts_1 - last_status_ts) > config.UPDATE_TIME) {
      last_status_ts = ts_1;
      send({
        "event": "status",
        "stage": state.stage_name,
        "cur": queue.cur_idx,
        "total_execs": state.total_execs,
        "pending_fav": queue.pending_favored,
        "map_rate": bitmap.map_rate,
      });
    }
    
    return exec_us; // return exec_us when not saved
      
  }
  
  return null;
  
}


exports.dry_run = function (callback) {

  var buf = undefined;
  
  while (true) {

    send({
      "event": "dry",
      "stage": state.stage_name,
      "cur": queue.cur_idx,
      "total_execs": state.total_execs,
      "pending_fav": queue.pending_favored,
      "map_rate": bitmap.map_rate,
    });

    var op = recv("input", function (val) {
      if (val.buf === null) {
        buf = null;
        return;
      }
      buf = utils.hex_to_arrbuf(val.buf);
      state.queue_cur = val.num;
    });

    op.wait();
    if (buf === null) break;
    
    var exec_us = common_fuzz_stuff(buf, callback);
    if (exec_us !== null) { // always save initial seeds
    
      queue.add(buf, exec_us, false);
      bitmap.update_bitmap_score(queue.last());

    }

  }

}


function fuzz_havoc(/* ArrayBuffer */ buf, callback, is_splice) {

  if (!is_splice)  {
    state.stage_name = "havoc";
    state.stage_max = config.HAVOC_CYCLES * 40; // TODO perf_score & co
  } else {
    state.stage_name = "splice-" + state.splice_cycle;
    state.stage_max = config.SPLICE_HAVOC * 40; // TODO perf_score & co
  }

  for (state.stage_cur = 0; state.stage_cur < state.stage_max;
       state.stage_cur++) {

    var muted = buf.slice(0);
    muted = mutator.mutate_havoc(muted);
    
    common_fuzz_stuff(muted, callback);
 
  }

}

exports.havoc_stage = function (/* ArrayBuffer */ buf, callback) {

  fuzz_havoc(buf, callback, false);

}

exports.splice_stage = function (/* ArrayBuffer */ buf, callback) {

  state.splice_cycle = 0;

  if (buf.byteLength <= 1 || queue.size() <= 1) return;

  while (state.splice_cycle < config.SPLICE_CYCLES) {

    var new_buf = queue.splice_target(buf);

    if (new_buf !== null)
      fuzz_havoc(new_buf, callback, true);

  }

}

