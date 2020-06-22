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
var bitmap = require("./bitmap.js");
var queue = require("./queue.js");

exports.stage_name = "init";
exports.stage_cur  = 0;
exports.stage_max  = 0;

exports.total_execs = 0;
exports.exec_speed = 0;

exports.splice_cycle = 0;

var zeroed_bits = new Uint8Array(config.MAP_SIZE); // TODO memset(..., 0, ...)
var last_status_ts = 0;

function common_fuzz_stuff(/* ArrayBuffer */ buf, callback) {

  Memory.writeByteArray(bitmap.trace_bits, zeroed_bits);

  var ts_0 = (new Date()).getTime();

  try {
    callback(buf);
  } catch (err) {
    // console.log(err.stack)
    if (err.type !== undefined) {
      send({
        "event": "crash",
        "err": err,
        "stage": exports.stage_name,
        "cur": queue.cur_idx,
        "total_execs": exports.total_execs,
        "pending_fav": queue.pending_favored,
        "favs": queue.favoreds,
        "map_rate": bitmap.map_rate,
      }, buf);
    } else if (err.$handle != undefined) {
      send({
        "event": "exception",
        "err": err.message,
        "stage": exports.stage_name,
        "cur": queue.cur_idx,
        "total_execs": exports.total_execs,
        "pending_fav": queue.pending_favored,
        "favs": queue.favoreds,
        "map_rate": bitmap.map_rate,
      }, buf);
    }
    throw err;
  }

  var ts_1 = (new Date()).getTime();

  var exec_ms = ts_1 - ts_0;
  if (exec_ms > config.TIMEOUT) {
    send({
      "event": "crash",
      "err": {"type": "timeout"},
      "stage": exports.stage_name,
      "cur": queue.cur_idx,
      "total_execs": exports.total_execs,
      "pending_fav": queue.pending_favored,
      "favs": queue.favoreds,
      "map_rate": bitmap.map_rate,
    }, buf);
    throw "timeout";
  }
  
  bitmap.classify_counts(bitmap.trace_bits, bitmap.count_class_lookup16);
  
  exports.exec_speed = exec_ms;
  ++exports.total_execs;
  
  if (bitmap.save_if_interesting(buf, exec_ms)) {
  
    if ((ts_1 - last_status_ts) > config.UPDATE_TIME) {
      last_status_ts = ts_1;
      send({
        "event": "status",
        "stage": exports.stage_name,
        "cur": queue.cur_idx,
        "total_execs": exports.total_execs,
        "pending_fav": queue.pending_favored,
        "favs": queue.favoreds,
        "map_rate": bitmap.map_rate,
      });
    }
    
    return exec_ms; // return exec_ms when not saved
      
  }
  
  return null;
  
}


exports.dry_run = function (callback) {

  var buf = undefined;
  
  while (true) {

    send({
      "event": "dry",
      "stage": exports.stage_name,
      "cur": queue.cur_idx,
      "total_execs": exports.total_execs,
      "pending_fav": queue.pending_favored,
      "favs": queue.favoreds,
      "map_rate": bitmap.map_rate,
    });

    var op = recv("input", function (val) {
      if (val.buf === null) {
        buf = null;
        return;
      }
      buf = utils.hex_to_arrbuf(val.buf);
      exports.queue_cur = val.num;
    });

    op.wait();
    if (buf === null) break;
    
    var exec_ms = common_fuzz_stuff(buf, callback);
    if (exec_ms !== null) { // always save initial seeds
    
      queue.add(buf, exec_ms, false);
      bitmap.update_bitmap_score(queue.last());

    }

  }

  send({
    "event": "status",
    "stage": exports.stage_name,
    "cur": queue.cur_idx,
    "total_execs": exports.total_execs,
    "pending_fav": queue.pending_favored,
    "favs": queue.favoreds,
    "map_rate": bitmap.map_rate,
  });

}


function fuzz_havoc(/* ArrayBuffer */ buf, callback, is_splice) {

  if (!is_splice)  {
    exports.stage_name = "havoc";
    exports.stage_max = config.HAVOC_CYCLES * 40; // TODO perf_score & co
  } else {
    exports.stage_name = "splice-" + exports.splice_cycle;
    exports.stage_max = config.SPLICE_HAVOC * 40; // TODO perf_score & co
  }

  for (exports.stage_cur = 0; exports.stage_cur < exports.stage_max;
       exports.stage_cur++) {

    var muted = buf.slice(0);
    muted = mutator.mutate_havoc(muted);
    
    common_fuzz_stuff(muted, callback);
 
  }

}

exports.havoc_stage = function (/* ArrayBuffer */ buf, callback) {

  fuzz_havoc(buf, callback, false);

}

exports.splice_stage = function (/* ArrayBuffer */ buf, callback) {

  exports.splice_cycle = 0;

  if (buf.byteLength <= 1 || queue.size() <= 1) return;

  while (exports.splice_cycle < config.SPLICE_CYCLES) {

    var new_buf = queue.splice_target(buf);

    if (new_buf !== null)
      fuzz_havoc(new_buf, callback, true);

  }

}

