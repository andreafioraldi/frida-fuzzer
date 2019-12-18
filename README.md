# Frida API Fuzzer

> v1.0 Copyright (C) 2019 Andrea Fioraldi <andreafioraldi@gmail.com>

> Released under the Apache License v2.0

This experimetal fuzzer is meant to be used for API in-memory fuzzing.

The desing is highly inspired and based on AFL/AFL++.

ATM the mutator is quite simple, just the AFL's havoc and splice stages and the seed selection
is simply FIFO (no favored paths, no trimming, no extra features).
Obviously these features are planned, if you want to contribute adding them PR
are well accepted.

I tested only on the two examples under tests/, this is a WIP project but is know to works at least on GNU/Linux x86_64 and Android x86_64.

You need Frida >= 12.8.0 to run this (`pip3 install -U frida`) and frida-tools to compile harness.

## Usage

The `fuzz` library has to be imported into a custom harness and then compiled with `frida-compile` to generate the agent that `frida-fuzzer` will inject into the target app.

The majority of the logic of the fuzzer is in the agent.

An harness has the following format:

```js
var fuzz = require("./fuzz");

var TARGET_MODULE = "test_linux64";
var TARGET_FUNCTION = DebugSymbol.fromName("target_func").address;;
var RET_TYPE = "void";
var ARGS_TYPES = ['pointer', 'int'];

var func_handle = new NativeFunction(TARGET_FUNCTION, RET_TYPE, ARGS_TYPES, { traps: 'all' });

fuzz.target_module = TARGET_MODULE;

fuzz.fuzzer_test_one_input = function (/* NativePointer */ payload, size) {

  func_handle(payload, size);

}
```

`fuzz.fuzzer_test_one_input` is mandatory. If you don't specify `fuzz.target_module`, all the code executed will be instrumented.

You can also set `fuzz.manual_loop_start = true` to tell the fuzzer that you will call `fuzz.fuzzing_loop()` in a callback and so it must not call it for you (e.g. to start fuzzing when a button is clicked in the Android app).

`frida-fuzzer` accepts the following arguments:

<table>
    <tr>
        <td>-i FOLDER</td>
        <td>Folder with initial seeds</td>
    </tr>
    <tr>
        <td>-o FOLDER</td>
        <td>Output folder with intermediate seeds and crashes</td>
    </tr>
    <tr>
        <td>-U</td>
        <td>Connect to USB</td>
    </tr>
    <tr>
        <td>-spawn</td>
        <td>Spawn and attach instead of simply attach</td>
    </tr>
    <tr>
        <td>-script SCRIPT</td>
        <td>Script filename (default is fuzzer-agent.js)</td>
    </tr>
</table>

Running `./frida-fuzzer -spawn ./tests/test_linux64` you will see something like the following status screen on your terminal:

```
 |=---------------=[ frida-fuzzer ]=---------------=|
   target app       : ./tests/test_linux64
   output folder    : /tmp/frida_fuzz_out_i3x37gbq
   uptime           : 0h-0m-1s
   last path        : 0h-0m-0s
   queue size       : 6
   last stage       : splice-13
   current testcase : id_1_havoc_cov
   total executions : 32000
   execution speed  : 17298/sec
 |=------------------------------------------------=|
```

You can also easily add a custom stage in `fuzz/fuzzer.js` and add it to the stages array in `fuzz/index.js`.

## Example

Let's fuzz the native shared library into the example Android app in `tests`.

Make sure to have root on your virtual device:

```
host$ adb root
```

Download the Android x86_64 frida-server from the repo release page and copy it
on the device under /data/local/tmp (use adb push).

Start a shell and run the frida-server:

```
device# cd /data/local/tmp
device# ./frida-server
```

Now install the test app `tests/app-debug.apk` using the drag & drop into the emulator window.

Then, open the app.

Compile the agent script wiht frida-compile:

```
host$ frida-compile -x tests/test_ndk_x64.js -o fuzzer-agent.js
```

Open the app in the emulator.

Fuzz the `test_func` function of the `libnative-lib.so` library shipped with the test app
with the command:

```
host$ ./frida-fuzzer -U -o output_folder/ com.example.ndktest1
```

Both interesting testcases and crashes are saved into output_folder.

Enjoy.

![screen1](assets/screen1.png)

## TODO

Hey OSS community, there are a lot of TODOs if someone wants to contribute.

+ Java code fuzzing (waiting for additional exposed methods in frida-java-bridge, should be easy, almost done)
+ ~~splice stage (merge two testcase in queue and apply havoc on it)~~
+ inlined istrumentation for x86, arm and arm64 (x86_64 is the only inlined atm)
+ support dictionaries (and so modify also havoc)
+ seed selection and performance scoring (explore schedule of AFL)
+ structural mutator (mutate bytes based on a grammar written in JSON)
+ CompareCoverage (sub-instruction profiling to bypass fuzzing roadblocks)
+ rewrite frida-fuzzer in C with frida-core to be able to run all the stuffs on the mobile device

If you have doubt on one of this featues feel free to DM me on [Twitter](https://twitter.com/andreafioraldi).

For features proposals, there is the [Issues section](https://github.com/andreafioraldi/frida-fuzzer/issues).

