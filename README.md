# Frida API Fuzzer

This experimetal fuzzer is meant to be used for API in-memory fuzzing.

The desing is highly inspired and based on AFL/AFL++.

ATM the mutator is quite simple, just the AFL's havoc stage and the seed selection
is simply FIFO (no favored paths, no trimming, no extra features).
Obviously these features are planned, if you want to contribute adding them PR
are well accepted.

I tested only on the two examples under tests/, this is a very WIP project but is know to works at least on GNU/Linux x86_64 and Android x86_64.

## How to

Firstly, install Frida on your host with `pip3 install frida`.

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

Now install the test app tests/app-debug.apk using the drag & drop into the emulator window.

Then, open the app.

Compile the agent script wiht frida-compile:

```
host$ frida-compile -x tests/test_ndk_x64.js -o fuzzer-agent.js
```

Fuzz the `test_func` function of the libnative-lib.so library shipped with the test app
with the command:

```
host$ ./fuzzer.py -o output_folder/ com.example.ndktest1
```

Both interesting testcases and crashes are saved into output_folder.

Enjoy.

![screen1](assets/screen1.png)

