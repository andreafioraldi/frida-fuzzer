# Frida/QBDI Android API Fuzzer

This experimetal fuzzer is meant to be used for API in-memory fuzzing on Android.

The desing is highly inspired and based on AFL/AFL++.

ATM the mutator is quite simple, just the AFL's havoc stage and the seed selection
is simply FIFO (no favored paths, no trimming, no extra features).
Obviously these features are planned, if you want to contribute adding them PR
are well accepted.

ATM I tested only on the two examples under tests/, this is a very WIP project.

## How to

This fuzzer is known to work in the Android Emulator (tested on x86_64) but should work on any rooted x86 Android device in theory.

Firstly, download the Android x86_64 build of QBDI and extract the archive in a subdirectory of this project named `QBDI`.

Then install Frida on your host with `pip3 install frida`.

Make sure to have the root shell and SELinux disabled on your virtual device:

```
host$ adb root
host$ adb shell setenforce 0
```

Download the Android x86_64 frida-server from the repo release page and copy it
on the device under /data/local/tmp (use adb push).

Copy libQBDI.so always in /data/local/tmp.

Start a shell and run the frida-server:

```
device# cd /data/local/tmp
device# ./frida-server-12.7.22-android-x86_64
```

Now install the test app tests/app-debug.apk using the drag & drop into the emulator window.

Then, open the app.

Compile the agent script wiht frida-compile:

```
host$ frida-compile -x index.js -o frida-fuzz-agent.js
```

Fuzz the `test_func` function of the libnative-lib.so library shipped with the test app
with the command:

```
host$ python3 fuzz.py output_folder/ com.example.ndktest1
```

Both interesting testcases and crashes are saved into output_folder.

Enjoy.

![screen1](assets/screen1.png)

