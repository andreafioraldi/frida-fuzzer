import frida
import base64
import time
import os
import sys
import time
import signal

output_folder = sys.argv[1]
if not os.path.exists(output_folder):
    os.mkdir(output_folder)

pid = (sys.argv[2])

mypid = os.getpid()

class QEntry(object):
    def __init__(self):
        self.filename = ""
        self.size = 0
        self.num = 0
        self.was_fuzzed = False
        self.exec_us = 0
        self.time = 0
        self.new_cov = False
        self.next = None

class Queue(object):
    def __init__(self):
        self.size = 0
        self.start = None
        self.cur = None
        self.top = None

    def add(self, buf, exec_us, new_cov, stage):
        q = QEntry()
        q.filename = os.path.join(output_folder, "id_%d_%s" % (self.size, stage))
        if new_cov:
            q.filename += "_cov"
        q.num = self.size
        q.exec_us = exec_us
        q.new_cov = new_cov
        q.time = int(time.time())
        q.size = len(buf)
        with open(q.filename, "wb") as f:
            f.write(buf)
        self.size += 1
        if self.top:
            self.top.next = q
            self.top = q
        else:
            self.start = q
            self.top = q
    
    def get(self):
        if self.cur is None:
            self.cur = self.start
        elif self.cur.next is None:
            self.cur = self.start
        else:
            q = self.cur.next
            self.cur = q
        return self.cur

queue = Queue()
start_time = 0
last_path = 0

def readable_time(t):
    h = t // 60 // 60
    m = t // 60 - h * 60
    s = t - m * 60
    return "%dh-%dm-%ds" % (h, m, s)

def status_screen(status):
    global queue, pid
    t = time.time()
    TERM_HOME = "\x1b[H"
    TERM_CLEAR = TERM_HOME + "\x1b[2J"
    print (TERM_CLEAR)
    print (" |=------------=[ frida-fuzz ]=------------|")
    print ("   target app       :", pid)
    print ("   output folder    :", output_folder)
    print ("   uptime           :", readable_time(t - start_time))
    print ("   last path        :", readable_time(last_path - start_time))
    print ("   queue size       :", queue.size)
    print ("   last stage       :", status["stage"])
    print ("   current testcase :", "<init>" if queue.cur is None else os.path.basename(queue.cur.filename))
    print ("   total executions :", status["total_execs"])
    print ("   execution speed  : %d/sec" % (status["total_execs"] / (t - start_time)))
    print (" |=----------------------------------------|\n")

with open("frida-fuzz-agent.js") as f:
    code = f.read()

device = frida.get_usb_device()
session = device.attach(pid)
session.enable_jit()

script = session.create_script(code)

def on_interesting(message, data):
    global queue, last_path
    exec_us = message["exec_us"]
    new_cov = message["new_cov"]
    stage = message["stage"]
    last_path = time.time()
    queue.add(data, exec_us, new_cov, stage)

def on_next(message, data):
    global queue
    q = queue.get()
    with open(q.filename, "rb") as f:
        buf = f.read()
    script.post({
      "type": "input",
      "buf": buf.hex(),
      "was_fuzzed": q.was_fuzzed,
    })

def on_crash(message, data):
    global queue, script, session
    print ("\n"*2 + " ************** CRASH FOUND! **************")
    print ("    type:", message["err"]["type"])
    if "memory" in message["err"]:
        print ("    %s at:" % message["err"]["memory"]["operation"], message["err"]["memory"]["address"])
    print ("")
    t = int(time.time())
    name = os.path.join(output_folder, "crash_%s_%s_%d" % (message["stage"], message["err"]["type"], t))
    #name = os.path.join(output_folder, "crash_%d" % t)
    print (" >> Saving at %s" % name)
    with open(name, "wb") as f:
        f.write(data)
    print (" >> Press Control-C to exit...")
    script.unload()
    session.detach()

def on_stats(message, data):
    status_screen(message)

def on_message(message, data):
    if message["type"] == "error":
        print (" ************** FUZZER ERROR! **************")
        print ("  line %d: %s" % (message["lineNumber"], message["description"]))
        print ("  JS stacktrace:\n")
        print (message["stack"])
        print ("")
        exit (1)
    msg = message["payload"]
    if msg["event"] == "interesting":
        on_interesting(msg, data)
        on_stats(msg, data)
    elif msg["event"] == "next":
        on_next(msg, data)
        on_stats(msg, data)
    elif msg["event"] == "crash":
        on_crash(msg, data)
    elif msg["event"] == "stats":
        on_stats(msg, data)

# init testcase

script.on('message', on_message)

script.load()

def signal_handler(sig, frame):
    print (" >> Exiting...")
    try:
        script.unload()
        session.detach()
    except: pass
    exit (0)
signal.signal(signal.SIGINT, signal_handler)

start_time = int(time.time())

last_path = start_time
queue.add(b"0000", 0, True, "init")

script.exports.loop()

