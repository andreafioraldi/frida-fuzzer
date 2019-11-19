import frida
import base64
import time
import os
import sys

output_folder = sys.argv[1]
if not os.path.exists(output_folder):
    os.mkdir(output_folder)

cmd = sys.argv[2:]

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
        q.filename = "queue/id_%s_%d" % (stage, self.size)
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

def status_screen(status):
    global queue
    print (chr(27) + "[2j") # clear
    print ('\033c')
    print ("\x1bc")
    print (" |=------------=[ frida-fuzz ]=------------|")
    print ("   output folder    :", output_folder)
    print ("   total executions :", status["total_execs"])
    print ("   execution speed  : %d/sec" % status["exec_speed"])
    print ("   current testcase :", "<init>" if queue.cur is None else os.path.basename(queue.cur.filename))
    print ("   queue size       :", queue.size)
    print ("   last stage       :", status["stage"])
    print (" |=----------------------------------------|")

with open("frida-fuzz-agent.js") as f:
    code = f.read()

pid = frida.spawn(cmd)
session = frida.attach(pid)
session.enable_jit()

script = session.create_script(code)

def on_interesting(message, data):
    global queue
    exec_us = message["exec_us"]
    new_cov = message["new_cov"]
    stage = message["stage"]
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
    global queue
    print ("\n ************** CRASH FOUND! **************")
    t = int(time.time())
    name = "crash_%d" % t
    print (" >> Saving at %s" % name)
    with open(name, "wb") as f:
        f.write(data)
    print (" >> Exiting...")
    exit (134)

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
queue.add(b"0000", 0, True, "init")

script.on('message', on_message)

script.load()

script.exports.loop()

