import frida
import base64
import sys

def status_screen(status):
    print ('\E[H\E[J$<50>') # clear
    print (" |=------------=[ frida-fuzz ]=------------|")
    print ("   Executions: %d (%d/sec)" % (status["total_execs"], status["exec_speed"]))

pid = frida.spawn(cmd)
session = frida.attach(pid)

def on_interesting(message, data):
    print(message)
script.on('interesting', on_interesting)

def on_next(message, data):
    print(message)
script.on('next', on_next)

def on_crash(message, data):
    print(message)
script.on('crash', on_crash)

def on_stats(message, data):
    print(message)
script.on('stats', on_stats)

script.load()

sys.stdin.read()

