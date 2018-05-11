#!/usr/bin/env python2.7

import os as OS
import subprocess as Process
import site as Site
import time as Chronos

if 'FLASK_APP' not in OS.environ:
    print "Running server..."
    OS.environ['FLASK_APP'] = __file__
    Process.call(['sudo', '-E', Site.USER_BASE + '/bin/flask', 'run', '--host=0.0.0.0', '--port=80'])
    exit(64)

from flask import Flask
app = Flask(__name__)

@app.route("/")
def hello():
    Chronos.sleep(5)
    return "Authentic"

if __name__ == '__main__':
      app.run(host='0.0.0.0', port=80)