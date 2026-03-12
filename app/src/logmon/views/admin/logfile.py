'''
logfile
---------
Admin view for monitoring log files in real-time and sending email alerts on errors.
'''
import os, time, glob, threading, re

# pypi
from flask import Flask, render_template, send_from_directory, abort, request
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin, login_required
from flask_security.utils import hash_password

# home grown
from ... import app, socketio
from ...model import db, LogEntry

LOG_START_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}')

LAST_ALERT = {}

def send_email_alert(content, path):
    with app.app_context():
        msg = Message(subject=f"⚠️ Exception: {os.path.basename(path)}",
                      recipients=[app.config['ADMIN_EMAIL']],
                      body=f"Error in {path}:\n\n{content}")
        try: mail.send(msg)
        except Exception as e: print(f"Mail failed: {e}")

def tail_file(path):
    with open(path, 'r') as f:
        f.seek(0, os.SEEK_END)
        buffer = []
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5); continue
            if LOG_START_PATTERN.match(line):
                if buffer:
                    msg = "".join(buffer)
                    is_err = "ERROR" in msg or "Traceback" in msg
                    with app.app_context():
                        entry = LogEntry(source=os.path.basename(path), content=msg, is_error=is_err)
                        db.session.add(entry); db.session.commit()
                        socketio.emit('new_log', {'source': entry.source, 'content': entry.content})
                        if is_err and (time.time() - LAST_ALERT.get(path, 0) > 300):
                            send_email_alert(msg, path)
                            LAST_ALERT[path] = time.time()
                buffer = [line]
            else: buffer.append(line)
