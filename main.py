from flask import Flask, render_template, request, make_response
from flask import redirect, session
import sqlite3
import hashlib
import datetime
import pyscrypt
import sys
import random
import string
import requests
import base64
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


#config ===========
salt = b"SeaSalt"  # if you change the salt after creating a database, you will lose all of your data !
#config ===========


def encrypt(inputstring, key):
    encodedstring = inputstring.encode()
    a = Fernet(key)
    encrypted_string = a.encrypt(encodedstring)
    encrypted_string = encrypted_string.decode()
    return encrypted_string


def decrypt(inputstring, key):
    inputstring = inputstring.encode()
    b = Fernet(key)
    decoded_string = b.decrypt(inputstring)
    decoded_string = decoded_string.decode()
    return decoded_string


conn = sqlite3.connect("data.sqlite", check_same_thread=False)
c = conn.cursor()


def create_table():
    c.execute("CREATE TABLE IF NOT EXISTS DATA(TITLE, USERNAME, PASSWORD, URL, ID integer primary key autoincrement)")
    c.close


def generate_key_derivation(salt, master_password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key


def get_random_string(length):
    letters = string.ascii_lowercase
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str


randomkey = generate_key_derivation(salt, str(get_random_string(10))).decode("utf-8")
create_table()
c.execute('SELECT * FROM DATA')
rows = c.fetchall()
app = Flask(__name__)


@app.route('/')
def landing():
    return render_template("passwordlogin.html", error="hidden")


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    resp = make_response(render_template('passwordlogin.html', error="hidden"))
    resp.set_cookie('cookie', expires=0)  # remove cookie to logout
    return resp


@app.route('/password', methods=['POST', 'GET'])
def passwordpage():
    if request.cookies.get('cookie') is None and request.form.get("INPUT_ADMIN_PASSWORD") is not None:  # if password added, add cookie
        resp2 = make_response(render_template('validpassword.html'))
        resp2.set_cookie('cookie', str(encrypt(generate_key_derivation(salt, request.form.get("INPUT_ADMIN_PASSWORD")).decode("utf-8"), str(randomkey))), expires=datetime.datetime.now() + datetime.timedelta(days=30))
        return resp2
    elif request.cookies.get('cookie') is None:
        return render_template('passwordlogin.html', error="hidden")
        pass
    elif request.cookies.get('cookie') is not None:
        key = decrypt(request.cookies.get('cookie'), randomkey)
        TITLE = request.form.get("TITLE")
        URL = request.form.get("URL")
        USERNAME = str(request.form.get("USERNAME"))
        PASSWORD = str(request.form.get("PASSWORD"))
        REMOVEFROMDB = str(request.form.get("REMOVEFROMDB"))
        if USERNAME != "None":
            USERNAME = encrypt(request.form.get("USERNAME"), key)
        if PASSWORD != "None":
            PASSWORD = encrypt(request.form.get("PASSWORD"), key)
        REMOVE = request.form.get("REMOVE")
        if REMOVE == "True":
            c.execute("DELETE FROM DATA")
            conn.commit()
        if REMOVEFROMDB is not None and REMOVEFROMDB != "None":
            c.execute("DELETE FROM DATA  where ID=?", (REMOVEFROMDB,))
            conn.commit()
        c.execute('SELECT * FROM DATA')
        if PASSWORD != "None":
            c.execute('INSERT INTO DATA (TITLE, USERNAME, PASSWORD, URL) VALUES (?, ?, ?, ?)', (TITLE, USERNAME, PASSWORD, URL,))
            conn.commit()
        number = 0
        c.execute('SELECT * FROM DATA')
        rows = c.fetchall()
        for row in rows:
            try:
                username = decrypt(row[1], key)
                password = decrypt(row[2], key)
            except:
                resp = make_response(render_template('passwordlogin.html', error="visible"))
                resp.set_cookie('cookie', expires=0)  # remove cookie to logout
                return resp
            rows[number] = (row[0], username, password, row[3], row[4])
            number = number + 1
        return render_template('password.html', rows=rows)
    else:
        return render_template('passwordlogin.html', error="hidden")


app.run(host='0.0.0.0', debug=False, threaded=True)
