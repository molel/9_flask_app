import binascii
import hashlib
import json
import os
from datetime import datetime
from hashlib import sha256

from flask import Flask, request, abort, jsonify

from settings import *

app = Flask(__name__)


def load():
    with open(AUTH, "r", encoding=ENCODING) as file:
        return list(json.load(file))


def dump(auth):
    with open(AUTH, "w", encoding=ENCODING) as file:
        file.write(json.dumps(auth))


def checkLogin(login):
    global users
    return login in [user["login"] for user in users]


def makeResponse(result=True, description=""):
    return {"result": result,
            "description": description}


def hashPassword(password, salt: str = None):
    if salt:
        salt = salt.encode("ascii")
        newPassword = hashlib.pbkdf2_hmac('sha512', password.encode(ENCODING), salt, 80000)
        newPassword = binascii.hexlify(newPassword)
        return (salt + newPassword).decode('ascii')
    else:
        salt = sha256(os.urandom(70)).hexdigest().encode('ascii')
        newPassword = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 80000)
        newPassword = binascii.hexlify(newPassword)
        return (salt + newPassword).decode('ascii'), salt.decode('ascii')


def regUser(user):
    # try:
    global users
    password, salt = hashPassword(user["password"])
    newUser = {"login": user["login"],
               "password": password,
               "salt": salt,
               "date": datetime.now().isoformat()}
    users.append(newUser)
    dump(users)
    return makeResponse(True, "user was registered in the system"), 201


# except:
#     abort(400)


def checkPassword(user):
    global users
    login = user["login"]
    password = user["password"]
    try:
        checkedUser = list(filter(lambda x: x["login"] == login, users))[0]
        checkedPassword = checkedUser["password"]
        checkedSalt = checkedUser["salt"]
        newPassword = hashPassword(password, checkedSalt)
        return checkedPassword == newPassword
    except IndexError:
        return False


@app.route('/user/reg', methods=['POST'])
def regUsers():
    user = json.loads(request.get_data())
    if checkLogin(user["login"]):
        return makeResponse(False, "this login was already registered")
    else:
        return regUser(user)


@app.route('/users/<string:username>', methods=['GET'])
def getUser(username):
    try:
        global users
        user = list(filter(lambda x: x["login"] == username, users))[0]
        return jsonify({users: user})
    except IndexError:
        abort(404)


@app.route('/user', methods=["GET", "POST"])
def authUser():
    global users
    match request.method:
        case "GET":
            return jsonify({"users": users})
        case "POST":
            match checkLogin(json.loads(request.get_data())["login"]), checkPassword(json.loads(request.get_data())):
                case True, True:
                    return makeResponse(True, "authentication was successful")
                case True, False:
                    return makeResponse(False, "incorrect password")
                case False, _:
                    return makeResponse(True, "incorrect username")


@app.route('/')
def user_data():
    return 'user registration system'


users = load()

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
