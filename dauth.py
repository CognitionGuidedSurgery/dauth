import StringIO
import uuid, json
import time
from flask import Flask, request, json_available
from flask.ext.restful import Resource, Api
import base64
from flask.wrappers import Response

import rsa

app = Flask(__name__)

USER_DB = {
    "weigl": 'abc'
}
import os.path

def read_keys():
    def readcontents(filename):
        with open(filename) as fp:
            c =  fp.read()
            return c

    priv = rsa.PrivateKey.load_pkcs1(readcontents("key.private"))
    pub = rsa.PublicKey.load_pkcs1(readcontents("key.public"))

    return pub, priv


pub, priv = read_keys()


def rewrite_scopes(scopes):
    return scopes


def check_user(username, password, scope):
    try:
        return USER_DB[username] == password
    except KeyError:
        return False


def _map_as_unique_str(map):
    io = StringIO.StringIO()
    io.write("^")
    for k,v in map.iteritems():
        io.write(k)
        io.write("#")
        io.write(v)
        io.write("##")
    io.write("$")
    return io.getvalue()

def sign_dictionary(map):
    host = request.host
    content = _map_as_unique_str(map)
    signature = rsa.sign(content, priv, 'SHA-512')

    msg = {
        'grant':map,
        'from': host,
        'signature': base64.b64encode(signature)
    }

    print msg

    return msg

def check_authorization(data):
    map = data['grant']
    signatureref = base64.b64decode(data['signature'])

    content = _map_as_unique_str(map)
    return rsa.verify(content, signatureref, pub)


class Grant(Resource):
    def get(self):
        print request.method, request.path, "HTTP/1.1"
        print request.headers

        username = request.values['username']
        password = request.values['password']
        duration = int(request.values.get('duration',600))
        scope   = request.values.get('scope', [])
        ipaddr = request.values.get('ipaddr', request.remote_addr)

        scope = rewrite_scopes(scope)

        if check_user(username, password, scope):
            gid = str(uuid.uuid4())
            endtime = int(time.time()) + duration

            return sign_dictionary(
                {
                    'username': username,
                    'ipaddr'  : ipaddr,
                    'scope'   : scope,
                    'grantid' : gid,
                    'validuntil': endtime
                }
            )
        else:
            return Response("Authorization not granted", 506)

class Auth(Resource):
    def get(self):
        print request.headers
        try:
            auth_txt = request.headers['Authorization']
        except:
            auth_txt = request.cookies['Authorization']
        try:
            auth_data = json.loads(auth_txt)
        except:
            return {'message':"error, no json"}

        if check_authorization(auth_data):
            return Response("ok", status=200)
        else:
            return Response("error", status=500)


class ScopeSystem(object):
    def __init__(self):
        self.scopes = {}


    def clean(self):
        curtime = time.time()
        self.scopes = dict(filter(lambda a: a[1] > curtime, self.scopes.iteritems()))

SCOPES = ScopeSystem()

class Scopes(Resource):
    def put(self):
        SCOPES.clean()
        data = request.json
        curtime = time.time()
        for s in data:
            SCOPES.scopes[s] = curtime + 60 * 60 * 24 # 1 d TTL

        return SCOPES.scopes

    def get(self):
        return SCOPES.scopes




api = Api(app)
api.add_resource(Grant, "/grant")
api.add_resource(Auth, "/auth")

if __name__ == '__main__':
    app.run(debug=True)
