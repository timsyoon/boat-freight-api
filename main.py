import json
import requests
import urllib.parse

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, request, jsonify, _request_ctx_stack, redirect, render_template, session, url_for
from flask_cors import cross_origin
from functools import wraps
from google.cloud import datastore
from jose import jwt
from os import environ as env
from six.moves.urllib.parse import urlencode, quote_plus
from six.moves.urllib.request import urlopen
from werkzeug.exceptions import HTTPException

CLIENT_ID = '550PTu8Z9Cs3NxE9iJoCUw7ACKIf5nXR'
CLIENT_SECRET = 'YqlvzT8SUrRxd9qDgRfj9uox3TABZXX_iCOxrkD-zlVzxM7EalEWMQjE1hG_z4vn'
DOMAIN = 'cs493-spring22-yoonti.us.auth0.com'
ALGORITHMS = ["RS256"]
BOATS = 'boats'
LOADS = 'loads'
USERS = 'users'
APP_URL = 'http://localhost:8080'

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url='https://' + DOMAIN + '/.well-known/openid-configuration'
)

client = datastore.Client()

# This code is adapted from https://auth0.com/docs/quickstart/backend/python/01-authorization?_ga=2.46956069.349333901.1589042886-466012638.1589042885#create-the-jwt-validation-decorator

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code

@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)

# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload

@app.route("/")
def home():
    return render_template("home.html")

@app.route('/login', methods=['POST'])
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    id_token = token['id_token']
    sub = token['userinfo']['sub']
    session['id_token'] = id_token
    session['sub'] = sub
    # If the user entity does not exist in the database, add a new user entity
    query = client.query(kind=USERS)
    query.add_filter('user_id', '=', sub)
    results = list(query.fetch())
    if len(results) == 0:
        new_user = datastore.entity.Entity(key=client.key(USERS))
        new_user.update(
            {
                'user_id': sub,
                'boats': []
            }
        )
        client.put(new_user)

    return redirect(url_for('user_info'))

@app.route('/user-info', methods=['GET'])
def user_info():
    id_token = session['id_token']
    sub = session['sub']
    return render_template('userInfo.html', id_token=id_token, sub=sub)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + DOMAIN
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": CLIENT_ID,
            },
            quote_via=quote_plus,
        )
    )

@app.route('/users', methods=['GET'])
def users():
    if request.method == 'GET':
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406
        
        # Get all the users in the database
        query = client.query(kind=USERS)
        results = list(query.fetch())
        return jsonify(results), 200

@app.route('/boats', methods=['POST', 'GET'])
def boats():
    if request.method == 'POST':
        # Create a boat if the Authorization header contains a valid JWT

        content = request.get_json()
        
        # If the request is missing any of the required attributes
        if (not 'name' in content
        or not 'type' in content
        or not 'length' in content):
            res_body = {
                'Error': 'The request object is missing at least one of the required attributes'
            }
            return jsonify(res_body), 400
        
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406
        
        is_jwt_valid = False
        payload = None
        try:
            payload = verify_jwt(request)
            is_jwt_valid = True
        except AuthError:
            res_body = {
                'Error': 'The request object has a missing or invalid JWT'
            }
            return jsonify(res_body), 401
        except:
            res_body = {
                'Error': 'There was an error during JWT verification'
            }
            return jsonify(res_body), 401
        
        if is_jwt_valid:
            # Add a new boat to the database
            new_boat = datastore.entity.Entity(key=client.key(BOATS))
            new_boat.update(
                {
                    'name': content['name'],
                    'type': content['type'],
                    'length': content['length'],
                    'owner': payload['sub'],
                    'loads': []
                }
            )
            client.put(new_boat)
            
            # Update the associated user entity's 'boats' property
            query = client.query(kind=USERS)
            query.add_filter('user_id', '=', payload['sub'])
            results = list(query.fetch())
            for user in results:
                user['boats'].append(new_boat.key.id)
                user.update(
                    {
                        'user_id': payload['sub'],
                        'boats': user['boats']
                    }
                )
                client.put(user)

            res_body = {
                'id': new_boat.key.id,
                'name': content['name'],
                'type': content['type'],
                'length': content['length'],
                'owner': payload['sub'],
                'loads': [],
                'self': '{}/boats/{}'.format(APP_URL, new_boat.key.id)
            }
            return jsonify(res_body), 201

    elif request.method == 'GET':

        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406

        is_jwt_valid = False
        payload = None
        try:
            payload = verify_jwt(request)
            is_jwt_valid = True
        except AuthError:
            res_body = {
                'Error': 'The request object has a missing or invalid JWT'
            }
            return jsonify(res_body), 401
        except:
            res_body = {
                'Error': 'There was an error during JWT verification'
            }
            return jsonify(res_body), 401
        
        if is_jwt_valid:
            sub = payload['sub']
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            
            query = client.query(kind=BOATS)
            query.add_filter("owner", "=", sub)
            query_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = query_iterator.pages
            results = list(next(pages))
            if query_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            for e in results:
                e["id"] = e.key.id
                e["self"] = "{}/{}".format(request.base_url, e.key.id)
            output = {"boats": results}
            if next_url:
                output["next"] = next_url
            return jsonify(output), 200

    else:
        return jsonify(error='Method not recognized')

@app.route('/owners/<owner_id>/boats', methods=['GET'])
def boats_of_owner(owner_id):
    decoded_owner_id = urllib.parse.unquote(owner_id)
    
    query = client.query(kind=BOATS)
    query.add_filter("owner", "=", decoded_owner_id)
    query.add_filter("public", "=", True)
    results = list(query.fetch())
    
    for boat in results:
        boat["id"] = boat.key.id
    return jsonify(results), 200

@app.route('/boats/<boat_id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def specific_boat(boat_id):

    if request.method == "GET":
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406
        
        is_jwt_valid = False
        payload = None
        try:
            payload = verify_jwt(request)
            is_jwt_valid = True
            jwt_sub = payload['sub']
        except AuthError:
            res_body = {
                'Error': 'The request object has a missing or invalid JWT'
            }
            return jsonify(res_body), 401
        except:
            res_body = {
                'Error': 'There was an error during JWT verification'
            }
            return jsonify(res_body), 401

        if is_jwt_valid:
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)
            # If the boat belongs to someone else
            if boat['owner'] != jwt_sub:
                res_body = {
                    "Error": "The boat belongs to someone else"
                }
                return jsonify(res_body), 403
            res_body = {
                "id": boat.key.id,
                "name": boat["name"],
                "type": boat["type"],
                "length": boat["length"],
                "owner": boat["owner"],
                "loads": boat["loads"],
                "self": request.base_url
            }
            return jsonify(res_body), 200

    elif request.method == 'PATCH':
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406
        
        is_jwt_valid = False
        payload = None
        jwt_sub = None
        try:
            payload = verify_jwt(request)
            is_jwt_valid = True
            jwt_sub = payload['sub']
        except AuthError:
            res_body = {
                'Error': 'The request object has a missing or invalid JWT'
            }
            return jsonify(res_body), 401
        except:
            res_body = {
                'Error': 'There was an error during JWT verification'
            }
            return jsonify(res_body), 401
        
        if is_jwt_valid:
            content = request.get_json()
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)
            # If the boat belongs to someone else
            if boat['owner'] != jwt_sub:
                res_body = {
                    "Error": "The boat belongs to someone else"
                }
                return jsonify(res_body), 403
            boat.update({
                "name": content["name"] if "name" in content else boat["name"],
                "type": content["type"] if "type" in content else boat["type"],
                "length": content["length"] if "length" in content else boat["length"]
            })
            client.put(boat)
            res_body = {
                "id": boat.key.id,
                "name": boat["name"],
                "type": boat["type"],
                "length": boat["length"],
                "owner": boat["owner"],
                "loads": boat["loads"],
                "self": request.base_url
            }
            return jsonify(res_body), 200

    elif request.method == 'PUT':
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406
        
        is_jwt_valid = False
        payload = None
        jwt_sub = None
        try:
            payload = verify_jwt(request)
            is_jwt_valid = True
            jwt_sub = payload['sub']
        except AuthError:
            res_body = {
                'Error': 'The request object has a missing or invalid JWT'
            }
            return jsonify(res_body), 401
        except:
            res_body = {
                'Error': 'There was an error during JWT verification'
            }
            return jsonify(res_body), 401
        
        if is_jwt_valid:
            content = request.get_json()
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)
            # If the boat belongs to someone else
            if boat['owner'] != jwt_sub:
                res_body = {
                    "Error": "The boat belongs to someone else"
                }
                return jsonify(res_body), 403
            boat.update({
                "name": content["name"],
                "type": content["type"],
                "length": content["length"]
            })
            client.put(boat)
            res_body = {
                "id": boat.key.id,
                "name": boat["name"],
                "type": boat["type"],
                "length": boat["length"],
                "owner": boat["owner"],
                "loads": boat["loads"],
                "self": request.base_url
            }
            return jsonify(res_body), 200

    elif request.method == 'DELETE':
        is_jwt_valid = False
        jwt_sub = None
        try:
            payload = verify_jwt(request)
            is_jwt_valid = True
            jwt_sub = payload['sub']
        except AuthError:
            res_body = {
                'Error': 'The request object has a missing or invalid JWT'
            }
            return jsonify(res_body), 401
        except:
            res_body = {
                'Error': 'There was an error during JWT verification'
            }
            return jsonify(res_body), 401
        
        if is_jwt_valid:
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)

            # If the boat is owned by someone else, return 403 status code
            if boat['owner'] != jwt_sub:
                res_body = {
                    "Error": "The boat belongs to someone else"
                }
                return jsonify(res_body), 403
            
            client.delete(boat_key)
            res_body = {}
            return jsonify(res_body), 204

# Generate a JWT from the Auth0 domain and return it
# Request: JSON body with 2 properties with "username" and "password"
#       of a user registered with this Auth0 domain
# Response: JSON with the JWT as the value of the property id_token
@app.route('/manual-login', methods=['POST'])
def manual_login_user():
    content = request.get_json()
    username = content["username"]
    password = content["password"]
    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = { 'content-type': 'application/json' }
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)
    return r.text, 200, {'Content-Type':'application/json'}

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
