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

@app.route('/login')
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

    # If the user does not exist in the database, add a new user entity
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
        
        # Create a boat if the Authorization header contains a valid JWT
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
            obj_to_add = {
                'id': new_boat.key.id,
                'self': '{}/boats/{}'.format(APP_URL, new_boat.key.id)
            }
            query = client.query(kind=USERS)
            query.add_filter('user_id', '=', payload['sub'])
            results = list(query.fetch())
            for user in results:
                user['boats'].append(obj_to_add)
                client.put(user)

            new_boat['id'] = new_boat.key.id
            new_boat['self'] = '{}/boats/{}'.format(APP_URL, new_boat.key.id)

            return jsonify(new_boat), 201

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
            
            # Get total number of boats (owned by the user) in the collection
            second_query = client.query(kind=BOATS)
            second_query.add_filter("owner", "=", sub)
            second_query.keys_only()
            results = list(query.fetch())
            total_number_of_boats = len(results)
            output["total_number_of_boats"] = total_number_of_boats

            return jsonify(output), 200

    else:
        return jsonify(error='Method not recognized')

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
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406
            
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

            # If the boat does not exist
            if boat is None:
                res_body = { "Error": "No boat with this boat_id exists" }
                return jsonify(res_body), 404

            # If the boat is owned by someone else, return 403 status code
            if boat['owner'] != jwt_sub:
                res_body = {
                    "Error": "The boat belongs to someone else"
                }
                return jsonify(res_body), 403
            
            # Update the loads that are on the boat
            for load_obj in boat["loads"]:
                load_key = client.key(LOADS, load_obj["id"])
                load = client.get(key=load_key)
                load["carrier"] = None
                client.put(load)

            # Update the user that owns this boat
            query = client.query(kind=USERS)
            query.add_filter("user_id", "=", jwt_sub)
            results = list(query.fetch())
            for user in results:
                for boat_obj in user["boats"]:
                    if boat_obj["id"] == boat.key.id:
                        user["boats"].remove(boat_obj)
                        client.put(user)

            # Delete the boat
            client.delete(boat_key)

            return jsonify({}), 204

@app.route('/loads', methods=['POST', 'GET', 'DELETE'])
def loads():
    if request.method == "POST":
        content = request.get_json()
        
        # If the request is missing any of the required attributes
        if (not "volume" in content) or (not "item" in content) or (not "creation_date" in content):
            res_body = {
                "Error": "The request object is missing at least one of the required attributes"
            }
            return jsonify(res_body), 400

        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406

        new_load = datastore.entity.Entity(key=client.key(LOADS))
        new_load.update(
            {
                "volume": content["volume"],
                "item": content["item"],
                "creation_date": content["creation_date"],
                "carrier": None
            }
        )
        client.put(new_load)
        res_body = {
            "id": new_load.key.id,
            "volume": new_load["volume"],
            "item": new_load["item"],
            "creation_date": new_load["creation_date"],
            "carrier": new_load["carrier"],
            "self": "{}/{}".format(request.base_url, new_load.key.id)
        }
        return jsonify(res_body), 201
    
    elif request.method == 'GET':

        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406
        
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        
        query = client.query(kind=LOADS)
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
        output = {"loads": results}
        if next_url:
            output["next"] = next_url
        
        # Get total number of loads in the collection
        second_query = client.query(kind=LOADS)
        second_query.keys_only()
        results = list(query.fetch())
        total_number_of_loads = len(results)
        output["total_number_of_loads"] = total_number_of_loads

        return jsonify(output), 200

    elif request.method == 'DELETE':
        return "", 405

@app.route('/loads/<load_id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def specific_load(load_id):
    if request.method == "GET":
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406
        
        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)
        load["id"] = load.key.id
        load["self"] = request.base_url

        return jsonify(load), 200
    
    elif request.method == 'PATCH':
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406
        
        content = request.get_json()
        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)
        load.update({
            "volume": content["volume"] if "volume" in content else load["volume"],
            "item": content["item"] if "item" in content else load["item"],
            "creation_date": content["creation_date"] if "creation_date" in content else load["creation_date"]
        })
        client.put(load)
        
        load["id"] = load.key.id
        load["self"] = request.base_url

        return jsonify(load), 200
    
    elif request.method == 'PUT':
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406
        
        content = request.get_json()
        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)
        load.update({
            "volume": content["volume"],
            "item": content["item"],
            "creation_date": content["creation_date"]
        })
        client.put(load)
        
        load["id"] = load.key.id
        load["self"] = request.base_url

        return jsonify(load), 200
    
    elif request.method == "DELETE":
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406

        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)

        # If the load does not exist
        if load is None:
            res_body = { "Error": "No load with this load_id exists" }
            return jsonify(res_body), 404

        # If the load does not have a carrier, simply delete the load
        if load["carrier"] is None:
            client.delete(load_key)
            return jsonify({}), 204

        # Update the boat carrying the load
        boat_id = load["carrier"]["id"]
        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)
        target_load = None  
        for load_obj in boat["loads"]:
            if load_obj["id"] == load.key.id:
                target_load = load_obj
        if target_load is not None:
            boat["loads"].remove(target_load)
            client.put(boat)

        # Delete the load
        client.delete(load_key)

        return jsonify({}), 204

@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def boats_loads(boat_id, load_id):
    if request.method == "PUT":
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406

        boat_key = client.key(BOATS, int(boat_id))
        load_key = client.key(LOADS, int(load_id))
        boat = client.get(key=boat_key)
        load = client.get(key=load_key)
        
        # Check whether both the boat and load exist
        if boat is None or load is None:
            res_body = { "Error": "The specified boat and/or load does not exist" }
            return jsonify(res_body), 404

        # If the load has already been assigned to another boat
        if load["carrier"] is not None:
            res_body = { "Error": "The load is already loaded on another boat" }
            return jsonify(res_body), 403

        # Add the load to the boat's loads only if the boat does not have that load
        does_boat_have_load = False
        for load_obj in boat["loads"]:
            if load_obj["id"] == load.key.id:
                does_boat_have_load = True
        if not does_boat_have_load:
            # Update the boat
            new_load_obj = {
                "id": load.key.id,
                "self": request.host_url + "loads/{}".format(load.key.id)
            }
            boat["loads"].append(new_load_obj)
            client.put(boat)

            # Update the load
            carrier_obj = {
                "id": boat.key.id,
                "self": request.host_url + "boats/{}".format(boat.key.id)
            }
            load["carrier"] = carrier_obj
            client.put(load)

            return jsonify({}), 204

    elif request.method == "DELETE":
        # If the request does not have an Accept header or the Accept header does not include 'application/json'
        if 'Accept' not in request.headers or request.headers['Accept'] != 'application/json':
            res_body = {
                'Error': 'The request object does not have an Accept header that includes \'application/json\''
            }
            return jsonify(res_body), 406

        boat_key = client.key(BOATS, int(boat_id))
        load_key = client.key(LOADS, int(load_id))
        boat = client.get(key=boat_key)
        load = client.get(key=load_key)

        # Check whether both the boat and load exist
        if boat is None or load is None:
            res_body = { "Error": "The specified boat and/or load does not exist" }
            return jsonify(res_body), 404

        # If the boat does not have the load
        does_boat_have_load = False
        target_load = None
        for load_obj in boat["loads"]:
            if load_obj["id"] == load.key.id:
                does_boat_have_load = True
                target_load = load_obj
        if not does_boat_have_load:
            res_body = { "Error": "No boat with this boat_id is loaded with the load with this load_id" }
            return jsonify(res_body), 404

        # Remove the load from the boat
        boat["loads"].remove(target_load)
        client.put(boat)

        # Reset the carrier of the load
        load["carrier"] = None
        client.put(load)

        return jsonify({}), 204

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
