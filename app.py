from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
from bson import ObjectId
import string
import jwt
import datetime
from functools import wraps
import bcrypt 
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'cm282001'

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.musiciansDB
musicians = db.musicians
users = db.users
blacklist = db.blacklist

def jwt_required(func):
    @wraps(func)
    def jwt_required_wrapper(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message': 'Token is invalid'}), 401
        
        bl_token = blacklist.find_one({"token" : token})
        if bl_token is not None:
            return make_response(jsonify({'message': 'Token has been cancelled'}), 401)
        return func(*args, **kwargs)
    
    return jwt_required_wrapper

def admin_required(func):
    @wraps(func)
    def admin_required_wrapper(*args, **kwargs):
        token = request.headers['x-access-token']
        data = jwt.decode(token, app.config['SECRET_KEY'])
        if data["admin"]:
            return func(*args, **kwargs)
        else:
            return make_response(jsonify({'message': 'Admin access is required'}), 401)
    return admin_required_wrapper

@app.route("/api/v1.0/musicians", methods=["GET"])
def show_all_musicians():
    page_num, page_size = 1, 10
    if request.args.get("pn"):
        page_num = int(request.args.get('pn'))
        
    if request.args.get("ps"):
        page_size = int(request.args.get('ps'))
        
    page_start = (page_size * (page_num - 1))
    
    data_to_return = []
    for musician in musicians.find().skip(page_start).limit(page_size):
        musician["_id"] = str(musician["_id"])
        for review in musician["reviews"]:
            review["_id"] = str(review["_id"])
        data_to_return.append(musician)
        
    return make_response( jsonify(data_to_return), 200)

@app.route("/api/v1.0/musicians/<string:id>", methods = ["GET"])
def show_one_musician(id):
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(jsonify({"error" : "Invalid musician ID"}), 404)
    musician = musicians.find_one({"_id": ObjectId(id)}) 
    if musician is not None: 
        musician["_id"] = str(musician["_id"]) 
        for review in musician["reviews"]: 
            review["_id"] = str(review["_id"]) 
        return make_response(jsonify( [musician] ), 200) 
    else:
        return make_response(jsonify({"error" : "Invalid musician ID"}), 404) 

@app.route("/api/v1.0/musicians/", methods = ["POST"])
def add_new_musician():
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(jsonify({"error" : "Invalid musician ID"}), 404)
    
    if "name" in request.form and "town"  in request.form and "rating" in request.form: 
        new_musician = {
            "name": request.form["name"],
            "town": request.form["town"],
            "rating": request.form["rating"],
            "reviews": []
        }
        new_musician_id = musicians.insert_one(new_musician)
        new_musician_link = "http://127.0.0.1:5000/api/v1.0/musicians/" + \
            str(new_musician_id.inserted_id)
        return make_response( jsonify({"url" : new_musician_link}), 201)
    else:
        return make_response(jsonify({"error" : "Missing form data"}), 404)
    
@app.route("/api/v1.0/musicians/<string:id>", methods = ["PUT"])
def edit_musician(id):
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(jsonify({"error" : "Invalid musician ID"}), 404)
    
    if "name" in request.form and "town"  in request.form and "rating" in request.form:
        result = musicians.update_one(
            {"_id": ObjectId(id) }, 
            {
                "$set" : {
                    "name" : request.form["name"],
                    "town": request.form["town"],
                    "rating": request.form["rating"],
                }
            }
        )
        if result.matched_count ==1:
            edit_musician_link = "http://127.0.0.1:5000/api/v1.0/musicians/" + id
            return make_response( jsonify({ "url": edit_musician_link }), 200)
    
        else:
            return make_response(jsonify({"error" : "Invalid musician ID"}), 404)
    else:
        return make_response(jsonify({"error" : "Missing form data"}), 404)
    
@app.route("/api/v1.0/musicians/<string:id>", methods = ["DELETE"])
def delete_musician(id):
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(jsonify({"error" : "Invalid musician ID"}), 404)
    result = musicians.delete_one({"_id": ObjectId(id)})
    if result.deleted_count == 1:
        return make_response( jsonify({}), 204)
    else:
        return make_response(jsonify({"error" : "Invalid musician ID"}), 404)
    
@app.route("/api/v1.0/musicians/<string:id>/reviews", methods = ["POST"])
def add_new_review(id):
    new_review = {
        "_id": ObjectId(),
        "username" : request.form["username"],
        "comment": request.form["comment"],
        "stars": request.form["stars"]
    }
    musicians.update_one(
        {"_id" : ObjectId(id)},
        {
            '$push' : {"reviews" : new_review}
        }
    )
    new_review_link = "http://127.0.0.1:5000/api/v1.0/musicians/" + id + \
        "/reviews/" + str(new_review["_id"])
    return make_response(jsonify({"url": new_review_link}), 201)

@app.route("/api/v1.0/musicians/<string:id>/reviews", methods = ["GET"])
def fetch_all_reviews(id):
    data_to_return = []
    musician = musicians.find_one(
        {"_id" : ObjectId(id)}, {"reviews" : 1, "_id": 0}
    )
    for review in musician["reviews"]:
        review["_id"] = str(review["_id"])
        data_to_return.append(review)
    return make_response( jsonify( data_to_return ), 200)

@app.route("/api/v1.0/musicians/<string:id>/reviews/<string:review_id>", methods = ["GET"])
def fetch_one_review(id, review_id):
    musician = musicians.find_one(
        { "reviews._id" : ObjectId(review_id) },
        {"_id" : 0, "reviews.$" : 1}
    )
    if musician is None:
        return make_response(jsonify({"error" : "Invalid musician or Review ID"}), 404)
    else:
        musician["reviews"][0]["_id"] = str(musician["reviews"][0]["_id"])
        return make_response( jsonify(musician["reviews"][0]), 200)
    
@app.route("/api/v1.0/musicians/<string:id>/reviews/<string:review_id>", methods = ["PUT"])
def edit_review(id, review_id):
    edited_review = {
        "reviews.$.username" : request.form["username"],
        "reviews.$.comment" : request.form["comment"],
        "reviews.$.stars" : request.form["stars"]
    }
    musicians.update_one(
        {"reviews._id": ObjectId(review_id)},
        {"$set": edited_review}
    )
    edit_review_url = "http://127.0.0.1:5000/api/v1.0/musicians/" + id + \
        "/reviews/" + review_id
    return make_response( jsonify({"url" : edit_review_url}), 200)

@app.route("/api/v1.0/musicians/<string:id>/reviews/<string:review_id>", methods = ["DELETE"])
def delete_review(id, review_id):
    musicians.update_one(
        {"_id" : ObjectId(id)},
        {"$pull" : {"reviews" : { "_id" : ObjectId(review_id) } } }
    )
    return make_response( jsonify( {} ), 204)

@app.route("/api/v1.0/login", methods = ["GET"])
def login():
    auth = request.authorization
    if auth:
        user = users.find_one({"username" : auth.username})
        if user is not None:
            if bcrypt.checkpw(bytes(auth.password, 'UTF-8'), user["password"]):      
                token = jwt.encode({
                    'user' : auth.username,
                    'admin' : user["admin"],
                    'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
                }, app.config['SECRET_KEY'])
                return make_response(jsonify({'token' : token.decode('UTF-8') }), 200)
            else:
                return make_response(jsonify({'message' : 'Bad Password'}), 401)
        else:
            return make_response(jsonify({'message' : 'Bad Username'}), 401)
        
    return make_response(jsonify({'message' : 'Authentication is required'}), 401)

@app.route("/api/v1.0/logout", methods=["GET"])
@jwt_required
def logout():
    token = request.headers['x-access-token']
    blacklist.insert_one({"token": token})
    return make_response(jsonify({'message' : 'Logout Successful!'}), 200)


if __name__ == "__main__":
    app.run(debug = True)