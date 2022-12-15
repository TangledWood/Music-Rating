from flask import Flask, request, jsonify, make_response
from pymongo import MongoClient
from bson import ObjectId
import string
import jwt
import datetime
from functools import wraps
import bcrypt 
from flask_cors import CORS

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
            
app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = 'cm282001'

client = MongoClient("mongodb://127.0.0.1:27017")
db = client.bizDB
businesses = db.biz
users = db.users
blacklist = db.blacklist

@app.route("/api/v1.0/businesses", methods=["GET"])
def show_all_businesses():
    page_num, page_size = 1, 10
    if request.args.get("pn"):
        page_num = int(request.args.get('pn'))
        
    if request.args.get("ps"):
        page_size = int(request.args.get('ps'))
        
    page_start = (page_size * (page_num - 1))
    
    data_to_return = []
    for business in businesses.find().skip(page_start).limit(page_size):
        business["_id"] = str(business["_id"])
        for review in business["reviews"]:
            review["_id"] = str(review["_id"])
        data_to_return.append(business)
        
    return make_response( jsonify(data_to_return), 200)

@app.route("/api/v1.0/businesses/<string:id>", methods = ["GET"])
def show_one_business(id):
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(jsonify({"error" : "Invalid Business ID"}), 404)
    business = businesses.find_one({"_id": ObjectId(id)}) 
    if business is not None: 
        business["_id"] = str(business["_id"]) 
        for review in business["reviews"]: 
            review["_id"] = str(review["_id"]) 
        return make_response(jsonify( [business] ), 200) 
    else:
        return make_response(jsonify({"error" : "Invalid Business ID"}), 404) #bad response

#creating POST endpoint for our REST api
@app.route("/api/v1.0/businesses/", methods = ["POST"])
@jwt_required
def add_new_business():
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(jsonify({"error" : "Invalid Business ID"}), 404)
    
    if "name" in request.form and "town"  in request.form and "rating" in request.form: #estalbishing data fields
        #new_business creates schema for adding a new business object
        new_business = {
            "name": request.form["name"],
            "town": request.form["town"],
            "rating": request.form["rating"],
            "reviews": []
        }
        #DB command to add one new business object
        new_business_id = businesses.insert_one(new_business)
        new_business_link = "http://127.0.0.1:5000/api/v1.0/businesses/" + \
            str(new_business_id.inserted_id)
        return make_response( jsonify({"url" : new_business_link}), 201)
    else:
        return make_response(jsonify({"error" : "Missing form data"}), 404)
    
@app.route("/api/v1.0/businesses/<string:id>", methods = ["PUT"])
@jwt_required
def edit_business(id):
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(jsonify({"error" : "Invalid Business ID"}), 404)
    
    if "name" in request.form and "town"  in request.form and "rating" in request.form:
        result = businesses.update_one(
            #almost the same as adding a new business except business ID is required in order to update form data
            {"_id": ObjectId(id) }, 
            {
                "$set" : {
                    "name" : request.form["name"],
                    "town": request.form["town"],
                    "rating": request.form["rating"],
                }
            }
        )
        #if the business ID was correct
        if result.matched_count ==1:
            edit_business_link = "http://127.0.0.1:5000/api/v1.0/businesses/" + id
            return make_response( jsonify({ "url": edit_business_link }), 200)
    
        else:
            return make_response(jsonify({"error" : "Invalid business ID"}), 404)
    else:
        return make_response(jsonify({"error" : "Missing form data"}), 404)
    
@app.route("/api/v1.0/businesses/<string:id>", methods = ["DELETE"])
@jwt_required
@admin_required
def delete_business(id):
    if len(id) != 24 or not all(c in string.hexdigits for c in id):
        return make_response(jsonify({"error" : "Invalid Business ID"}), 404)
    #DB commant to delete one object using the object ID
    result = businesses.delete_one({"_id": ObjectId(id)})
    if result.deleted_count == 1:
        return make_response( jsonify({}), 204)
    else:
        return make_response(jsonify({"error" : "Invalid business ID"}), 404)
    
@app.route("/api/v1.0/businesses/<string:id>/reviews", methods = ["POST"])
def add_new_review(id):
    #new_review defines schema used for review form data
    new_review = {
        "_id": ObjectId(),
        "username" : request.form["username"],
        "comment": request.form["comment"],
        "stars": request.form["stars"]
    }
    #We need to update the buisness object with the new review so we pass the business ID and update the review field with our new review
    businesses.update_one(
        {"_id" : ObjectId(id)},
        {
            '$push' : {"reviews" : new_review}
        }
    )
    new_review_link = "http://127.0.0.1:5000/api/v1.0/businesses/" + id + \
        "/reviews/" + str(new_review["_id"])
    return make_response(jsonify({"url": new_review_link}), 201)

@app.route("/api/v1.0/businesses/<string:id>/reviews", methods = ["GET"])
def fetch_all_reviews(id):
    #definding our returned data (reviews) as a list
    data_to_return = []
    business = businesses.find_one(
        #we find one review via the business ID and then project the review without its ID
        {"_id" : ObjectId(id)}, {"reviews" : 1, "_id": 0}
    )
    for review in business["reviews"]:
        review["_id"] = str(review["_id"])
        data_to_return.append(review)
    return make_response( jsonify( data_to_return ), 200)

@app.route("/api/v1.0/businesses/<string:id>/reviews/<string:review_id>", methods = ["GET"])
@jwt_required
def fetch_one_review(id, review_id):
    business = businesses.find_one(
        { "reviews._id" : ObjectId(review_id) },
        {"_id" : 0, "reviews.$" : 1}
    )
    if business is None:
        return make_response(jsonify({"error" : "Invalid Business or Review ID"}), 404)
    else:
        business["reviews"][0]["_id"] = str(business["reviews"][0]["_id"])
        return make_response( jsonify(business["reviews"][0]), 200)
    
@app.route("/api/v1.0/businesses/<string:id>/reviews/<string:review_id>", methods = ["PUT"])
@jwt_required
def edit_review(id, review_id):
    #using $ positonal operator again as it poitns to the single review that matches the ID given, so we onyl update that one review
    edited_review = {
        "reviews.$.username" : request.form["username"],
        "reviews.$.comment" : request.form["comment"],
        "reviews.$.stars" : request.form["stars"]
    }
    #We update our business object by setting the review returned by the search as the new review (edited review)
    businesses.update_one(
        {"reviews._id": ObjectId(review_id)},
        {"$set": edited_review}
    )
    edit_review_url = "http://127.0.0.1:5000/api/v1.0/businesses/" + id + \
        "/reviews/" + review_id
    return make_response( jsonify({"url" : edit_review_url}), 200)

@app.route("/api/v1.0/businesses/<string:id>/reviews/<string:review_id>", methods = ["DELETE"])
@jwt_required
@admin_required
def delete_review(id, review_id):
    #we again update one business using the same ID found in the url
    #to pull from reviews collection the review with the corresponding ID found in the url
    businesses.update_one(
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
    
# Figure out how to validate reviews for extra marks 