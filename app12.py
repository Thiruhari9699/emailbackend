from flask import Flask,request ,jsonify
import uuid
from werkzeug.security import generate_password_hash,check_password_hash
import pymongo
import ssl
import hashlib
import jwt
import datetime
from functools import wraps
from model.mongodb import UserModel
app=Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token=None
        if 'x-access-token' in request.headers:
            token=request.headers.get('x-access-token')
        if not token:
            return 'token missing'
        data=jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256'])
        print(data)
        try:
            data=jwt.decode(token,app.config['SECRET_KEY'],algorithms=['HS256'])
            data_key=data['public_id']
            client=pymongo.MongoClient('mongodb+srv://ramnath1:ramnath1@cluster0.agxnajm.mongodb.net/',ssl=True,ssl_cert_reqs=ssl.CERT_NONE)
            db = client['user_account']
            collection = db['user_account']
            print(data_key)
            
            query = {
            "public_id": data_key
            }
            current_user = collection.find_one(query)
            print(current_user)
        except:
            return 'Token invalid'
        return f(current_user,*args,**kwargs)
    return decorated

@app.route('/user',methods=['GET'])
@token_required
def get_all_users(current_user):
    user_model = UserModel() 
    all_documents=(user_model.find_all())
    for document in all_documents:
        print(document)
    return ''


@app.route('/user1',methods=['GET'])
# @token_required
def get_one_user():
    user_model = UserModel() 
    name = request.args.get('name')
    password = request.args.get('password')
    hashed_password=hashlib.sha512(password.encode())
    hashed_pass_hexi=hashed_password.hexdigest()
    matching_documents=(user_model.login(name))
    print(matching_documents['password'])
    if(hashed_pass_hexi==matching_documents['password']):
        token=jwt.encode({'public_id':matching_documents['public_id'],'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])
        return jsonify({'token': token})    
    else:
        return 'password invalid'

@app.route('/register',methods=['POST'])
# @token_required
def create_user():
    user_model = UserModel() 
    data=request.get_json()
    hashed_password=hashlib.sha512(data['password'].encode())
    print(hashed_password)
    
    data = {
        'name': data['name'],
        'password': hashed_password.hexdigest(),
        'public_id':str(uuid.uuid4()),
        'admin':False
    }
    user_model.insert_user(data)
    return 'User Created'

if __name__=='__main__':
    app.run(debug=True)