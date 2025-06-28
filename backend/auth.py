from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime
from models import User, db

def admin_required():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            return fn(*args, **kwargs)
        return decorator
    return wrapper

def register_user(username, password, is_admin=False):
    if User.query.filter_by(username=username).first():
        return False, "Username already exists"
    
    user = User(username=username, is_admin=is_admin)
    user.set_password(password)
    
    db.session.add(user)
    db.session.commit()
    return True, "User created successfully"

def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return None
    
    user.last_login = datetime.utcnow()
    db.session.commit()
    return user
