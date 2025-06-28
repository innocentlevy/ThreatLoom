from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    last_login = db.Column(db.DateTime)

    def set_password(self, password):
        import logging
        logger = logging.getLogger('wireshark_siem')
        logger.info(f'Setting password for user {self.username}')
        self.password_hash = pbkdf2_sha256.hash(password)
        logger.info(f'Generated hash: {self.password_hash}')

    def check_password(self, password):
        import logging
        logger = logging.getLogger('wireshark_siem')
        logger.info(f'Checking password for user {self.username}')
        logger.info(f'Input password: {password}')
        logger.info(f'Stored hash: {self.password_hash}')
        result = pbkdf2_sha256.verify(password, self.password_hash)
        logger.info(f'Password check result: {result}')
        return result

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
