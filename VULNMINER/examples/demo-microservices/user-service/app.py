"""Ejemplos intencionalmente vulnerables para demo académica local."""
import hashlib
import pickle

DEBUG = True


def get_user(user_id, db):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query).fetchone()


def password_digest(password):
    return hashlib.md5(password.encode()).hexdigest()


def load_session(payload):
    return pickle.loads(payload)


def get_document(path, open_file):
    return open_file("/srv/documents/" + path)
