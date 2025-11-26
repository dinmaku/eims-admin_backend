#__init__.py
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
import os
from .logging_config import setup_logging
from .routes import init_routes

def create_app():
    app = Flask(__name__)

    CORS(app,
         origins=[
             "http://localhost:5173",
             "https://redcarpetadmin.vercel.app"
         ],
         methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
         allow_headers=["Content-Type", "Authorization"],
         supports_credentials=True
    )

    setup_logging(app)

    app.config['JWT_SECRET_KEY'] = os.getenv('eims', 'fallback_jwt_secret')
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = False

    jwt = JWTManager(app)

    init_routes(app)

    return app