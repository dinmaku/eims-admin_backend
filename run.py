#run.py
from app import create_app
import logging
from logging.handlers import RotatingFileHandler
import os

# Create the Flask application instance
app = create_app()

# Configure logging
if not app.debug:
    # Ensure the logs directory exists
    if not os.path.exists('logs'):
        os.mkdir('logs')
        
    # Set up file handler
    file_handler = RotatingFileHandler(
        'logs/app.log', 
        maxBytes=10240, 
        backupCount=10
    )
    
    # Set logging format
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    
    # Set logging level
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

if __name__ == '__main__':
    app.run(debug=True)