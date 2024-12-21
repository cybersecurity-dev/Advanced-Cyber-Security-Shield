"""
The flask application package.
"""

from flask import Flask
app = Flask(__name__)

UPLOAD_FOLDER = './dir_upload/'


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_PATH'] = 16 * 1000 * 1000 #16MB
app.config['SECRET_KEY'] = 'CSAI-MalwareDetector'

import ACSS.views
