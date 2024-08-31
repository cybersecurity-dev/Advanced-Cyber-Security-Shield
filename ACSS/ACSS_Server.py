from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Welcome Malware Detector!..'

if __name__ == '__main__':
    HOST = environ.get('SERVER_HOST', 'localhost')
    try:
        PORT = int(environ.get('SERVER_PORT', '5000'))
    except ValueError:
        PORT = 5000
    app.run(HOST, PORT)