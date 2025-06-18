from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def rce():
    cmd = request.args.get('cmd')
    return str(eval(cmd))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
