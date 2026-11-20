import os
from flask import Flask, request

app = Flask(__name__)

@app.route("/")
def home():
    return "ClipFlow OAuth handler is online."

@app.route("/callback")
def callback():
    error = request.args.get("error")
    if error:
        return "Authorization failed.", 400

    code = request.args.get("code")
    if code:
        return "Authorization received. You can close this page."
    return "No authorization code received.", 400

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
