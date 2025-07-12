# AI-Based-Web-Threat-Detection
 
from flask import Flask, render_template_string, request
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import pandas as pd
import joblib
import os

app = Flask(__name__)

# Step 1: Load or Train Model
DATA_FILE = "web_requests.csv"
MODEL_FILE = "model.pkl"
VEC_FILE = "vectorizer.pkl"

def train_model():
    # Sample dataset
    data = {
        "url": [
            "/login?user=admin",
            "/search?q=banana",
            "/home"
        ],
        "payload": [
            "' OR '1'='1",
            "<script>alert('xss')</script>",
            ""
        ],
        "label": ["SQLi", "XSS", "benign"]
    }

    df = pd.DataFrame(data)
    df["label"] = df["label"].map({"benign": 0, "SQLi": 1, "XSS": 2})

    vectorizer = TfidfVectorizer(max_features=100)
    X = vectorizer.fit_transform(df["url"] + " " + df["payload"]).toarray()
    y = df["label"]

    clf = RandomForestClassifier()
    clf.fit(X, y)

    joblib.dump(clf, MODEL_FILE)
    joblib.dump(vectorizer, VEC_FILE)

if not os.path.exists(MODEL_FILE) or not os.path.exists(VEC_FILE):
    train_model()

model = joblib.load(MODEL_FILE)
vectorizer = joblib.load(VEC_FILE)

def predict_threat(url, payload):
    text = url + " " + payload
    X = vectorizer.transform([text]).toarray()
    pred = model.predict(X)[0]
    return ["Benign ✅", "SQL Injection 🚨", "XSS Attack ⚠"][pred]

# Step 2: HTML UI
HTML_TEMPLATE = '''
<!doctype html>
<title>Threat Detector</title>
<h2>Web Request Threat Detection</h2>
<form method="post">
    URL: <input type="text" name="url" required><br><br>
    Payload:<br>
    <textarea name="payload" rows="5" cols="40"></textarea><br><br>
    <input type="submit" value="Analyze">
</form>
{% if prediction %}
    <h3>Prediction: {{ prediction }}</h3>
{% endif %}
'''

# Step 3: Routes
@app.route("/", methods=["GET", "POST"])
def home():
    prediction = None
    if request.method == "POST":
        url = request.form["url"]
        payload = request.form["payload"]
        prediction = predict_threat(url, payload)
    return render_template_string(HTML_TEMPLATE, prediction=prediction)

if __name__ == "__main__":
    app.run(debug=True)
