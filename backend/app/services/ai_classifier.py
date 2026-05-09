import joblib

model = joblib.load("app/ml/model.pkl")

def classify_text(text: str):

    prediction = model.predict([text])[0]

    probability = model.predict_proba([text])[0]

    risk_score = round(float(max(probability)) * 100, 2)

    return {
        "input": text,
        "threat_detected": bool(prediction),
        "risk_score": risk_score
    }