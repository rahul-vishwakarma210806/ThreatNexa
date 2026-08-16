from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from services.url_analyzer import extract_url_features
from services.risk_engine import calculate_risk
from services.ml_predictor import predict_url
from services.decision_engine import make_final_decision


app = FastAPI(title="ThreatNexa API")


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# REQUEST MODEL
# ============================================================

class URLRequest(BaseModel):
    url: str


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():
    return {
        "message": "ThreatNexa backend is running!"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "ThreatNexa API"
    }


# ============================================================
# URL ANALYSIS
# ============================================================

@app.post("/api/analyze")
def analyze_url(request: URLRequest):

    # --------------------------------------------------------
    # 1. Extract URL features
    # --------------------------------------------------------

    features = extract_url_features(request.url)


    # --------------------------------------------------------
    # 2. Rule-based risk analysis
    # --------------------------------------------------------

    risk = calculate_risk(features)


    # --------------------------------------------------------
    # 3. Machine Learning prediction
    # --------------------------------------------------------

    ml_analysis = predict_url(request.url)


    # --------------------------------------------------------
    # 4. Final decision
    # --------------------------------------------------------

    final_decision = make_final_decision(
        risk,
        ml_analysis
    )


    # --------------------------------------------------------
    # 5. Return complete analysis
    # --------------------------------------------------------

    return {
        "url": request.url,
        "status": "analysis_complete",

        "risk": risk,

        "ml_analysis": ml_analysis,

        "final_decision": final_decision,

        "features": features
    }