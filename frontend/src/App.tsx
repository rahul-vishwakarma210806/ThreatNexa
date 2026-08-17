import { useState } from "react";
import "./App.css";

interface RiskResult {
  risk_score: number;
  risk_level: string;
  reasons: string[];
  positive_signals: string[];
}

interface MLAnalysis {
  prediction: string;
  phishing_probability: number;
  legitimate_probability: number;
}

interface FinalDecision {
  final_score: number;
  final_level: string;
  verdict: string;
  rule_score: number;
  rule_level: string;
  ml_prediction: string;
  ml_phishing_probability: number;
  explanation: string[];
}

interface Features {
  url: string;
  url_length: number;
  hostname: string;
  uses_https: boolean;
  has_ip_address: boolean;
  dot_count: number;
  subdomain_count: number;
  path_length: number;
  query_length: number;
  has_query: boolean;
  special_character_count: number;
  suspicious_keywords: string[];
  suspicious_keyword_count: number;
}

interface AnalysisResult {
  url: string;
  status: string;
  risk: RiskResult;
  ml_analysis: MLAnalysis;
  final_decision: FinalDecision;
  features: Features;
}
interface ScanHistoryItem {
  url: string;
  score: number;
  level: string;
}
function App() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [scanHistory, setScanHistory] = useState<ScanHistoryItem[]>([]);
  const handleAnalyze = async () => {
    if (url.trim() === "") {
      setError("Please enter a URL first.");
      setResult(null);
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(
        "http://127.0.0.1:8000/api/analyze",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            url: url.trim(),
          }),
        }
      );

      if (!response.ok) {
        throw new Error("Failed to analyze URL.");
      }

      const data: AnalysisResult = await response.json();

      setResult(data);
setScanHistory((previous) => [
  {
    url: data.url,
    score: data.final_decision.final_score,
    level: data.final_decision.final_level,
  },
  ...previous,
].slice(0, 5));
    } catch (error) {
      console.error(error);
      setError("Could not connect to ThreatNexa backend.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">

      {/* NAVBAR */}
      <header className="navbar">
        <div className="logo">ThreatNexa</div>

        <nav>
          <a href="#">Home</a>
          <a href="#">How it works</a>
          <a href="#">About</a>
        </nav>
      </header>

      <main>
        <section className="hero">

          {/* HERO SECTION */}
          <p className="eyebrow">
            AI-POWERED SECURITY
          </p>

          <h1>
            Detect threats
            <br />
            before you click.
          </h1>

          <p className="subtitle">
            Analyze suspicious URLs with AI-powered
            phishing detection and threat intelligence.
          </p>

          {/* URL SCANNER */}
          <div className="scanner">

            <input
              type="text"
              placeholder="Paste a suspicious URL..."
              value={url}
              onChange={(event) => setUrl(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter" && !loading) {
                  handleAnalyze();
                }
              }}
            />

            <button
              onClick={handleAnalyze}
              disabled={loading}
            >
              {loading ? "scanning..." : "Analyze URL"}
            </button>

          </div>

          {/* ERROR */}
          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          {/* ANALYSIS RESULT */}
          {result && (
            <div className="result-card">

              <p className="result-label">
                THREATNEXA SECURITY REPORT
              </p>

              <h2>
                Analysis Complete
              </h2>

              <p className="result-url">
                {result.url}
              </p>

              {/* ================================================= */}
              {/* FINAL DECISION */}
              {/* ================================================= */}

              <div
                className={`final-decision ${result.final_decision.final_level.toLowerCase()}`}
              >

                <p className="section-label">
                  FINAL SECURITY VERDICT
                </p>

                <div className="final-score">
                  {result.final_decision.final_score}
                  <span>/100</span>
                </div>

                <h3>
                  {result.final_decision.verdict}
                </h3>

                <p>
                  ThreatNexa combines rule-based analysis and
                  machine-learning prediction to produce this
                  final result.
                </p>

              </div>

              {/* ================================================= */}
              {/* ML ANALYSIS */}
              {/* ================================================= */}

              <div className="analysis-section">

                <h3>
                  🤖 Machine Learning Analysis
                </h3>

                <div className="ml-result">

                  <div className="ml-item">
                    <span>Prediction</span>
                    <strong>
                      {result.ml_analysis.prediction}
                    </strong>
                  </div>

                  <div className="ml-item">
                    <span>Phishing Probability</span>
                    <strong>
                      {result.ml_analysis.phishing_probability}%
                    </strong>
                  </div>

                  <div className="ml-item">
                    <span>Legitimate Probability</span>
                    <strong>
                      {result.ml_analysis.legitimate_probability}%
                    </strong>
                  </div>

                </div>

              </div>

              {/* ================================================= */}
              {/* RULE ENGINE */}
              {/* ================================================= */}

              <div className="analysis-section">

                <h3>
                  🛡️ Rule-Based Analysis
                </h3>

                <div className="ml-result">

                  <div className="ml-item">
                    <span>Rule Score</span>
                    <strong>
                      {result.final_decision.rule_score}/100
                    </strong>
                  </div>

                  <div className="ml-item">
                    <span>Rule Risk Level</span>
                    <strong>
                      {result.final_decision.rule_level}
                    </strong>
                  </div>

                </div>

              </div>

              {/* ================================================= */}
              {/* RISK FACTORS */}
              {/* ================================================= */}

              <div className="analysis-section">

                <h3>
                  ⚠️ Risk Factors
                </h3>

                {result.risk.reasons.length > 0 ? (
                  <ul>
                    {result.risk.reasons.map((reason, index) => (
                      <li key={index}>
                        {reason}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>
                    No major risk factors were detected by the
                    current analysis.
                  </p>
                )}

              </div>

              {/* ================================================= */}
              {/* POSITIVE SIGNALS */}
              {/* ================================================= */}

              <div className="analysis-section">

                <h3>
                  ✓ Positive Signals
                </h3>

                {result.risk.positive_signals.length > 0 ? (
                  <ul>
                    {result.risk.positive_signals.map(
                      (signal, index) => (
                        <li key={index}>
                          {signal}
                        </li>
                      )
                    )}
                  </ul>
                ) : (
                  <p>
                    No positive security signals were detected.
                  </p>
                )}

              </div>

              {/* ================================================= */}
              {/* URL FEATURES */}
              {/* ================================================= */}

              <div className="analysis-section">

                <h3>
                  🔍 URL Analysis
                </h3>

                <div className="features-grid">

                  <div className="feature">
                    <span>Hostname</span>
                    <strong>
                      {result.features.hostname}
                    </strong>
                  </div>

                  <div className="feature">
                    <span>HTTPS</span>
                    <strong>
                      {result.features.uses_https
                        ? "Yes"
                        : "No"}
                    </strong>
                  </div>

                  <div className="feature">
                    <span>IP Address</span>
                    <strong>
                      {result.features.has_ip_address
                        ? "Detected"
                        : "Not detected"}
                    </strong>
                  </div>

                  <div className="feature">
                    <span>URL Length</span>
                    <strong>
                      {result.features.url_length}
                    </strong>
                  </div>

                  <div className="feature">
                    <span>Subdomains</span>
                    <strong>
                      {result.features.subdomain_count}
                    </strong>
                  </div>

                  <div className="feature">
                    <span>Query Parameters</span>
                    <strong>
                      {result.features.has_query
                        ? "Present"
                        : "None"}
                    </strong>
                  </div>

                  <div className="feature">
                    <span>Special Characters</span>
                    <strong>
                      {result.features.special_character_count}
                    </strong>
                  </div>

                  <div className="feature">
                    <span>Suspicious Keywords</span>
                    <strong>
                      {result.features.suspicious_keyword_count}
                    </strong>
                  </div>

                </div>

              </div>

              {/* ================================================= */}
              {/* DETECTED KEYWORDS */}
              {/* ================================================= */}

              {result.features.suspicious_keywords.length > 0 && (
                <div className="analysis-section">

                  <h3>
                    Detected Keywords
                  </h3>

                  <div className="keyword-list">

                    {result.features.suspicious_keywords.map(
                      (keyword, index) => (
                        <span
                          className="keyword"
                          key={index}
                        >
                          {keyword}
                        </span>
                      )
                    )}

                  </div>

                </div>
              )}

            </div>
          )}

        </section>
      </main>

    </div>
  );
}

export default App;