def make_final_decision(risk, ml_analysis):
    """
    Combine the rule-based risk engine and the ML prediction
    into one final ThreatNexa security decision.

    This does NOT replace either system.
    It combines their results.
    """

    rule_score = risk["risk_score"]
    rule_level = risk["risk_level"]

    ml_prediction = ml_analysis["prediction"]
    phishing_probability = ml_analysis["phishing_probability"]

    # ==========================================================
    # 1. START WITH THE RULE-BASED SCORE
    # ==========================================================

    final_score = rule_score

    # ==========================================================
    # 2. ML CONTRIBUTION
    # ==========================================================

    # If ML considers the URL phishing, increase the final score
    # according to how confident the model is.
    if ml_prediction == "PHISHING":

        if phishing_probability >= 90:
            final_score += 30

        elif phishing_probability >= 70:
            final_score += 20

        elif phishing_probability >= 50:
            final_score += 10

    # If ML considers the URL legitimate, reduce the score
    # slightly, but never ignore suspicious rule-based signals.
    elif ml_prediction == "LEGITIMATE":

        if phishing_probability <= 10:
            final_score -= 10

        elif phishing_probability <= 30:
            final_score -= 5

    # ==========================================================
    # 3. KEEP SCORE BETWEEN 0 AND 100
    # ==========================================================

    final_score = min(max(final_score, 0), 100)

    # ==========================================================
    # 4. DETERMINE FINAL RISK LEVEL
    # ==========================================================

    if final_score >= 70:
        final_level = "HIGH"

    elif final_score >= 40:
        final_level = "MEDIUM"

    else:
        final_level = "LOW"

    # ==========================================================
    # 5. FINAL VERDICT
    # ==========================================================

    if final_level == "HIGH":
        verdict = "HIGH RISK"

    elif final_level == "MEDIUM":
        verdict = "SUSPICIOUS"

    else:
        verdict = "LOW RISK"

    # ==========================================================
    # 6. EXPLANATION
    # ==========================================================

    explanation = []

    explanation.append(
        f"Rule-based analysis produced a risk score of {rule_score}/100."
    )

    explanation.append(
        f"Machine learning classified the URL as {ml_prediction} "
        f"with {phishing_probability}% phishing probability."
    )

    if ml_prediction == "PHISHING":
        explanation.append(
            "The ML system increased the final risk because "
            "the URL resembles phishing URLs seen during training."
        )

    else:
        explanation.append(
            "The ML system reduced the final risk because "
            "the URL resembles legitimate URLs seen during training."
        )

    # ==========================================================
    # 7. RETURN FINAL RESULT
    # ==========================================================

    return {
        "final_score": final_score,
        "final_level": final_level,
        "verdict": verdict,
        "rule_score": rule_score,
        "rule_level": rule_level,
        "ml_prediction": ml_prediction,
        "ml_phishing_probability": phishing_probability,
        "explanation": explanation,
    }