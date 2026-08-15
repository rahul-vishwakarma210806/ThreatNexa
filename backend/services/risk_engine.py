def calculate_risk(features: dict):
    """
    Calculate a preliminary phishing risk score
    based on multiple URL security signals.

    Score range: 0 - 100

    IMPORTANT:
    This is a heuristic/rule-based engine.
    It is not the final machine-learning detector.
    """

    score = 0
    reasons = []
    positive_signals = []

    # ==========================================================
    # 1. IP ADDRESS
    # ==========================================================

    if features["has_ip_address"]:
        score += 25

        reasons.append(
            "The URL uses an IP address instead of a normal domain."
        )
    else:
        positive_signals.append(
            "The hostname is a domain name rather than an IP address."
        )

    # ==========================================================
    # 2. HTTPS
    # ==========================================================

    if not features["uses_https"]:
        score += 15

        reasons.append(
            "The website does not use HTTPS."
        )
    else:
        positive_signals.append(
            "The URL uses HTTPS."
        )

    # ==========================================================
    # 3. URL LENGTH
    # ==========================================================

    if features["url_length"] > 150:
        score += 20

        reasons.append(
            "The URL is unusually long."
        )

    elif features["url_length"] > 100:
        score += 15

        reasons.append(
            "The URL is very long."
        )

    elif features["url_length"] > 75:
        score += 8

        reasons.append(
            "The URL is relatively long."
        )

    # ==========================================================
    # 4. SUBDOMAINS
    # ==========================================================

    if features["subdomain_count"] >= 4:
        score += 15

        reasons.append(
            "The URL contains a very high number of subdomains."
        )

    elif features["subdomain_count"] >= 3:
        score += 12

        reasons.append(
            "The URL contains an unusually high number of subdomains."
        )

    elif features["subdomain_count"] >= 2:
        score += 6

        reasons.append(
            "The URL contains multiple subdomains."
        )

    else:
        positive_signals.append(
            "The domain structure is relatively simple."
        )

    # ==========================================================
    # 5. SUSPICIOUS KEYWORDS
    # ==========================================================

    keyword_count = features["suspicious_keyword_count"]

    if keyword_count >= 4:
        score += 20

        reasons.append(
            "The URL contains several security-sensitive keywords."
        )

    elif keyword_count >= 2:
        score += 10

        reasons.append(
            "The URL contains multiple security-sensitive keywords."
        )

    elif keyword_count == 1:
        score += 5

        reasons.append(
            "The URL contains a security-sensitive keyword."
        )

    # ==========================================================
    # 6. SPECIAL CHARACTERS
    # ==========================================================

    special_count = features["special_character_count"]

    if special_count > 20:
        score += 15

        reasons.append(
            "The URL contains an unusually high number of special characters."
        )

    elif special_count > 10:
        score += 10

        reasons.append(
            "The URL contains many special characters."
        )

    elif special_count > 8:
        score += 5

        reasons.append(
            "The URL contains several special characters."
        )

    # ==========================================================
    # 7. @ SYMBOL
    # ==========================================================

    if features["has_at_symbol"]:
        score += 20

        reasons.append(
            "The URL contains an '@' symbol, which can obscure the actual destination."
        )

    # ==========================================================
    # 8. NON-STANDARD PORT
    # ==========================================================

    if features["has_non_standard_port"]:
        score += 10

        reasons.append(
            "The URL uses a non-standard network port."
        )

    # ==========================================================
    # 9. URL ENCODING
    # ==========================================================

    if features["encoded_character_count"] >= 5:
        score += 10

        reasons.append(
            "The URL contains a large amount of encoded characters."
        )

    elif features["has_url_encoding"]:
        score += 4

        reasons.append(
            "The URL contains encoded characters."
        )

    # ==========================================================
    # 10. URL SHORTENER
    # ==========================================================

    if features["is_url_shortener"]:
        score += 15

        reasons.append(
            "The URL uses a URL-shortening service, which can hide the final destination."
        )

    # ==========================================================
    # 11. PUNYCODE
    # ==========================================================

    if features["has_punycode"]:
        score += 15

        reasons.append(
            "The domain uses punycode, which can sometimes be used to imitate another domain."
        )

    # ==========================================================
    # 12. SUSPICIOUS TLD
    # ==========================================================

    if features["suspicious_tld"]:
        score += 10

        reasons.append(
            "The domain uses a TLD that ThreatNexa currently treats as a higher-risk signal."
        )

    # ==========================================================
    # 13. MANY QUERY PARAMETERS
    # ==========================================================

    if features["query_parameter_count"] >= 8:
        score += 10

        reasons.append(
            "The URL contains an unusually large number of query parameters."
        )

    elif features["query_parameter_count"] >= 5:
        score += 5

        reasons.append(
            "The URL contains several query parameters."
        )

    # ==========================================================
    # 14. DEEP PATH
    # ==========================================================

    if features["path_depth"] >= 8:
        score += 10

        reasons.append(
            "The URL contains a deeply nested path."
        )

    elif features["path_depth"] >= 5:
        score += 5

        reasons.append(
            "The URL contains a relatively deep path."
        )

    # ==========================================================
    # 15. REPEATED SPECIAL CHARACTERS
    # ==========================================================

    if features["has_repeated_special_characters"]:
        score += 5

        reasons.append(
            "The hostname contains repeated special characters."
        )

    # ==========================================================
    # 16. MANY DIGITS IN HOSTNAME
    # ==========================================================

    if features["hostname_digit_ratio"] >= 0.30:
        score += 10

        reasons.append(
            "The hostname contains an unusually high proportion of numbers."
        )

    # ==========================================================
    # 17. KEEP SCORE BETWEEN 0 AND 100
    # ==========================================================

    score = min(max(score, 0), 100)

    # ==========================================================
    # 18. RISK LEVEL
    # ==========================================================

    if score >= 70:
        risk_level = "HIGH"

    elif score >= 40:
        risk_level = "MEDIUM"

    else:
        risk_level = "LOW"

    # ==========================================================
    # 19. ADDITIONAL POSITIVE SIGNALS
    # ==========================================================

    if not features["has_ip_address"]:
        # Already added above.
        pass

    if not features["has_at_symbol"]:
        positive_signals.append(
            "The URL does not contain an '@' symbol."
        )

    if not features["is_url_shortener"]:
        positive_signals.append(
            "The URL does not use a known URL-shortening service."
        )

    if not features["has_punycode"]:
        positive_signals.append(
            "The domain does not use punycode."
        )

    if not features["has_non_standard_port"]:
        positive_signals.append(
            "The URL does not use a non-standard port."
        )

    # ==========================================================
    # RETURN RESULT
    # ==========================================================

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "reasons": reasons,
        "positive_signals": positive_signals,
    }