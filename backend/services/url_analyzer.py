from urllib.parse import urlparse, parse_qs
import ipaddress
import re


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "account",
    "secure",
    "update",
    "confirm",
    "password",
    "signin",
    "bank",
    "payment",
]

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
}

SUSPICIOUS_TLDS = {
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
}


def extract_url_features(url: str):

    parsed = urlparse(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    fragment = parsed.fragment or ""

    hostname_lower = hostname.lower()

    # ==========================================================
    # IP ADDRESS
    # ==========================================================

    has_ip_address = False

    try:
        ipaddress.ip_address(hostname)
        has_ip_address = True
    except ValueError:
        pass

    # ==========================================================
    # DOMAIN STRUCTURE
    # ==========================================================

    dot_count = hostname.count(".")

    # IP addresses are NOT domains with subdomains.
    if has_ip_address:
        subdomain_count = 0
    else:
        subdomain_count = max(dot_count - 1, 0)

    # ==========================================================
    # PATH
    # ==========================================================

    clean_path = path.strip("/")

    if clean_path:
        path_depth = len(clean_path.split("/"))
    else:
        path_depth = 0

    # ==========================================================
    # QUERY PARAMETERS
    # ==========================================================

    query_parameters = parse_qs(query)

    query_parameter_count = len(query_parameters)

    # ==========================================================
    # HTTPS
    # ==========================================================

    uses_https = parsed.scheme.lower() == "https"

    # ==========================================================
    # @ SYMBOL
    # ==========================================================

    has_at_symbol = "@" in url

    # ==========================================================
    # PORT
    # ==========================================================

    has_non_standard_port = False

    try:
        port = parsed.port

        if port is not None:
            if parsed.scheme.lower() == "https" and port != 443:
                has_non_standard_port = True

            elif parsed.scheme.lower() == "http" and port != 80:
                has_non_standard_port = True

    except ValueError:
        has_non_standard_port = True

    # ==========================================================
    # URL ENCODING
    # ==========================================================

    encoded_matches = re.findall(
        r"%[0-9a-fA-F]{2}",
        url
    )

    encoded_character_count = len(encoded_matches)

    has_url_encoding = encoded_character_count > 0

    # ==========================================================
    # HOSTNAME CHARACTERS
    # ==========================================================

    hyphen_count = hostname.count("-")

    digit_count_in_hostname = sum(
        character.isdigit()
        for character in hostname
    )

    if hostname:
        hostname_digit_ratio = (
            digit_count_in_hostname / len(hostname)
        )
    else:
        hostname_digit_ratio = 0.0

    # ==========================================================
    # REPEATED SPECIAL CHARACTERS
    # ==========================================================

    has_repeated_special_characters = bool(
        re.search(r"[-_.]{2,}", hostname)
    )

    # ==========================================================
    # URL SHORTENER
    # ==========================================================

    is_url_shortener = hostname_lower in URL_SHORTENERS

    # ==========================================================
    # PUNYCODE
    # ==========================================================

    has_punycode = (
        hostname_lower.startswith("xn--")
        or ".xn--" in hostname_lower
    )

    # ==========================================================
    # SUSPICIOUS TLD
    # ==========================================================

    suspicious_tld = any(
        hostname_lower.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )

    # ==========================================================
    # SUSPICIOUS KEYWORDS
    # ==========================================================

    url_lower = url.lower()

    suspicious_keywords_found = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    # ==========================================================
    # SPECIAL CHARACTERS
    # ==========================================================

    special_character_count = len(
        re.findall(r"[@?=&%_\-]", url)
    )

    # ==========================================================
    # RETURN FEATURES
    # ==========================================================

    return {
        "url": url,

        "hostname": hostname,

        "url_length": len(url),

        "path_length": len(path),

        "path_depth": path_depth,

        "query_length": len(query),

        "query_parameter_count": query_parameter_count,

        "has_query": bool(query),

        "has_fragment": bool(fragment),

        "fragment_length": len(fragment),

        "uses_https": uses_https,

        "has_ip_address": has_ip_address,

        "has_at_symbol": has_at_symbol,

        "has_non_standard_port": has_non_standard_port,

        "has_url_encoding": has_url_encoding,

        "encoded_character_count": encoded_character_count,

        "dot_count": dot_count,

        "subdomain_count": subdomain_count,

        "hyphen_count": hyphen_count,

        "digit_count_in_hostname": digit_count_in_hostname,

        "hostname_digit_ratio": hostname_digit_ratio,

        "has_repeated_special_characters":
            has_repeated_special_characters,

        "is_url_shortener": is_url_shortener,

        "has_punycode": has_punycode,

        "suspicious_tld": suspicious_tld,

        "special_character_count":
            special_character_count,

        "suspicious_keywords":
            suspicious_keywords_found,

        "suspicious_keyword_count":
            len(suspicious_keywords_found),
    }