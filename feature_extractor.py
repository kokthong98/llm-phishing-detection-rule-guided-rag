import re
from urllib.parse import urlparse, unquote


CATEGORY_MAP = {
    "URL_01": "URL_BASED_RULES",
    "URL_02": "URL_BASED_RULES",
    "URL_03": "URL_BASED_RULES",
    "URL_05": "URL_BASED_RULES",
    "URL_07": "URL_BASED_RULES",
    "URL_08": "URL_BASED_RULES",
    "URL_09": "URL_BASED_RULES",
    "URL_11": "URL_BASED_RULES",
    "URL_13": "URL_BASED_RULES",
    "URL_15": "URL_BASED_RULES",
    "SA_04": "SENDER_AUTHENTICITY_RULES",
    "SE_01": "SOCIAL_ENGINEERING_RULES",
    "SE_02": "SOCIAL_ENGINEERING_RULES",
    "SE_04": "SOCIAL_ENGINEERING_RULES",
    "SE_05": "SOCIAL_ENGINEERING_RULES",
    "SE_06": "SOCIAL_ENGINEERING_RULES",
    "SE_07": "SOCIAL_ENGINEERING_RULES",
    "SE_09": "SOCIAL_ENGINEERING_RULES",
    "SE_10": "SOCIAL_ENGINEERING_RULES",
    "SE_11": "SOCIAL_ENGINEERING_RULES",
    "SE_12": "SOCIAL_ENGINEERING_RULES",
    "SE_13": "SOCIAL_ENGINEERING_RULES",
    "SE_15": "SOCIAL_ENGINEERING_RULES",
    "LA_01": "LINGUISTIC_ANOMALY_RULES",
    "LA_06": "LINGUISTIC_ANOMALY_RULES",
    "LA_10": "LINGUISTIC_ANOMALY_RULES",
    "LE_02": "LEGITIMATE_EMAIL_RULES",
    "LE_05": "LEGITIMATE_EMAIL_RULES",
}


def _extract_urls(text: str) -> list[str]:
    return re.findall(r'https?://[^\s<>"\'\])]+', text, flags=re.IGNORECASE)


def _extract_sender(text: str) -> str:
    match = re.search(r'^\s*from:\s*(.+)$', text, flags=re.IGNORECASE | re.MULTILINE)
    return match.group(1).strip() if match else ""


def _contains_any_pattern(text: str, patterns: list[str]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def extract_rule_evidence(email_text: str) -> dict:
    text = email_text or ""
    lower_text = text.lower()
    urls = _extract_urls(text)
    sender = _extract_sender(text).lower()

    triggered_rules: list[str] = []
    evidence: dict[str, bool] = {}

    def trigger(rule_id: str, evidence_name: str) -> None:
        if rule_id not in triggered_rules:
            triggered_rules.append(rule_id)
        evidence[evidence_name] = True

    def has_rule_prefix(prefix: str) -> bool:
        return any(rule.startswith(prefix) for rule in triggered_rules)

    def has_any_phishing_signal() -> bool:
        # Treat URL, sender authenticity, social engineering, and linguistic anomalies
        # as suspicious/phishing-oriented signals for final legitimacy gating.
        return (
            has_rule_prefix("URL_")
            or has_rule_prefix("SA_")
            or has_rule_prefix("SE_")
            or has_rule_prefix("LA_")
        )

    # -------------------------
    # PATTERN FAMILIES
    # -------------------------

    urgency_patterns = [
        r'\burgent\b',
        r'\bimmediately\b',
        r'\bas soon as possible\b',
        r'\basap\b',
        r'\bwithout delay\b',
        r'\bpromptly\b',
        r'\baction required\b',
        r'\bfinal warning\b',
        r'\btime[- ]sensitive\b',
        r'\bwithin \d+\s*(hours?|days?)\b',
    ]

    threat_patterns = [
        r'\baccount (?:will be|has been) suspended\b',
        r'\baccount (?:will be|has been) blocked\b',
        r'\baccount (?:will be|has been) restricted\b',
        r'\baccount closure\b',
        r'\bpermanent(?:ly)? account closure\b',
        r'\bpenalt(?:y|ies)\b',
        r'\bsuspend(?:ed|sion)?\b',
        r'\bblocked\b',
        r'\blocked\b',
        r'\brestricted\b',
        r'\bterminated\b',
        r'\bfailure to verify\b',
    ]

    verification_patterns = [
        r'\bverify your account\b',
        r'\bconfirm your account\b',
        r'\baccount verification\b',
        r'\bverify your identity\b',
        r'\bconfirm your identity\b',
        r'\bvalidate your account\b',
    ]

    payment_patterns = [
        r'\bpayment required\b',
        r'\bpay now\b',
        r'\bmake payment\b',
        r'\btransfer funds\b',
        r'\bbank transfer\b',
        r'\binvoice attached\b',
        r'\bsettle invoice\b',
    ]

    password_reset_patterns = [
        r'\breset your password\b',
        r'\bpassword reset\b',
        r'\bchange your password\b',
    ]

    confidential_info_patterns = [
        r'\bprovide your password\b',
        r'\bconfirm your banking details\b',
        r'\bcredit card\b',
        r'\bbank details\b',
        r'\bpersonal information\b',
        r'\bconfidential information\b',
        r'\bsocial security\b',
    ]

    cta_patterns = [
    r'\bclick (?:the )?link\b',
    r'\bclick below\b',
    r'\bverify immediately\b',
    r'\bdownload now\b',
    r'\blog in now\b',
    r'\bopen (?:the )?attachment\b',
    r'\breview (?:your|the)?\s*(?:account|sign[- ]in|login)?\s*details\b',
    r'\bvisit (?:the )?link\b',
    r'\buse the link below\b',
    r'\bcheck your account\b',
    r'\bconfirm your details\b',
    r'\bupdate your details\b',
]

    reward_patterns = [
        r'\byou (?:have )?won\b',
        r'\bfree gift\b',
        r'\breward\b',
        r'\bprize\b',
        r'\bvoucher\b',
        r'\bcashback\b',
    ]

    fake_security_patterns = [
    r'\bsecurity alert\b',
    r'\bsuspicious activity\b',
    r'\bunusual activity\b',
    r'\bunusual account activity\b',
    r'\bsecurity issue\b',
    r'\baccount security\b',
    r'\bsecurity notice\b',
]

    unusual_activity_patterns = [
    r'\bunusual activity\b',
    r'\bunusual account activity\b',
    r'\bsuspicious activity\b',
    r'\baccount activity\b',
    r'\breview your sign[- ]in\b',
    r'\bsign[- ]in details\b',
    r'\blogin activity\b',
]

    tech_support_patterns = [
        r'\btechnical support\b',
        r'\bit support\b',
        r'\bhelp desk\b',
        r'\bmicrosoft support\b',
    ]

    generic_greeting_patterns = [
        r'\bdear customer\b',
        r'\bdear user\b',
        r'\bdear member\b',
        r'\bdear valued customer\b',
    ]

    # -------------------------
    # URL-BASED RULES
    # -------------------------

    if any(re.search(r'https?://\d{1,3}(?:\.\d{1,3}){3}', u, flags=re.IGNORECASE) for u in urls):
        trigger("URL_01", "raw_ip_address_in_url")

    for u in urls:
        parsed = urlparse(u)
        domain = parsed.netloc.split("@")[-1]
        if len(domain) > 30:
            trigger("URL_02", "excessive_domain_length")
            break

    for u in urls:
        parsed = urlparse(u)
        domain = parsed.netloc.split("@")[-1]
        if domain.count(".") >= 3:
            trigger("URL_03", "excessive_subdomains")
            break

    shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]
    for u in urls:
        parsed = urlparse(u)
        domain = parsed.netloc.lower()
        if any(s == domain or domain.endswith("." + s) for s in shorteners):
            trigger("URL_05", "url_shortener_detected")
            break

    for u in urls:
        parsed = urlparse(u)
        domain = parsed.netloc.split("@")[-1]
        digit_count = sum(ch.isdigit() for ch in domain)
        if digit_count >= 4:
            trigger("URL_07", "excessive_digits_in_domain")
            break

    for u in urls:
        parsed = urlparse(u)
        if len(parsed.path) > 25:
            trigger("URL_08", "suspicious_url_path_length")
            break

    for u in urls:
        if "@" in u or "%" in u or u.count("-") >= 3:
            trigger("URL_09", "special_characters_in_url")
            break

    if any(u.lower().startswith("http://") for u in urls):
        trigger("URL_11", "http_instead_of_https")

    sensitive_url_terms = ["login", "verify", "update", "reset", "secure", "account"]
    for u in urls:
        decoded_url = unquote(u.lower())
        if any(term in decoded_url for term in sensitive_url_terms):
            trigger("URL_13", "url_contains_sensitive_action_terms")
            break

    for u in urls:
        if "%" in u:
            trigger("URL_15", "encoded_url_characters")
            break

    # -------------------------
    # SENDER AUTHENTICITY RULES
    # -------------------------

    free_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"]
    if sender:
        sender_email_match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', sender)
        if sender_email_match:
            sender_domain = sender_email_match.group(1).lower()
            if sender_domain in free_domains:
                trigger("SA_04", "free_email_provider_sender")

    # -------------------------
    # SOCIAL ENGINEERING RULES
    # -------------------------

    if _contains_any_pattern(lower_text, urgency_patterns):
        trigger("SE_01", "urgency_language_detected")

    if _contains_any_pattern(lower_text, threat_patterns):
        trigger("SE_02", "threat_or_fear_message_detected")

    if _contains_any_pattern(lower_text, reward_patterns):
        trigger("SE_04", "financial_reward_bait_detected")

    if _contains_any_pattern(lower_text, verification_patterns):
        trigger("SE_05", "account_verification_request_detected")

    if _contains_any_pattern(lower_text, payment_patterns):
        trigger("SE_06", "unexpected_payment_request_detected")

    if _contains_any_pattern(lower_text, password_reset_patterns):
        trigger("SE_07", "password_reset_request_detected")

    if _contains_any_pattern(lower_text, confidential_info_patterns):
        trigger("SE_09", "confidential_information_request_detected")

    if _contains_any_pattern(lower_text, [r'\bwithin \d+\s*(hours?|days?)\b', r'\bdeadline\b', r'\bexpires? today\b']):
        trigger("SE_10", "time_pressure_tactics_detected")

    if _contains_any_pattern(lower_text, fake_security_patterns):
        trigger("SE_11", "fake_security_alert_detected")

    if _contains_any_pattern(lower_text, cta_patterns):
        trigger("SE_12", "suspicious_call_to_action_detected")

    if _contains_any_pattern(lower_text, unusual_activity_patterns):
        trigger("SE_13", "unusual_account_activity_warning_detected")

    if _contains_any_pattern(lower_text, tech_support_patterns):
        trigger("SE_15", "fake_technical_support_detected")

    # -------------------------
    # LINGUISTIC ANOMALY RULES
    # -------------------------

    if _contains_any_pattern(lower_text, generic_greeting_patterns):
        trigger("LA_01", "generic_greeting_detected")

    uppercase_words = re.findall(r'\b[A-Z]{4,}\b', text)
    if len(uppercase_words) >= 2:
        trigger("LA_06", "excessive_capitalization_detected")

    if re.search(r'!{2,}|\?{2,}|\.{4,}', text):
        trigger("LA_10", "repeated_punctuation_detected")

    # -------------------------
    # LEGITIMATE EMAIL RULES
    # -------------------------

    if re.search(r'\b(hello|hi|dear)\s+[A-Z][a-z]+\b', text):
        trigger("LE_02", "personalized_greeting_detected")

    # Much stricter LE_05:
    # only allow this if there are no suspicious signals at all
    if (
        not has_any_phishing_signal()
        and not urls
        and not sender
        and not _contains_any_pattern(lower_text, urgency_patterns + threat_patterns + cta_patterns)
    ):
        trigger("LE_05", "no_urgent_call_to_action_detected")

    activated_categories = sorted({CATEGORY_MAP[rule_id] for rule_id in triggered_rules}) #category mapping

    return {
        "triggered_rules": triggered_rules,
        "activated_categories": activated_categories,
        "evidence": evidence,
        "urls_found": urls,
        "sender_found": sender,
    }