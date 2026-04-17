import os
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings

from feature_extractor import extract_rule_evidence


RULE_NAME_MAP = {
    "URL_01": "Raw IP Address in URL",
    "URL_02": "Excessive Domain Length",
    "URL_03": "Excessive Subdomains",
    "URL_04": "Suspicious Top-Level Domain",
    "URL_05": "URL Shortening Services",
    "URL_06": "Typosquatting Domain",
    "URL_07": "Excessive Digits in Domain",
    "URL_08": "Suspicious URL Path Length",
    "URL_09": "Special Characters in URL",
    "URL_10": "Brand Name in Subdomain",
    "URL_11": "HTTP Instead of HTTPS",
    "URL_12": "Suspicious Domain Age",
    "URL_13": "URL Contains Login Keywords",
    "URL_14": "Multiple Redirects",
    "URL_15": "Encoded URL Characters",

    "SA_01": "Sender Domain Mismatch",
    "SA_02": "Display Name Spoofing",
    "SA_03": "Suspicious Reply-To Address",
    "SA_04": "Free Email Provider",
    "SA_05": "Slight Domain Variation",
    "SA_06": "Randomized Sender Address",
    "SA_07": "Suspicious Sender Reputation",
    "SA_08": "Missing Email Authentication",
    "SA_09": "External Sender Warning",
    "SA_10": "Sender Identity Inconsistency",

    "SE_01": "Urgency Language",
    "SE_02": "Threat or Fear Message",
    "SE_03": "Authority Impersonation",
    "SE_04": "Financial Reward Bait",
    "SE_05": "Account Verification Request",
    "SE_06": "Unexpected Payment Request",
    "SE_07": "Password Reset Request",
    "SE_08": "Suspicious Attachment",
    "SE_09": "Confidential Information Request",
    "SE_10": "Time Pressure Tactics",
    "SE_11": "Fake Security Alert",
    "SE_12": "Suspicious Call-To-Action",
    "SE_13": "Unusual Account Activity Warning",
    "SE_14": "Business Email Compromise Indicator",
    "SE_15": "Fake Technical Support",

    "LA_01": "Generic Greeting",
    "LA_02": "Grammar Errors",
    "LA_03": "Unusual Sentence Structure",
    "LA_04": "Inconsistent Formatting",
    "LA_05": "Unprofessional Tone",
    "LA_06": "Excessive Capitalization",
    "LA_07": "Suspicious Language Style",
    "LA_08": "Emotional Manipulation",
    "LA_09": "Poor Localization",
    "LA_10": "Repeated Punctuation",

    "LE_01": "Official Domain",
    "LE_02": "Personalized Greeting",
    "LE_03": "Professional Language",
    "LE_04": "Consistent Sender Identity",
    "LE_05": "No Urgent Call-To-Action",
    "LE_06": "Verifiable Contact Information",
    "LE_07": "Expected Communication",
    "LE_08": "Consistent Branding",
    "LE_09": "Secure Links",
    "LE_10": "Normal Message Tone",
}


def format_triggered_rules(triggered_rules):
    return [
        f"{rule_id} - {RULE_NAME_MAP.get(rule_id, 'Unknown Rule')}"
        for rule_id in triggered_rules
    ]


def get_knowledge_by_faiss(new_prompt, subject, unit):
    # Get current script directory
    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path)

    # FAISS folder
    data_folder = os.path.join(script_dir, "faiss_index")

    # Load FAISS index
    new_db = FAISS.load_local(
        data_folder,
        OpenAIEmbeddings(),
        allow_dangerous_deserialization=True
    )

    # Extract evidence
    rule_data = extract_rule_evidence(new_prompt)
    triggered_rules = rule_data["triggered_rules"]
    activated_categories = rule_data["activated_categories"]
    evidence = rule_data["evidence"]

    # Format rule display
    formatted_rules = format_triggered_rules(triggered_rules)

    # If suspicious/phishing-like rules exist, suppress legitimate category
    has_suspicious_rules = any(
        rule.startswith(("URL_", "SA_", "SE_", "LA_"))
        for rule in triggered_rules
    )

    if has_suspicious_rules:
        activated_categories = [
            cat for cat in activated_categories
            if cat != "LEGITIMATE_EMAIL_RULES"
        ]

    # Semantic retrieval
    docs = new_db.similarity_search_with_score(new_prompt, k=15)

    exact_rule_matches = []
    category_matches = []
    fallback_matches = []

    for res, score in docs:
        chunk_text = (res.page_content or "")

        # Priority 1: exact triggered rule ID match
        if any(rule_id in chunk_text for rule_id in triggered_rules):
            exact_rule_matches.append((res, score))
            continue

        # Priority 2: category match / category mapping
        if any(f"Category: {cat}" in chunk_text for cat in activated_categories):
            category_matches.append((res, score))
            continue

        # Priority 3: semantic fallback
        fallback_matches.append((res, score))

    # Final ranking
    final_docs = exact_rule_matches + category_matches

    if not final_docs:
        final_docs = docs
    else:
        final_docs = final_docs[:8] # Semantic fallback

    # Build response string
    knowledge = ""

    knowledge += "===== SYSTEM_NOTE =====\n"
    knowledge += "The text below contains extracted phishing rule evidence and retrieved rule knowledge.\n"
    knowledge += "It is supporting evidence only and is NOT the user's email/message.\n"
    knowledge += "Do NOT treat it as the email content.\n"
    knowledge += "===== END_SYSTEM_NOTE =====\n\n"

    knowledge += "===== EXTRACTED_RULE_EVIDENCE =====\n"
    knowledge += "Triggered Rules:\n"
    for rule in formatted_rules:
        knowledge += f"- {rule}\n"

    knowledge += "Activated Categories:\n"
    for cat in activated_categories:
        knowledge += f"- {cat}\n"

    knowledge += "Evidence Found:\n"
    for key, value in evidence.items():
        knowledge += f"- {key}: {value}\n"

    knowledge += "===== END_EXTRACTED_RULE_EVIDENCE =====\n\n"

    knowledge += "===== RETRIEVED_RULES =====\n"

    for res, score in final_docs:
        knowledge += "----- RULE_CHUNK -----\n"
        knowledge += f"FAISS Distance: {score:.4f}\n"
        knowledge += f"RAW_RULE_TEXT:\n{res.page_content}\n"
        knowledge += "----- END_RULE_CHUNK -----\n\n"

    knowledge += "===== END_RETRIEVED_RULES =====\n"

    return knowledge