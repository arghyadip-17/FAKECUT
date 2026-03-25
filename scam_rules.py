import re
import ipaddress
from urllib.parse import urlparse

# -----------------------------
# Normalization / helpers
# -----------------------------

def normalize(text: str) -> str:
    text = text or ""
    text = text.lower()

    # Remove punctuation but keep ₹ and @ because they matter in scam detection
    text = re.sub(r"[^\w\s₹@./:+-]", " ", text)

    # Collapse repeated spaces
    text = re.sub(r"\s+", " ", text).strip()
    return text


def contains_any(text: str, phrases: list[str]) -> list[str]:
    found = []
    for phrase in phrases:
        if phrase and phrase in text:
            found.append(phrase)
    return found


def regex_any(text: str, patterns: list[str]) -> list[str]:
    found = []
    for pattern in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE):
            found.append(pattern)
    return found


def unique_extend(target_list, items):
    seen = {str(x).lower() for x in target_list}
    for item in items:
        key = str(item).lower()
        if key not in seen:
            target_list.append(item)
            seen.add(key)


def clamp(n, low=0, high=100):
    return max(low, min(high, n))


# -----------------------------
# Scoring rules
# -----------------------------

RULES = [
    {
        "reason": "Asks for money",
        "keywords": [
            "registration fee",
            "processing fee",
            "onboarding fee",
            "training fee",
            "application fee",
            "security fee",
            "deposit",
            "fee required",
            "payment required",
            "advance payment",
            "small fee",
            "admin fee",
            "activation fee",
            "verification fee",
            "kit fee",
            "document fee",
            "courier fee",
            "refundable fee",
            "token amount",
            "account activation charge",
            "background verification fee",
            "joining fee",
            "certificate fee",
        ],
        "points": 18,
    },
    {
        "reason": "Urgent pressure",
        "keywords": [
            "apply immediately",
            "urgent",
            "last chance",
            "join today",
            "limited seats",
            "hurry up",
            "within 24 hours",
            "immediately respond",
            "fast approval",
            "act now",
            "today only",
            "offer ends soon",
            "selected within",
            "within 2 hours",
        ],
        "points": 12,
    },
    {
        "reason": "Too good to be true",
        "keywords": [
            "guaranteed job",
            "guaranteed salary",
            "huge salary",
            "easy money",
            "no skill required",
            "work from home and earn",
            "earn money instantly",
            "instant income",
            "earn money easily",
            "high package",
            "direct selection",
            "100% placement",
            "sure job",
            "fixed selection",
        ],
        "points": 18,
    },
    {
        "reason": "Weak company details",
        "keywords": [
            "telegram only",
            "whatsapp only",
            "no official website",
            "unknown company",
            "contact on whatsapp",
            "dm for details",
            "direct message for details",
            "message us on telegram",
            "reach us on whatsapp",
            "contact via telegram",
            "contact via whatsapp",
            "email us on gmail",
            "send message on whatsapp",
            "reply to this number",
            "call this number",
            "walk in no interview",
        ],
        "points": 14,
    },
    {
        "reason": "Privacy warning",
        "keywords": [
            "share otp",
            "share aadhaar",
            "share aadhar",
            "share bank details",
            "send pan card",
            "send cv with bank details",
            "send documents and otp",
            "share your otp",
            "bank account details",
            "cv with aadhaar",
            "upload aadhaar",
            "send pancard",
            "share card details",
        ],
        "points": 26,
    },
    {
        "reason": "Credential theft risk",
        "keywords": [
            "password",
            "login",
            "sign in",
            "verify account",
            "reset password",
            "remote access",
            "anydesk",
            "teamviewer",
            "chrome remote desktop",
        ],
        "points": 20,
    },
]

SAFE_SIGNALS = [
    ("official website", -12),
    ("apply through official website", -15),
    ("career page", -8),
    ("hr@", -10),
    ("careers@", -10),
    ("no fee", -16),
    ("no registration fee", -16),
    ("no application fee", -16),
    ("selection based on interview", -10),
    ("official email", -8),
    ("company website", -6),
    ("no interview fee", -10),
]

CONTACT_HINTS = [
    "telegram",
    "whatsapp",
    "dm",
    "direct message",
    "message us",
    "contact on whatsapp",
    "contact on telegram",
    "contact via telegram",
    "contact via whatsapp",
    "text us",
    "ping us",
    "reply on whatsapp",
]

SUSPICIOUS_JOB_CONTEXT = [
    "job",
    "internship",
    "hiring",
    "vacancy",
    "apply",
    "recruitment",
    "offer letter",
    "joining",
    "career",
    "walk-in",
    "placement",
]

PAYMENT_TERMS = [
    "pay",
    "payment",
    "fee",
    "deposit",
    "transfer",
    "upi",
    "bank transfer",
    "card",
    "card details",
    "qr code",
    "scan to pay",
    "send money",
    "refund",
    "amount",
    "rupee",
    "rs.",
    "rs ",
    "inr",
    "advance",
    "token",
]

SUSPICIOUS_COMPANIES = [
    "amazon",
    "google",
    "microsoft",
    "tcs",
    "infosys",
    "wipro",
    "accenture",
    "deloitte",
    "capgemini",
    "ibm",
    "flipkart",
    "zoho",
    "oracle",
    "linkedin",
]

FREE_EMAIL_DOMAINS = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "rediffmail.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "live.com",
    "aol.com",
]

# Regex-based patterns catch variations your keyword list may miss
REGEX_RULES = [
    (r"\b(no\s+experience|required|freshers?\s+welcome)\b", 8, "No experience requirement"),
    (r"(₹|rs\.?|inr)?\s?\d{3,7}(,\d{3})*(\s?(/|per)\s?(day|week|month))", 18, "High earning claim"),
    (r"\b(earn|make)\s+(₹|rs\.?|inr)?\s?\d{3,7}(,\d{3})*(\s?(/|per)\s?(day|week|month))", 22, "Suspicious earning claim"),
    (r"\b(work\s+from\s+home|wfh)\b", 4, "Work-from-home claim"),
    (r"\b(guaranteed|sure)\s+(job|selection|salary|placement)\b", 18, "Guaranteed outcome"),
    (r"\b(no\s+interview|direct\s+selection|instant\s+joining)\b", 14, "No interview / instant selection"),
    (r"\b(part\s*time|easy\s*job|simple\s*task|copy\s*paste|data\s*entry|typing\s*job)\b", 12, "Low-skill task bait"),
    (r"\b(like|subscribe|review|rate|click)\s+(videos?|posts?|products?)\b", 16, "Task scam hint"),
    (r"\b(telegram|whatsapp)\s*(only|exclusive|preferred)\b", 8, "Informal contact only"),
    (r"\b(send|share)\s+(otp|aadhaar|aadhar|pan|bank\s*details|card\s*details|password)\b", 28, "Sensitive info request"),
    (r"\b(amazon|google|microsoft|tcs|infosys|wipro|accenture|deloitte|capgemini|ibm)\b.*\b(whatsapp|telegram|gmail)\b", 22, "Company impersonation via informal channel"),
    (r"\b(offer\s*letter|joining\s*letter)\b.*\b(fee|payment|deposit)\b", 22, "Offer letter fee"),
    (r"\b(training\s*kit|study\s*material|certificate\s*fee|document\s*verification\s*fee)\b", 16, "Training/certificate fee"),
    (r"\b(click|open|visit)\s+(this\s+)?link\b", 8, "Click link trap"),
    (r"\b(install|download)\s+(app|application|apk|software)\b", 10, "Forced install/download"),
    (r"\b(remote\s+access|anydesk|teamviewer|chrome\s+remote\s+desktop)\b", 24, "Remote access request"),
    (r"\b(whatsapp|telegram|gmail)\b.*\b(job|internship|hiring|vacancy|apply)\b", 12, "Hiring through informal channel"),
]

URL_RULES = [
    ("Shortened URL detected", ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "shorturl.at", "cutt.ly", "rebrand.ly"], 20),
    ("Suspicious domain pattern", ["-jobs", "-career", "-apply", "freecash", "quickmoney", "workfromhome", "joboffer"], 10),
    ("Suspicious TLD", [".top", ".xyz", ".click", ".live", ".shop", ".monster"], 8),
]

GENERIC_PHRASES = [
    ("free laptop", 8),
    ("refund later", 12),
    ("security deposit", 16),
    ("return the fee", 12),
    ("send documents", 6),
    ("certificate charges", 12),
    ("paid training", 8),
    ("commission based only", 6),
    ("no prior experience", 6),
    ("selection guaranteed", 16),
    ("approve your profile", 8),
    ("complete task", 8),
    ("rating task", 12),
    ("amazon task", 12),
    ("google form registration", 8),
    ("job without interview", 14),
    ("work with us and earn", 14),
    ("limited opening", 6),
    ("only few seats left", 8),
]

SENSITIVE_PATTERNS = [
    (r"\b\d{10}\b", "Phone number mentioned directly.", "phone number"),
    (r"\b\d{12}\b", "12-digit number mentioned (possible Aadhaar).", "12-digit id"),
    (r"\botp\b", "OTP is mentioned.", "otp"),
    (r"\baadhaar\b|\baadhar\b", "Aadhaar is requested.", "aadhaar"),
    (r"\bpan card\b|\bpan\b", "PAN is requested.", "pan"),
    (r"\bbank details\b", "Bank details are requested.", "bank details"),
    (r"\bbank account details\b", "Bank account details are requested.", "bank account details"),
    (r"\bifsc\b", "IFSC is requested.", "ifsc"),
    (r"\bupi id\b|\bupi\b", "UPI is requested.", "upi"),
    (r"\bcard number\b|\bdebit card\b|\bcredit card\b", "Card details are requested.", "card details"),
    (r"\bpassword\b", "Password is requested.", "password"),
    (r"\bpin\b", "PIN is mentioned.", "pin"),
]

# -----------------------------
# URL analysis
# -----------------------------

def analyze_url(url: str):
    score = 0
    reasons = []
    matched_terms = []

    url = (url or "").strip()
    if not url:
        return score, reasons, matched_terms

    # Allow bare domain strings
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = (parsed.netloc or "").lower()
    full_url = url.lower()

    if not host:
        score += 8
        reasons.append("URL looks incomplete or invalid.")
        matched_terms.append(url)

    # IP-based host is suspicious
    try:
        host_no_port = host.split(":")[0]
        ipaddress.ip_address(host_no_port)
        score += 20
        reasons.append("URL uses a raw IP address instead of a normal domain.")
        matched_terms.append(host_no_port)
    except Exception:
        pass

    # Punycode / homograph trick
    if "xn--" in host:
        score += 20
        reasons.append("URL uses punycode, which can hide lookalike domains.")
        matched_terms.append("punycode")

    # Too many subdomains
    if host.count(".") >= 3:
        score += 5
        reasons.append("Domain has many subdomains.")
        matched_terms.append(host)

    # Shorteners and suspicious patterns
    for reason, bad_parts, points in URL_RULES:
        for item in bad_parts:
            if item in full_url or item in host:
                score += points
                reasons.append(f"{reason}: '{item}'")
                matched_terms.append(item)
                break

    # URL contains '@' trick
    if "@" in url:
        score += 10
        reasons.append("URL contains '@', which can be used to confuse users.")
        matched_terms.append("@")

    # Login/verify wording in URL path
    if any(word in full_url for word in ["login", "verify", "secure", "signin", "account"]):
        score += 5
        reasons.append("URL contains login/verify/security wording.")
        matched_terms.append("login/verify/security wording")

    return score, reasons, matched_terms


# -----------------------------
# Main analyzer
# -----------------------------

def analyze_content(text: str, url: str = "", **fields):
    """
    Backward compatible:
    - analyze_content(text, url)

    Optional structured fields:
    - company_name
    - contact_email
    - company_website
    - salary_range
    - telecommuting
    - job_title
    - recruiter_name
    - company_verified
    """
    text_norm = normalize(text)
    url_norm = normalize(url)

    total_score = 0
    reasons = []
    matched_terms = []

    # -------------------------
    # Structured metadata rules
    # -------------------------
    company_name = normalize(fields.get("company_name", ""))
    contact_email = normalize(fields.get("contact_email", ""))
    company_website = normalize(fields.get("company_website", ""))
    salary_range = normalize(fields.get("salary_range", ""))
    telecommuting = fields.get("telecommuting", None)
    job_title = normalize(fields.get("job_title", ""))
    recruiter_name = normalize(fields.get("recruiter_name", ""))
    company_verified = fields.get("company_verified", None)

    # If company name is missing in a hiring post, increase suspicion a bit
    if any(word in text_norm for word in SUSPICIOUS_JOB_CONTEXT) and not company_name:
        total_score += 4
        reasons.append("Job/internship post does not mention a clear company name.")
        matched_terms.append("missing company name")

    # If only free email is used, that's suspicious
    if contact_email:
        if any(contact_email.endswith("@" + d) for d in FREE_EMAIL_DOMAINS):
            total_score += 8
            reasons.append("Recruiter/contact uses a free email domain.")
            matched_terms.append("free email domain")
        if not re.search(r"@[a-z0-9.-]+\.[a-z]{2,}$", contact_email):
            total_score += 6
            reasons.append("Contact email looks malformed.")
            matched_terms.append("invalid email")
    else:
        if any(word in text_norm for word in SUSPICIOUS_JOB_CONTEXT):
            total_score += 3
            reasons.append("No contact email provided in a job-related post.")
            matched_terms.append("missing email")

    # If company website is missing, weak signal
    if any(word in text_norm for word in SUSPICIOUS_JOB_CONTEXT) and not company_website:
        total_score += 3
        reasons.append("Job/internship post does not mention an official company website.")
        matched_terms.append("missing company website")

    # Unverified company flag if explicitly false
    if company_verified is False:
        total_score += 6
        reasons.append("Company is marked unverified.")
        matched_terms.append("unverified company")

    # Telecommuting + payment is risky in some scam patterns
    if telecommuting is True and any(word in text_norm for word in ["fee", "pay", "deposit", "registration"]):
        total_score += 8
        reasons.append("Remote work mention combined with payment request.")
        matched_terms.append("remote work + payment")

    # Salary not disclosed in hiring post can be okay, but generic vague offers are weaker
    if any(word in text_norm for word in SUSPICIOUS_JOB_CONTEXT) and not salary_range:
        if any(word in text_norm for word in ["urgent", "apply", "join today", "limited seats"]):
            total_score += 4
            reasons.append("Hiring post is urgent and does not mention salary details.")
            matched_terms.append("urgent + no salary")

    # -------------------------
    # Safe signals first
    # -------------------------
    for phrase, points in SAFE_SIGNALS:
        if phrase in text_norm:
            total_score += points
            reasons.append(f"Safe signal detected: '{phrase}'")

    # -------------------------
    # Keyword-based rules
    # -------------------------
    for rule in RULES:
        found = contains_any(text_norm, rule["keywords"])
        if found:
            total_score += rule["points"]
            reasons.append(f"{rule['reason']}: {', '.join(found[:5])}")
            unique_extend(matched_terms, found)

    # -------------------------
    # Regex-based rules
    # -------------------------
    for pattern, points, reason in REGEX_RULES:
        if re.search(pattern, text_norm, flags=re.IGNORECASE):
            total_score += points
            reasons.append(reason)
            matched_terms.append(reason.lower())

    # -------------------------
    # Payment-related logic
    # -------------------------
    payment_hits = contains_any(text_norm, PAYMENT_TERMS)
    if payment_hits:
        # smaller base penalty; context will decide more
        total_score += 6
        reasons.append(f"Payment-related terms found: {', '.join(payment_hits[:5])}")
        unique_extend(matched_terms, payment_hits)

        if any(word in text_norm for word in SUSPICIOUS_JOB_CONTEXT):
            if not any(p in text_norm for p in ["no fee", "no registration fee", "no application fee", "official website"]):
                total_score += 10
                reasons.append("Payment/fee mentioned in a job or internship context.")
                matched_terms.append("payment + job context")

    # -------------------------
    # Job context boost
    # -------------------------
    job_context_hits = [word for word in SUSPICIOUS_JOB_CONTEXT if word in text_norm]
    if job_context_hits:
        total_score += 3
        reasons.append("Job-related context detected.")
        unique_extend(matched_terms, job_context_hits)

    # -------------------------
    # Big company + informal channel = impersonation signal
    # -------------------------
    if any(company in text_norm for company in SUSPICIOUS_COMPANIES):
        if any(ch in text_norm for ch in ["whatsapp", "telegram", "gmail", "dm"]):
            total_score += 18
            reasons.append("Big company name used with informal contact channel.")
            matched_terms.append("company impersonation")

    # -------------------------
    # Urgency + payment combination
    # -------------------------
    urgency_hits = ["urgent", "immediately", "today only", "within 24 hours", "hurry", "fast approval"]
    if any(word in text_norm for word in urgency_hits) and payment_hits:
        total_score += 8
        reasons.append("Urgency combined with payment request.")
        matched_terms.append("urgency + payment")

    # -------------------------
    # Informal contact method
    # -------------------------
    contact_hits = [w for w in CONTACT_HINTS if w in text_norm]
    if contact_hits:
        total_score += 6
        reasons.append("Uses informal contact methods like Telegram/WhatsApp/DM.")
        unique_extend(matched_terms, contact_hits)

    # -------------------------
    # Direct phone / email patterns in text
    # -------------------------
    if re.search(r"\b[\w\.-]+@gmail\.com\b", text_norm):
        total_score += 6
        reasons.append("Uses a free Gmail address instead of a company domain.")
        matched_terms.append("gmail address")

    if re.search(r"\b(?:\+?\d{1,3}[-.\s]?)?\d{10}\b", text_norm):
        total_score += 4
        reasons.append("A phone number is included in the post.")
        matched_terms.append("phone number")

    # -------------------------
    # Sensitive data detection
    # -------------------------
    for pattern, reason, term in SENSITIVE_PATTERNS:
        if re.search(pattern, text_norm, flags=re.IGNORECASE):
            total_score += 18
            reasons.append(reason)
            matched_terms.append(term)

    # -------------------------
    # Extra suspicious phrases from scam-style posts
    # -------------------------
    for phrase, points in GENERIC_PHRASES:
        if phrase in text_norm:
            total_score += points
            reasons.append(f"Suspicious phrase detected: '{phrase}'")
            matched_terms.append(phrase)

    # -------------------------
    # Special combination logic
    # -------------------------

    # Fee + job context
    if any(word in text_norm for word in ["fee", "deposit", "payment"]) and any(
        word in text_norm for word in SUSPICIOUS_JOB_CONTEXT
    ):
        total_score += 6
        reasons.append("Fee/payment request appears in a job-related post.")
        matched_terms.append("fee + job context")

    # Earning claim + task verbs
    if "earn" in text_norm and any(w in text_norm for w in ["like", "review", "click", "subscribe", "rate"]):
        total_score += 14
        reasons.append("Task-based earning scam pattern.")
        matched_terms.append("earn + task")

    # Link + urgency
    if "link" in text_norm and any(w in text_norm for w in ["urgent", "immediately", "today only", "within 24 hours"]):
        total_score += 10
        reasons.append("Urgent link instruction.")
        matched_terms.append("link + urgency")

    # Company name + Gmail / Telegram / WhatsApp
    if any(company in text_norm for company in SUSPICIOUS_COMPANIES) and any(
        w in text_norm for w in ["gmail", "whatsapp", "telegram"]
    ):
        total_score += 8
        reasons.append("Well-known company name paired with informal contact.")
        matched_terms.append("company + informal contact")

    # -------------------------
    # URL analysis
    # -------------------------
    url_score, url_reasons, url_terms = analyze_url(url)
    total_score += url_score
    reasons.extend(url_reasons)
    unique_extend(matched_terms, url_terms)

    # -------------------------
    # Repetition / text spam hints
    # -------------------------
    words = re.findall(r"\b[a-z]{3,}\b", text_norm)
    if words:
        unique_word_ratio = len(set(words)) / len(words)
        if unique_word_ratio < 0.45 and len(words) > 25:
            total_score += 6
            reasons.append("Text looks repetitive or spammy.")
            matched_terms.append("repetitive text")

    # -------------------------
    # Final boost for multiple independent signals
    # -------------------------
    if len(reasons) >= 5:
        total_score += 4
        reasons.append("Multiple scam signals detected together.")
        matched_terms.append("multiple signals")

    total_score = clamp(total_score, 0, 100)

    if total_score <= 30:
        verdict = "Likely Safe"
        badge = "safe"
    elif total_score <= 60:
        verdict = "Caution"
        badge = "caution"
    else:
        verdict = "Suspicious"
        badge = "danger"

    if total_score > 60:
        explanation = "This post has multiple warning signs. Verify everything before trusting it."
    elif total_score > 30:
        explanation = "Some details look risky. Check the company, email domain, URL, and payment requests carefully."
    else:
        explanation = "No major scam signals were found, but manual verification is still recommended."

    if not reasons:
        reasons = ["No obvious red flags found in the text or URL."]

    advice = [
        "Verify the company on its official website and LinkedIn page.",
        "Check whether the recruiter uses an official company email domain.",
        "Never pay money to get a job, internship, or certificate.",
        "Do not share OTP, bank details, Aadhaar, PAN, or passwords.",
        "Search the company name + 'scam' before proceeding.",
    ]

    # Remove duplicate matched terms
    seen = set()
    unique_terms = []
    for term in matched_terms:
        key = str(term).lower()
        if key not in seen:
            seen.add(key)
            unique_terms.append(term)

    return {
        "score": total_score,
        "verdict": verdict,
        "badge": badge,
        "explanation": explanation,
        "reasons": reasons,
        "advice": advice,
        "matched_terms": unique_terms,
    }


def detect_fake_job_offer(text: str, url: str = "", **fields):
    return analyze_content(text=text, url=url, **fields)