import dns.resolver
from email_validator import validate_email, EmailNotValidError
import random

DISPOSABLE_DOMAINS = [
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "mailinator.com"
]

COMMON_PROVIDERS = [
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "protonmail.com"
]

def analyze_email(email: str):

    try:
        valid = validate_email(email)

        email = valid.email

    except EmailNotValidError as e:

        return {
            "valid": False,
            "error": str(e)
        }

    domain = email.split("@")[1]

    # MX RECORD CHECK
    mx_records = []

    try:
        answers = dns.resolver.resolve(domain, 'MX')

        mx_records = [str(r.exchange) for r in answers]

        mx_valid = True

    except:
        mx_valid = False

    # Disposable email detection
    disposable = domain in DISPOSABLE_DOMAINS

    # Provider detection
    provider_known = domain in COMMON_PROVIDERS

    # Fake breach simulation logic
    breach_probability = random.randint(5, 95)

    breached = breach_probability > 70

    breach_sources = [
        "LinkedIn Leak",
        "Adobe Leak",
        "Dropbox Leak",
        "Twitter Leak",
        "Collection #1"
    ]

    return {
        "email": email,
        "valid": True,
        "domain": domain,
        "mx_records_valid": mx_valid,
        "mx_records": mx_records,
        "disposable": disposable,
        "common_provider": provider_known,
        "breached": breached,
        "risk_score": breach_probability,
        "possible_breach_source":
            random.choice(breach_sources)
            if breached else None
    }
