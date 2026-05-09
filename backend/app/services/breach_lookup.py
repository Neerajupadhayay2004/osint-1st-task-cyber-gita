import requests

def check_email_breach(email):

    demo_breaches = {
        "admin@test.com": {
            "breached": True,
            "source": "LinkedIn Leak"
        },
        "demo@breach.com": {
            "breached": True,
            "source": "Adobe Leak"
        }
    }

    if email in demo_breaches:
        return demo_breaches[email]

    return {
        "breached": False,
        "source": None
    }
