from dotenv import load_dotenv
import os

load_dotenv()

class Settings:
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
<<<<<<< HEAD
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
=======
>>>>>>> d0f073da67d0618f343f8ec0c7a223c3526914d5
    DATABASE_URL = os.getenv("DATABASE_URL")
    JWT_SECRET = os.getenv("JWT_SECRET")

settings = Settings()
