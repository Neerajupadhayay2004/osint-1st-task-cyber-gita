from fastapi import APIRouter
from app.services.breach_lookup import check_email_breach

router = APIRouter()

@router.get("/breach/{email}")
def breach_lookup(email: str):
    return check_email_breach(email)
