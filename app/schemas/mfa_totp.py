from pydantic import BaseModel

class VerifyMFASchema(BaseModel):
    code: str

class MFAVerifyLoginSchema(BaseModel):
    mfa_token: str
    code: str