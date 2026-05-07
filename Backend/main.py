import os
import json
import re
import logging
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import joblib
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI

from sqlalchemy import create_engine, Column, Integer, String, Text, Float, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy.sql import func


# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("scam-shield")


# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI(title="Scam Shield API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # okay for hackathon/demo
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------
# Load ML model
# -----------------------------
MODEL_PATH = "scam_model.pkl"
model = joblib.load(MODEL_PATH)


# -----------------------------
# OpenAI setup
# -----------------------------
openai_api_key = os.getenv("OPENAI_API_KEY", "").strip()
openai_model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip()

openai_client: Optional[OpenAI] = (
    OpenAI(api_key=openai_api_key) if openai_api_key else None
)


def _load_domain_blocklist() -> set[str]:
    raw = os.getenv("SCAM_BLOCKLIST_DOMAINS", "")
    return {d.strip().lower() for d in raw.split(",") if d.strip()}


DOMAIN_BLOCKLIST = _load_domain_blocklist()

_URL_RE = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)
_PHONE_RE = re.compile(
    r"(?:\+?60|0)?(?:1[0-9]|[3-9][0-9])[0-9]{7,8}\b|\+\d{10,15}\b|\b\d{8,12}\b"
)


def _extract_urls(text: str) -> List[str]:
    return list(dict.fromkeys(m.group(0).rstrip(").,;]") for m in _URL_RE.finditer(text)))


def _host_from_url(url: str) -> Optional[str]:
    u = url.strip()
    if u.lower().startswith("www."):
        u = "http://" + u
    try:
        parsed = urlparse(u)
        host = (parsed.hostname or "").lower()
        return host or None
    except Exception:
        return None


def _extract_domains(urls: List[str]) -> List[str]:
    hosts = []
    for u in urls:
        h = _host_from_url(u)
        if h:
            hosts.append(h)
    return list(dict.fromkeys(hosts))


def _normalize_phone(raw: str) -> str:
    digits = re.sub(r"[^\d+]", "", raw)
    if digits.startswith("+") and len(digits) > 1:
        return "+" + re.sub(r"\D", "", digits[1:])
    return re.sub(r"\D", "", digits)


def _extract_phones(text: str) -> List[str]:
    found = []
    for m in _PHONE_RE.finditer(text):
        norm = _normalize_phone(m.group(0))
        if len(norm) >= 8:
            found.append(norm)
    return list(dict.fromkeys(found))


def _domain_blocklist_hits(domains: List[str], blocklist: set[str]) -> List[str]:
    if not blocklist or not domains:
        return []
    hits = []
    for d in domains:
        for blocked in blocklist:
            if d == blocked or d.endswith("." + blocked):
                hits.append(d)
                break
    return list(dict.fromkeys(hits))


# -----------------------------
# Database setup
# -----------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()

Base = declarative_base()
engine = None
SessionLocal = None
db_connected = False


class SmsScamLog(Base):
    __tablename__ = "sms_scam_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    phone_number = Column(String(50), nullable=True)
    sms_content = Column(Text, nullable=False)
    risk_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False)
    verdict = Column(String(100), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


if DATABASE_URL:
    try:
        engine = create_engine(
            DATABASE_URL,
            pool_pre_ping=True,
            pool_recycle=3600,
        )

        SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine,
        )

        Base.metadata.create_all(bind=engine)
        db_connected = True
        logger.info("Database connected and table checked/created")

    except Exception as exc:
        logger.exception("Database connection/setup failed: %s", exc)
        db_connected = False
        engine = None
        SessionLocal = None
else:
    logger.warning("DATABASE_URL not set. Database logging disabled.")


# -----------------------------
# Pydantic models
# -----------------------------
class MessageIn(BaseModel):
    message: str


class SmsLogIn(BaseModel):
    phone_number: Optional[str] = "UNKNOWN"
    sms_content: str
    risk_score: float
    risk_level: str
    verdict: str


class AnalyzeResponse(BaseModel):
    verdict: str
    risk_score: float
    risk_level: str
    scam_type: str
    reasons: List[str]
    safe_action: str
    reason_source: str
    openai_error: Optional[str] = None
    saved_to_db: bool = False
    db_log_id: Optional[int] = None


class AgentStepOut(BaseModel):
    step_id: str
    title: str
    status: str
    detail: str


class AnalyzeAgenticResponse(BaseModel):
    verdict: str
    risk_score: float
    risk_level: str
    scam_type: str
    reasons: List[str]
    safe_action: str
    reason_source: str
    openai_error: Optional[str] = None
    steps: List[AgentStepOut]
    agent_mode: str = "v0"
    saved_to_db: bool = False
    db_log_id: Optional[int] = None


# -----------------------------
# Helper functions
# -----------------------------
def get_risk_level_and_verdict(scam_prob: float):
    """
    scam_prob is percentage from 0 to 100.
    """
    if scam_prob >= 70:
        return "High", "Likely scam"
    elif scam_prob >= 40:
        return "Medium", "Suspicious"
    else:
        return "Low", "Likely safe"


def detect_scam_type(text: str) -> str:
    lowered = text.lower()

    if any(word in lowered for word in ["bank", "account", "otp", "pin", "password", "verify"]):
        return "Banking / Credential Scam"

    if any(word in lowered for word in ["parcel", "delivery", "customs", "courier"]):
        return "Parcel / Delivery Scam"

    if any(word in lowered for word in ["police", "court", "arrest", "lhdn", "tax", "government"]):
        return "Authority Impersonation Scam"

    if any(word in lowered for word in ["winner", "prize", "reward", "claim"]):
        return "Prize / Reward Scam"

    if any(word in lowered for word in ["investment", "profit", "crypto", "return"]):
        return "Investment Scam"

    return "SMS/Message Scam"


def build_heuristic_reasons(text: str) -> List[str]:
    """
    Backup explanation layer.
    Used when OpenAI is unavailable or fails.
    """
    reasons = []
    lowered = text.lower()

    if "http" in lowered or "www" in lowered:
        reasons.append("Contains a link")

    if any(word in lowered for word in ["urgent", "immediately", "now", "final notice", "within 24 hours"]):
        reasons.append("Uses urgency language")

    if any(word in lowered for word in ["otp", "password", "pin", "tac", "verify"]):
        reasons.append("Requests sensitive credentials")

    if any(word in lowered for word in ["bank", "police", "lhdn", "court", "customs", "government"]):
        reasons.append("Uses authority-related language")

    if any(word in lowered for word in ["pay", "transfer", "rm", "payment", "fee"]):
        reasons.append("Mentions payment or money transfer")

    if not reasons:
        reasons.append("Prediction based on wording patterns from trained spam dataset")

    return reasons[:4]


def get_openai_reasons(text: str, risk_score: float, risk_level: str):
    """
    Uses OpenAI to generate user-friendly reasons.
    Falls back to heuristic reasons if OpenAI fails.
    """
    if openai_client is None:
        return build_heuristic_reasons(text), "heuristic", "OPENAI_API_KEY not set"

    prompt = f"""
Analyze this message for scam indicators.

Return up to 4 short reasons only.

Rules:
- Plain text only
- One reason per line
- No numbering
- No markdown
- Each reason under 16 words
- Focus on ordinary user safety

Risk level: {risk_level}
Risk score: {round(risk_score, 1)}%

Message:
{text}
"""

    try:
        response = openai_client.responses.create(
            model=openai_model,
            input=[
                {
                    "role": "system",
                    "content": "You explain scam indicators clearly and briefly for everyday users.",
                },
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        )

        content = (response.output_text or "").strip()

        reasons = [
            line.strip("-• \t")
            for line in content.splitlines()
            if line.strip()
        ]

        reasons = [reason for reason in reasons if len(reason) > 2][:4]

        if reasons:
            return reasons, "openai", None

        return build_heuristic_reasons(text), "heuristic", "OpenAI returned empty response"

    except Exception as exc:
        logger.exception("OpenAI explanation failed")
        return build_heuristic_reasons(text), "heuristic", str(exc)


def synthesize_agent_reasons(
    text: str,
    risk_score: float,
    risk_level: str,
    verdict: str,
    scam_type: str,
    signals: Dict[str, Any],
) -> Tuple[List[str], str, Optional[str]]:
    if openai_client is None:
        return build_heuristic_reasons(text), "heuristic", "OPENAI_API_KEY not set"

    preview = text.strip().replace("\n", " ")[:200]
    payload = {
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "verdict": verdict,
        "scam_type": scam_type,
        "signals": signals,
        "message_preview": preview,
    }

    user_prompt = f"""Summarize scam risk for the user using ONLY the JSON facts below.
Do not invent links, phone numbers, or organizations not present in the JSON.

Facts:
{json.dumps(payload, ensure_ascii=False, indent=2)}

Return up to 4 short reasons, one per line.
Rules: plain text only, no numbering, no markdown, each line under 16 words."""

    try:
        completion = openai_client.chat.completions.create(
            model=openai_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You explain scam indicators briefly for everyday users. "
                        "Use only the facts given in the user message."
                    ),
                },
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.2,
            max_tokens=200,
        )
        content = (completion.choices[0].message.content or "").strip()
        lines = [line.strip("-• \t") for line in content.splitlines() if line.strip()]
        reasons = [line for line in lines if len(line) > 2][:4]
        if reasons:
            return reasons, "openai", None
        return (
            build_heuristic_reasons(text),
            "heuristic",
            "OpenAI returned empty synthesis",
        )
    except Exception as exc:
        logger.exception("Agent synthesis failed")
        return build_heuristic_reasons(text), "heuristic", str(exc)


def get_safe_action(risk_level: str) -> str:
    if risk_level == "High":
        return (
            "Do not click links, share OTP, PIN, password, or make payment. "
            "Verify directly using the official app, website, or phone number."
        )

    if risk_level == "Medium":
        return (
            "Be cautious. Do not share sensitive details. "
            "Verify the message through an official channel before taking action."
        )

    return (
        "This message appears low risk, but stay cautious. "
        "Avoid sharing sensitive information unless you trust the source."
    )


def save_analysis_to_db(
    text: str,
    risk_score: float,
    risk_level: str,
    verdict: str,
    phone_number: Optional[str] = "UNKNOWN",
):
    """
    Saves analysis into database.

    This version matches existing table:
    id, phone_number, sms_content, risk_score, risk_level, verdict, created_at
    """
    if SessionLocal is None:
        logger.warning("Database save skipped: SessionLocal is None")
        return False, None

    session = SessionLocal()

    try:
        log = SmsScamLog(
            phone_number=phone_number or "UNKNOWN",
            sms_content=text,
            risk_score=round(float(risk_score), 1),
            risk_level=risk_level,
            verdict=verdict,
        )

        session.add(log)
        session.commit()
        session.refresh(log)

        logger.info("Saved analysis to database. id=%s", log.id)
        return True, log.id

    except Exception as exc:
        session.rollback()
        logger.exception("Database insert failed: %s", exc)
        return False, None

    finally:
        session.close()


def run_agentic_analysis(text: str) -> AnalyzeAgenticResponse:
    if not text.strip():
        return AnalyzeAgenticResponse(
            verdict="No message provided",
            risk_score=0,
            risk_level="Low",
            scam_type="SMS/Message Scam",
            reasons=["Empty input"],
            safe_action="Paste a suspicious message to analyze.",
            reason_source="system",
            openai_error=None,
            steps=[
                AgentStepOut(
                    step_id="classify",
                    title="Risk check",
                    status="skipped",
                    detail="No message text was provided.",
                )
            ],
            agent_mode="v0",
            saved_to_db=False,
            db_log_id=None,
        )

    steps: List[AgentStepOut] = []

    probs = model.predict_proba([text])[0]
    scam_prob = float(probs[1]) * 100
    risk_level, verdict = get_risk_level_and_verdict(scam_prob)
    scam_type = detect_scam_type(text)

    steps.append(
        AgentStepOut(
            step_id="classify",
            title="Risk check",
            status="ok",
            detail=(
                f"We estimated a {round(scam_prob, 1)}% scam risk "
                f"({risk_level} - {verdict})."
            ),
        )
    )

    urls = _extract_urls(text)
    domains = _extract_domains(urls)
    phones = _extract_phones(text)

    steps.append(
        AgentStepOut(
            step_id="entities",
            title="Message clues",
            status="warning" if (urls or phones) else "ok",
            detail=(
                f"Found {len(urls)} link(s) and {len(phones)} phone number(s) in the message."
            ),
        )
    )

    hits = _domain_blocklist_hits(domains, DOMAIN_BLOCKLIST)
    if hits:
        blocklist_detail = "Some links match known risky domain(s): " + ", ".join(hits)
    else:
        blocklist_detail = (
            "No links in this message matched your known risky domain list."
        )
    steps.append(
        AgentStepOut(
            step_id="domain_blocklist",
            title="Known risky links check",
            status="warning" if hits else "ok",
            detail=blocklist_detail,
        )
    )

    signals: Dict[str, Any] = {
        "urls": urls[:8],
        "domains": domains[:8],
        "phones_normalized": phones[:8],
        "blocklist_hits": hits,
        "url_count": len(urls),
        "phone_count": len(phones),
    }
    steps.append(
        AgentStepOut(
            step_id="signals",
            title="Summary of findings",
            status="ok",
            detail=(
                f"Prepared a plain summary from {signals['url_count']} link(s), "
                f"{signals['phone_count']} phone number(s), and {len(hits)} risky link match(es)."
            ),
        )
    )

    reasons, reason_source, openai_error = synthesize_agent_reasons(
        text=text,
        risk_score=scam_prob,
        risk_level=risk_level,
        verdict=verdict,
        scam_type=scam_type,
        signals=signals,
    )
    steps.append(
        AgentStepOut(
            step_id="synthesize",
            title="User-friendly explanation",
            status="ok" if reason_source == "openai" else "warning",
            detail=(
                "Generated simple safety reasons for this message."
                if reason_source == "openai"
                else "Used backup explanation because AI response was unavailable."
            ),
        )
    )

    safe_action = get_safe_action(risk_level)
    saved_to_db, db_log_id = save_analysis_to_db(
        text=text,
        risk_score=scam_prob,
        risk_level=risk_level,
        verdict=verdict,
    )

    return AnalyzeAgenticResponse(
        verdict=verdict,
        risk_score=round(scam_prob, 1),
        risk_level=risk_level,
        scam_type=scam_type,
        reasons=reasons[:4],
        safe_action=safe_action,
        reason_source=reason_source,
        openai_error=openai_error,
        steps=steps,
        agent_mode="v0",
        saved_to_db=saved_to_db,
        db_log_id=db_log_id,
    )


# -----------------------------
# Routes
# -----------------------------
@app.get("/api/health")
def health():
    return {
        "ok": True,
        "model_loaded": True,
        "model_path": MODEL_PATH,
        "openai_enabled": openai_client is not None,
        "openai_model": openai_model,
        "db_enabled": SessionLocal is not None,
        "db_connected": db_connected,
        "agentic_v0": True,
        "blocklist_domain_count": len(DOMAIN_BLOCKLIST),
    }


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(payload: MessageIn):
    text = payload.message.strip()

    if not text:
        return AnalyzeResponse(
            verdict="No message provided",
            risk_score=0,
            risk_level="Low",
            scam_type="SMS/Message Scam",
            reasons=["Empty input"],
            safe_action="Paste a suspicious message to analyze.",
            reason_source="system",
            openai_error=None,
            saved_to_db=False,
            db_log_id=None,
        )

    # ML prediction
    probs = model.predict_proba([text])[0]

    # probs[0] = ham / normal probability
    # probs[1] = spam / scam probability
    scam_prob = float(probs[1]) * 100

    risk_level, verdict = get_risk_level_and_verdict(scam_prob)
    scam_type = detect_scam_type(text)

    reasons, reason_source, openai_error = get_openai_reasons(
        text=text,
        risk_score=scam_prob,
        risk_level=risk_level,
    )

    safe_action = get_safe_action(risk_level)

    saved_to_db, db_log_id = save_analysis_to_db(
        text=text,
        risk_score=scam_prob,
        risk_level=risk_level,
        verdict=verdict,
    )

    return AnalyzeResponse(
        verdict=verdict,
        risk_score=round(scam_prob, 1),
        risk_level=risk_level,
        scam_type=scam_type,
        reasons=reasons,
        safe_action=safe_action,
        reason_source=reason_source,
        openai_error=openai_error,
        saved_to_db=saved_to_db,
        db_log_id=db_log_id,
    )


@app.post("/api/analyze-agentic", response_model=AnalyzeAgenticResponse)
def analyze_agentic(payload: MessageIn):
    return run_agentic_analysis(payload.message.strip())


@app.post("/api/sms-log")
def log_sms(payload: SmsLogIn):
    """
    Manual logging endpoint.
    Not required if /api/analyze auto-saves.
    """
    saved_to_db, db_log_id = save_analysis_to_db(
        text=payload.sms_content,
        risk_score=payload.risk_score,
        risk_level=payload.risk_level,
        verdict=payload.verdict,
        phone_number=payload.phone_number or "UNKNOWN",
    )

    return {
        "ok": saved_to_db,
        "saved_to_db": saved_to_db,
        "db_log_id": db_log_id,
    }


@app.get("/api/logs")
def get_logs(limit: int = 50):
    """
    View latest database logs.
    """
    if SessionLocal is None:
        return {
            "ok": False,
            "error": "Database not configured",
            "logs": [],
        }

    session = SessionLocal()

    try:
        logs = (
            session.query(SmsScamLog)
            .order_by(SmsScamLog.id.desc())
            .limit(limit)
            .all()
        )

        return {
            "ok": True,
            "logs": [
                {
                    "id": log.id,
                    "phone_number": log.phone_number,
                    "sms_content": log.sms_content,
                    "risk_score": log.risk_score,
                    "risk_level": log.risk_level,
                    "verdict": log.verdict,
                    "created_at": str(log.created_at),
                }
                for log in logs
            ],
        }

    except Exception as exc:
        logger.exception("Failed to read logs: %s", exc)
        return {
            "ok": False,
            "error": str(exc),
            "logs": [],
        }

    finally:
        session.close()