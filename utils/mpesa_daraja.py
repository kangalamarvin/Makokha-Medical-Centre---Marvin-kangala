import base64
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import requests


@dataclass(frozen=True)
class DarajaToken:
    access_token: str
    expires_at_monotonic: float


_TOKEN_CACHE: Optional[DarajaToken] = None


def _now_mono() -> float:
    return time.monotonic()


def normalize_msisdn_ke(raw: str) -> str:
    """Normalize Kenyan phone numbers to 2547XXXXXXXX or 2541XXXXXXXX."""
    s = (raw or "").strip().replace(" ", "").replace("-", "")
    if not s:
        return ""
    if s.startswith("+"):
        s = s[1:]
    if s.startswith("0") and len(s) >= 10:
        s = "254" + s[1:]
    if s.startswith("7") or s.startswith("1"):
        s = "254" + s
    if not s.isdigit():
        return ""
    return s


def daraja_timestamp(dt: Optional[datetime] = None) -> str:
    """Daraja STK timestamp format: YYYYMMDDHHMMSS."""
    dt = dt or datetime.now()
    return dt.strftime("%Y%m%d%H%M%S")


def generate_stk_password(shortcode: str, passkey: str, timestamp: str) -> str:
    data = f"{shortcode}{passkey}{timestamp}".encode("utf-8")
    return base64.b64encode(data).decode("utf-8")


def get_access_token(*, base_url: str, consumer_key: str, consumer_secret: str, timeout: float = 30.0) -> str:
    """Get and cache OAuth token from Daraja."""
    global _TOKEN_CACHE

    if _TOKEN_CACHE and _TOKEN_CACHE.expires_at_monotonic > (_now_mono() + 10):
        return _TOKEN_CACHE.access_token

    url = f"{base_url.rstrip('/')}/oauth/v1/generate?grant_type=client_credentials"
    resp = requests.get(url, auth=(consumer_key, consumer_secret), timeout=timeout)
    resp.raise_for_status()
    payload = resp.json() or {}
    token = (payload.get("access_token") or "").strip()
    expires_in = int(payload.get("expires_in") or 0)
    if not token:
        raise RuntimeError("Daraja OAuth returned empty access_token")

    # subtract a small skew so we refresh early
    _TOKEN_CACHE = DarajaToken(access_token=token, expires_at_monotonic=_now_mono() + max(0, expires_in - 30))
    return token


def daraja_post_json(
    *,
    base_url: str,
    path: str,
    token: str,
    json_body: Dict[str, Any],
    timeout: float = 60.0,
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    resp = requests.post(url, headers={"Authorization": f"Bearer {token}"}, json=json_body, timeout=timeout)
    resp.raise_for_status()
    return resp.json() if resp.content else {}


def parse_stk_callback(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Parse STK callback body and extract common fields.

    Returns a dict with keys:
      - checkout_request_id
      - merchant_request_id
      - result_code
      - result_desc
      - mpesa_receipt_number (if success)
      - amount (if present)
      - phone_number (if present)
      - transaction_date (as raw string if present)
    """
    stk = ((payload or {}).get("Body") or {}).get("stkCallback") or {}
    result_code = stk.get("ResultCode")
    result_desc = stk.get("ResultDesc")
    checkout_request_id = stk.get("CheckoutRequestID")
    merchant_request_id = stk.get("MerchantRequestID")

    meta = stk.get("CallbackMetadata") or {}
    items = meta.get("Item") or []

    extracted: Dict[str, Any] = {
        "checkout_request_id": checkout_request_id,
        "merchant_request_id": merchant_request_id,
        "result_code": result_code,
        "result_desc": result_desc,
        "mpesa_receipt_number": None,
        "amount": None,
        "phone_number": None,
        "transaction_date": None,
    }

    if isinstance(items, list):
        for it in items:
            name = (it or {}).get("Name")
            value = (it or {}).get("Value")
            if name == "MpesaReceiptNumber":
                extracted["mpesa_receipt_number"] = value
            elif name == "Amount":
                extracted["amount"] = value
            elif name == "PhoneNumber":
                extracted["phone_number"] = str(value) if value is not None else None
            elif name == "TransactionDate":
                extracted["transaction_date"] = str(value) if value is not None else None

    return extracted


def parse_c2b_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Parse C2B confirmation/validation payload (Till/Paybill confirmation).

    Common keys include: TransID, TransAmount, MSISDN, BillRefNumber, TransTime.
    """
    p = payload or {}
    return {
        "trans_id": (p.get("TransID") or "").strip() or None,
        "amount": p.get("TransAmount"),
        "msisdn": (p.get("MSISDN") or "").strip() or None,
        "bill_ref": (p.get("BillRefNumber") or "").strip() or None,
        "trans_time": (p.get("TransTime") or "").strip() or None,
        "first_name": (p.get("FirstName") or "").strip() or None,
        "middle_name": (p.get("MiddleName") or "").strip() or None,
        "last_name": (p.get("LastName") or "").strip() or None,
        "short_code": (p.get("BusinessShortCode") or p.get("ShortCode") or "").strip() or None,
    }


def safe_json_dumps(obj: Any) -> str:
    import json

    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    except Exception:
        try:
            return json.dumps({"_error": "failed_to_serialize"})
        except Exception:
            return "{}"
