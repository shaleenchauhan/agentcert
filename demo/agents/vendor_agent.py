"""Agent 5: Vendor Agent.

A domain-sales service that verifies buyer certificates before
fulfilling purchase requests via the Porkbun API. All actions are
logged in a signed, hash-chained audit trail.
"""

import os
import time as _time
from pathlib import Path

import requests
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

import agentcert
from agentcert.integrations.langchain import AgentCertMiddleware

from .trust_verification import verify_counterparty

KEYS_DIR = os.path.join(os.path.dirname(__file__), "..", "keys")

PORKBUN_API = "https://api.porkbun.com/api/json/v3"


def _porkbun_body():
    return {
        "secretapikey": os.environ["PORKBUN_SECRET_KEY"],
        "apikey": os.environ["PORKBUN_API_KEY"],
    }


class VendorAgent:
    """Domain vendor that verifies buyer identity before transacting."""

    def __init__(self):
        self.middleware = AgentCertMiddleware(
            creator_keys=os.path.join(KEYS_DIR, "creator.keys.json"),
            agent_keys=os.path.join(KEYS_DIR, "vendor-agent.keys.json"),
            agent_name="vendor-agent-v1",
            platform="langchain",
            capabilities=["domain-search", "domain-sales", "price-quotation"],
            constraints=["porkbun-only", "max-sale-50-usd"],
            risk_tier=3,
        )
        self._agent_keys = agentcert.load_keys(
            os.path.join(KEYS_DIR, "vendor-agent.keys.json")
        )
        self._trail = self.middleware._trail
        self._last_check_time = 0.0

    def get_certificate(self):
        return self.middleware.get_certificate()

    def _log(self, action_type, summary, detail=None):
        agentcert.log_action(
            self._trail,
            self._agent_keys,
            action_type=action_type,
            action_summary=summary,
            action_detail=detail,
        )

    def _rate_limit_wait(self):
        """Porkbun rate-limits domain checks to 1 per 10 seconds."""
        elapsed = _time.time() - self._last_check_time
        if elapsed < 11:
            wait = 11 - elapsed
            print(f"    [rate limit: waiting {wait:.0f}s]")
            _time.sleep(wait)
        self._last_check_time = _time.time()

    def check_domain(self, domain: str) -> dict:
        """Check if a domain is available via Porkbun."""
        self._log(
            agentcert.ActionType.TOOL_USE,
            f"Checking domain availability: {domain}",
        )
        self._rate_limit_wait()
        body = _porkbun_body()
        try:
            resp = requests.post(
                f"{PORKBUN_API}/domain/checkDomain/{domain}",
                json=body,
                timeout=30,
            )
            data = resp.json()

            if data.get("status") == "ERROR":
                # Rate limited or other API error
                result = {
                    "domain": domain,
                    "available": False,
                    "error": data.get("message", "API error"),
                }
            else:
                response = data.get("response", data)
                avail = response.get("avail", "no")
                available = avail == "yes" if isinstance(avail, str) else bool(avail)
                price = response.get("price", "unknown")
                result = {
                    "domain": domain,
                    "available": available,
                    "price": price,
                    "raw_status": data.get("status"),
                }
        except Exception as e:
            result = {"domain": domain, "available": False, "error": str(e)}

        status_msg = "available" if result.get("available") else "unavailable"
        price_msg = f" (${result['price']}/yr)" if result.get("price") else ""
        self._log(
            agentcert.ActionType.DATA_ACCESS,
            f"Domain check result: {domain} — {status_msg}{price_msg}",
            {"domain": domain, "available": result.get("available", False)},
        )
        return result

    def get_pricing(self) -> dict:
        """Get domain pricing from Porkbun."""
        self._log(agentcert.ActionType.TOOL_USE, "Fetching domain pricing from Porkbun")
        try:
            resp = requests.post(
                f"{PORKBUN_API}/pricing/get", json={}, timeout=30
            )
            data = resp.json()
            pricing = data.get("pricing", {})
            cheap = {}
            for tld in ["xyz", "site", "online", "click", "link", "fun", "io", "dev", "org", "com"]:
                if tld in pricing:
                    cheap[tld] = pricing[tld]
            return cheap
        except Exception as e:
            return {"error": str(e)}

    def handle_purchase_request(self, domain: str, buyer_cert) -> dict:
        """Handle a purchase request: verify buyer, then execute if trusted."""
        self._log(
            agentcert.ActionType.COMMUNICATION,
            f"Received purchase request for {domain}",
            {"domain": domain, "buyer_cert_id": buyer_cert.cert_id[:16] + "..."},
        )

        # --- TRUST HANDSHAKE: Verify buyer ---
        self._log(
            agentcert.ActionType.DECISION,
            "Verifying buyer certificate before processing transaction",
        )

        trust_result = verify_counterparty(
            buyer_cert,
            required_capabilities=["domain-purchase"],
            max_risk_tier=5,
        )

        self._log(
            agentcert.ActionType.DECISION,
            f"Buyer verification: {'TRUSTED' if trust_result.trusted else 'REJECTED'} — {trust_result.reason}",
            {"checks": trust_result.checks, "trusted": trust_result.trusted},
        )

        if not trust_result.trusted:
            self._log(
                agentcert.ActionType.ERROR,
                f"Transaction DENIED: {trust_result.reason}",
                {"domain": domain, "buyer_cert_id": buyer_cert.cert_id[:16] + "..."},
            )
            return {
                "success": False,
                "reason": trust_result.reason,
                "trust_checks": trust_result.checks,
            }

        # --- Execute purchase ---
        self._log(
            agentcert.ActionType.TRANSACTION,
            f"Executing domain purchase: {domain}",
            {"domain": domain},
        )

        # First check availability and get price
        check = self.check_domain(domain)
        if not check.get("available"):
            self._log(
                agentcert.ActionType.ERROR,
                f"Domain not available: {domain}",
                {"domain": domain},
            )
            return {
                "success": False,
                "reason": f"Domain {domain} is not available",
                "trust_checks": trust_result.checks,
            }

        price = check.get("price", "0")

        # Porkbun expects cost as integer cents (e.g. 204 for $2.04)
        try:
            cost_cents = int(round(float(price) * 100))
        except (ValueError, TypeError):
            cost_cents = 0

        body = _porkbun_body()
        body.update({
            "cost": cost_cents,
            "agreeToTerms": "yes",
        })

        try:
            resp = requests.post(
                f"{PORKBUN_API}/domain/create/{domain}",
                json=body,
                timeout=30,
            )
            data = resp.json()

            if data.get("status") == "SUCCESS":
                self._log(
                    agentcert.ActionType.TRANSACTION,
                    f"Domain purchased successfully: {domain} (${price})",
                    {"domain": domain, "price": price, "response_status": "SUCCESS"},
                )
                return {
                    "success": True,
                    "domain": domain,
                    "price": price,
                    "message": f"Domain {domain} registered successfully for ${price}",
                    "trust_checks": trust_result.checks,
                }
            else:
                error_msg = data.get("message", "Unknown error")
                self._log(
                    agentcert.ActionType.ERROR,
                    f"Domain purchase failed: {error_msg}",
                    {"domain": domain, "error": error_msg},
                )
                return {
                    "success": False,
                    "reason": f"Porkbun error: {error_msg}",
                    "trust_checks": trust_result.checks,
                }
        except Exception as e:
            self._log(
                agentcert.ActionType.ERROR,
                f"Domain purchase error: {e}",
                {"domain": domain, "error": str(e)},
            )
            return {
                "success": False,
                "reason": f"Request error: {e}",
                "trust_checks": trust_result.checks,
            }

    def save(self):
        output_dir = os.path.join(
            os.path.dirname(__file__), "..", "output", "vendor-agent"
        )
        os.makedirs(output_dir, exist_ok=True)
        self.middleware.save(output_dir)
        return output_dir
