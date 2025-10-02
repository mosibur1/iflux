import re
import secrets
import signal
import tracemalloc
import uuid
from fake_useragent import UserAgent
import os
import sys
import time
import json
import asyncio
import random
import threading
import gzip
import zlib
import brotli
import chardet
import requests
from datetime import datetime
from queue import Queue as ThreadQueue
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from colorama import Fore, init as colorama_init
import psutil
import shutil
import socket
import statistics
from collections import deque
import gc

DEFAULT_TIMEOUT = 10
NAME_BOT = "Iflux"


class BoundedSet:
    """LRU-like bounded set to avoid unbounded memory growth for dedupe."""

    def __init__(self, maxlen: int = 10000):
        self._set = set()
        self._dq = deque()
        self.maxlen = maxlen

    def __contains__(self, item):
        return item in self._set

    def add(self, item):
        if item in self._set:
            return
        self._set.add(item)
        self._dq.append(item)
        if len(self._dq) > self.maxlen:
            old = self._dq.popleft()
            try:
                self._set.remove(old)
            except KeyError:
                pass

    def clear(self):
        self._set.clear()
        self._dq.clear()

    def __len__(self):
        return len(self._dq)


colorama_init(autoreset=True)

_global_ua = None


def now_ts():
    return datetime.now().strftime("[%Y:%m:%d ~ %H:%M:%S] |")


class ProxyManager:
    def __init__(
        self,
        proxy_list: list | None,
        test_url: str = "https://httpbin.org/ip",
        test_timeout: float = 4.0,
    ):
        self.proxy_pool = ThreadQueue()
        self._bad = set()
        self.test_url = test_url
        self.test_timeout = test_timeout
        if proxy_list:
            for p in proxy_list:
                p = p.strip()
                if p:
                    self.proxy_pool.put(p)

    def _quick_test(self, proxy: str) -> bool:
        try:
            proxies = {"http": proxy, "https": proxy}
            r = requests.get(self.test_url, proxies=proxies, timeout=self.test_timeout)
            r.raise_for_status()
            return True
        except Exception:
            return False

    def get_proxy(self, test_before_use: bool = True, attempts: int = 4) -> str | None:
        tried = []
        for _ in range(attempts):
            try:
                p = self.proxy_pool.get_nowait()
            except Exception:
                break
            if not p or p in self._bad:
                continue
            if test_before_use:
                if self._quick_test(p):
                    return p
                else:
                    self._bad.add(p)
                    continue
            return p
        return None

    def release_proxy(self, proxy: str):
        if not proxy or proxy in self._bad:
            return
        try:
            self.proxy_pool.put_nowait(proxy)
        except Exception:
            pass

    def mark_bad(self, proxy: str):
        if not proxy:
            return
        self._bad.add(proxy)


class iflux:
    BASE_URL = "https://gw.iflux.global/api/"
    HEADERS = {
        "accept": "application/json, text/plain, */*",
        "accept-encoding": "br",
        "accept-language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
        "authorization": "",
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": "https://depin.iflux.global",
        "pragma": "no-cache",
        "priority": "u=1, i",
        "sec-ch-ua": '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    }

    def __init__(
        self,
        use_proxy: bool = False,
        proxy_list: list | None = None,
        load_on_init: bool = True,
    ):
        """
        load_on_init: pass False for worker instances to avoid duplicate config/query logs.
        """
        # track whether this instance should suppress some session-level logs
        self._suppress_local_session_log = not load_on_init

        # load config/query only when requested
        if load_on_init:
            self.config = self.load_config()
            self.query_list = self.load_query("query.txt")
        else:
            self.config = {}
            self.query_list = []

        self.last_login_signature = None
        self.index_account = 0
        self.session = None
        self.proxy = None
        # prefer explicit proxy_list param; fallback to file loader only when loaded on init
        self.proxy_list = (
            proxy_list
            if proxy_list is not None
            else (self.load_proxies() if load_on_init else [])
        )
        self.proxy_manager = (
            ProxyManager(self.proxy_list) if self.config.get("proxy") else None
        )

    def banner(self):
        self.log("")
        self.log("=======================================", Fore.CYAN)
        self.log(f"           🎉  Iflux MRPTech BOT 🎉             ", Fore.CYAN)
        self.log("=======================================", Fore.CYAN)
        self.log("🚀  by MRPTech", Fore.CYAN)
        self.log("📢  https://t.me/mrptechofficial", Fore.CYAN)
        self.log("=======================================", Fore.CYAN)
        self.log("")

    def log(self, message, color=Fore.RESET):
        safe_message = str(message).encode("utf-8", "backslashreplace").decode("utf-8")
        print(Fore.LIGHTBLACK_EX + now_ts() + " " + color + safe_message + Fore.RESET)

    def _request(
        self,
        method: str,
        url_or_path: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        data=None,
        json_data=None,
        timeout: float | None = None,
        use_session: bool = True,
        allow_redirects: bool = True,
        stream: bool = False,
        parse: bool = False,
        retries: int = 2,
        backoff: float = 0.5,
        allow_proxy: bool = True,
    ):
        method = method.upper()
        headers = headers or {}
        timeout = timeout or DEFAULT_TIMEOUT

        if not url_or_path.lower().startswith("http"):
            url = self.BASE_URL.rstrip("/") + "/" + url_or_path.lstrip("/")
        else:
            url = url_or_path

        hdr = dict(self.HEADERS)
        if headers:
            hdr.update(headers)

        last_exc = None
        for attempt in range(1, retries + 2):
            chosen_proxy = None
            resp = None
            try:
                proxies = None
                # === STICKY PROXY logic: prefer existing self.proxy if present ===
                if allow_proxy and getattr(self, "proxy_manager", None):
                    if getattr(self, "proxy", None):
                        chosen_proxy = self.proxy
                        proxies = {"http": chosen_proxy, "https": chosen_proxy}
                    else:
                        # get new proxy from manager (it will quick-test itself)
                        chosen_proxy = self.proxy_manager.get_proxy(
                            test_before_use=True
                        )
                        if chosen_proxy:
                            # make it sticky for future requests
                            self.proxy = chosen_proxy
                            self._proxy_use_count = 0
                            proxies = {"http": chosen_proxy, "https": chosen_proxy}

                call_args = dict(
                    headers=hdr,
                    params=params,
                    data=data,
                    json=json_data,
                    timeout=timeout,
                    allow_redirects=allow_redirects,
                    stream=stream,
                )

                # attach proxies only for raw requests when session not used OR if proxies set
                if use_session and getattr(self, "session", None):
                    if proxies:
                        # set session.proxies for sticky usage (do not restore unless failed)
                        try:
                            self.session.proxies = proxies
                        except Exception:
                            pass
                    func = getattr(self.session, method.lower())
                    resp = func(url, **call_args)
                else:
                    if proxies:
                        call_args["proxies"] = proxies
                    func = getattr(requests, method.lower())
                    resp = func(url, **call_args)

                resp.raise_for_status()

                # success -> don't immediately release sticky proxy.
                if chosen_proxy:
                    # increment use count and rotate if configured
                    self._proxy_use_count = getattr(self, "_proxy_use_count", 0) + 1
                    rotate_after = (
                        int(self.config.get("proxy_rotate_every", 0))
                        if getattr(self, "config", None)
                        else 0
                    )
                    if rotate_after > 0 and self._proxy_use_count >= rotate_after:
                        # put proxy back to pool and drop sticky
                        try:
                            if getattr(self, "proxy_manager", None):
                                self.proxy_manager.release_proxy(self.proxy)
                        except Exception:
                            pass
                        self.proxy = None
                        self._proxy_use_count = 0

                if parse:
                    decoded = self.decode_response(resp)
                    return resp, decoded
                return resp

            except requests.exceptions.RequestException as e:
                last_exc = e
                # if used a sticky proxy and it failed -> mark bad and drop it
                if chosen_proxy and getattr(self, "proxy_manager", None):
                    try:
                        self.proxy_manager.mark_bad(chosen_proxy)
                    except Exception:
                        pass
                    try:
                        self.log(
                            f"⚠️ Proxy {chosen_proxy} failure on attempt {attempt}: {e}",
                            Fore.YELLOW,
                        )
                    except Exception:
                        pass
                    # drop current sticky proxy so next attempt picks new
                    self.proxy = None
                    self._proxy_use_count = 0
                else:
                    self.log(
                        f"⚠️ Request error attempt {attempt} for {method} {url}: {e}",
                        Fore.YELLOW,
                    )

                if attempt >= (retries + 1):
                    self.log(
                        f"❌ Giving up on {method} {url} after {attempt} attempts",
                        Fore.RED,
                    )
                    raise
                sleep_for = backoff * (2 ** (attempt - 1)) + random.random() * 0.2
                time.sleep(sleep_for)
                continue

            except Exception as e:
                # unexpected
                if getattr(self, "proxy", None) and getattr(
                    self, "proxy_manager", None
                ):
                    # drop sticky if something weird happened
                    try:
                        self.proxy_manager.mark_bad(self.proxy)
                    except Exception:
                        pass
                    self.proxy = None
                self.log(
                    f"❌ Unexpected error during request {method} {url}: {e}", Fore.RED
                )
                raise

        if last_exc:
            raise last_exc
        raise RuntimeError("request failed unexpectedly")

    def get_ua(self):
        """
        Return a shared fake UserAgent instance (or None).
        Uses the module-global _global_ua so we don't recreate the UserAgent object.
        """
        global _global_ua
        if _global_ua is None:
            try:

                _global_ua = UserAgent()
            except Exception:
                _global_ua = None
        return _global_ua

    def rotate_proxy_and_ua(
        self, force_new_proxy: bool = True, quick_test: bool = True
    ):
        """
        Rotate User-Agent and (optionally) pick a new proxy from proxy_manager.
        Now supports random proxy pickup from multiple proxy_manager interfaces:
        - proxy_manager.get_random_proxy(test_before_use=...)
        - proxy_manager.list_proxies() / proxy_manager.get_all_proxies() / proxy_manager.proxies
        - fallback to proxy_manager.get_proxy(test_before_use=...)
        Logs what's happening. Returns (ua_str, proxy_str).
        """

        # ensure lock to avoid races if multiple threads touch the same session
        if not hasattr(self, "_session_lock"):
            self._session_lock = threading.Lock()

        ua_applied = None
        proxy_applied = None

        try:
            with self._session_lock:
                # --- rotate UA (same logic as before) ---
                try:
                    ua_obj = self.get_ua() if hasattr(self, "get_ua") else None
                    ua_str = None
                    if ua_obj:
                        try:
                            ua_str = ua_obj.random
                        except Exception:
                            ua_str = None

                    if not ua_str:
                        base = self.HEADERS.get("user-agent", "python-requests/unknown")
                        ua_str = f"{base} (+rot/{random.randint(1000,9999)})"

                    try:
                        if getattr(self, "session", None):
                            self.session.headers.update({"User-Agent": ua_str})
                    except Exception as e:
                        try:
                            self.log(
                                f"⚠️ Failed to apply UA to session: {e}", Fore.YELLOW
                            )
                        except Exception:
                            pass

                    self.HEADERS["user-agent"] = ua_str
                    ua_applied = ua_str
                    try:
                        self.log(f"🔁 UA rotated -> {ua_str[:120]}", Fore.CYAN)
                    except Exception:
                        pass
                except Exception as e:
                    try:
                        self.log(f"⚠️ UA rotation error: {e}", Fore.YELLOW)
                    except Exception:
                        pass

                # --- rotate proxy (random pickup with fallbacks) ---
                proxy_applied = getattr(self, "proxy", None)

                try:
                    if (
                        force_new_proxy
                        and self.config.get("proxy")
                        and getattr(self, "proxy_manager", None)
                    ):
                        old = getattr(self, "proxy", None)
                        newp = None
                        pm = self.proxy_manager

                        # 1) Prefer get_random_proxy if available
                        try:
                            if hasattr(pm, "get_random_proxy"):
                                try:
                                    newp = pm.get_random_proxy(
                                        test_before_use=quick_test
                                    )
                                except TypeError:
                                    newp = pm.get_random_proxy()
                        except Exception:
                            newp = None

                        # 2) Try list/get_all style interfaces (list_proxies / get_all_proxies / proxies)
                        if not newp:
                            candidates = None
                            for attr in (
                                "list_proxies",
                                "get_all_proxies",
                                "get_proxies",
                                "proxies",
                            ):
                                try:
                                    if hasattr(pm, attr):
                                        cand = getattr(pm, attr)
                                        # if callable, call it; else treat as iterable
                                        if callable(cand):
                                            try:
                                                candidates = cand()
                                            except TypeError:
                                                # maybe requires no args or has different signature
                                                try:
                                                    candidates = cand
                                                except Exception:
                                                    candidates = None
                                        else:
                                            candidates = cand
                                        break
                                except Exception:
                                    candidates = None

                            # normalize candidates to a list of strings
                            try:
                                if candidates:
                                    if isinstance(candidates, dict):
                                        # dict might be mapping proxy->meta
                                        candidates = list(candidates.keys())
                                    else:
                                        candidates = list(candidates)
                                    # filter empties
                                    candidates = [c for c in candidates if c]
                                    if candidates:
                                        newp = random.choice(candidates)
                            except Exception:
                                newp = None

                        # 3) fallback to existing get_proxy (old behavior)
                        if not newp:
                            try:
                                if hasattr(pm, "get_proxy"):
                                    try:
                                        newp = pm.get_proxy(test_before_use=quick_test)
                                    except TypeError:
                                        newp = pm.get_proxy()
                            except Exception:
                                newp = None

                        # If we found a new proxy, apply it
                        if newp:
                            try:
                                if getattr(self, "session", None):
                                    self.session.proxies = {"http": newp, "https": newp}
                                    # clearing cookies is often helpful when switching proxies
                                    try:
                                        self.session.cookies.clear()
                                    except Exception:
                                        pass
                            except Exception as e:
                                try:
                                    self.log(
                                        f"⚠️ Failed to set session proxies: {e}",
                                        Fore.YELLOW,
                                    )
                                except Exception:
                                    pass

                            self.proxy = newp
                            proxy_applied = newp
                            try:
                                self._proxy_use_count = 0
                            except Exception:
                                self._proxy_use_count = 0

                            # return old proxy to pool if it's different
                            if old and old != newp:
                                try:
                                    if hasattr(pm, "release_proxy"):
                                        pm.release_proxy(old)
                                    try:
                                        self.log(
                                            f"🔁 Released old proxy -> {old}",
                                            Fore.MAGENTA,
                                        )
                                    except Exception:
                                        pass
                                except Exception:
                                    try:
                                        self.log(
                                            f"⚠️ Could not release old proxy {old}",
                                            Fore.YELLOW,
                                        )
                                    except Exception:
                                        pass

                            try:
                                self.log(f"🔁 Using proxy {newp}", Fore.CYAN)
                            except Exception:
                                pass
                        else:
                            proxy_applied = getattr(self, "proxy", None)
                            try:
                                self.log(
                                    f"ℹ️ Proxy rotate: no new proxy selected, keeping {proxy_applied or 'local'}",
                                    Fore.YELLOW,
                                )
                            except Exception:
                                pass
                    else:
                        # proxy rotation disabled by config or no proxy manager
                        proxy_applied = getattr(self, "proxy", None)
                        if proxy_applied:
                            try:
                                self.log(
                                    f"ℹ️ Keeping existing proxy: {proxy_applied}",
                                    Fore.YELLOW,
                                )
                            except Exception:
                                pass
                        else:
                            try:
                                self.log("🌐 Using local IP (no proxy)", Fore.YELLOW)
                            except Exception:
                                pass
                except Exception as e:
                    try:
                        self.log(f"⚠️ Proxy rotation error: {e}", Fore.YELLOW)
                    except Exception:
                        pass

        except Exception as e:
            try:
                self.log(f"❌ rotate_proxy_and_ua failed: {e}", Fore.RED)
            except Exception:
                pass

        return ua_applied, proxy_applied

    def load_config(self, suppress_log: bool = False):
        """
        Load config.json. If suppress_log=True, don't print the 'Config loaded' message.
        """
        try:
            with open("config.json", "r", encoding="utf-8") as f:
                cfg = json.load(f)
            if not suppress_log:
                self.log("✅ Config loaded", Fore.GREEN)
            return cfg
        except FileNotFoundError:
            if not suppress_log:
                self.log("⚠️ config.json not found (using minimal)", Fore.YELLOW)
            return {}
        except Exception as e:
            if not suppress_log:
                self.log(f"❌ Config parse error: {e}", Fore.RED)
            return {}

    def load_query(self, path_file: str = "query.txt") -> list:
        try:
            with open(path_file, "r", encoding="utf-8") as file:
                queries = [line.strip() for line in file if line.strip()]
            if not queries:
                self.log(f"⚠️ {path_file} empty", Fore.YELLOW)
            self.log(f"✅ {len(queries)} entries loaded", Fore.GREEN)
            return queries
        except FileNotFoundError:
            self.log(f"❌ {path_file} not found", Fore.RED)
            return []
        except Exception as e:
            self.log(f"❌ Query load error: {e}", Fore.RED)
            return []

    def login(self, index: int) -> None:
        """Standardized login (updated for query entries with format "email|password"):
        - parse self.query_list entries as "email|password" (password may contain additional '|' characters)
        - POST to auth/login with {"email","password"}
        - store access token into self.HEADERS['authorization']
        - GET public/v1/accounts/profile and show important fields

        Notes:
        - This version intentionally removes any signature parsing/storage (query.txt is expected
        to contain only email|password). Backwards-compatible parsing for list/tuple entries is
        retained.
        """
        self.log("🔐 Attempting to log in...", Fore.GREEN)

        if not hasattr(self, "query_list") or not isinstance(
            self.query_list, (list, tuple)
        ):
            self.log("❌ query_list missing or invalid. Aborting.", Fore.RED)
            return

        if index < 0 or index >= len(self.query_list):
            self.log("❌ Invalid login index. Please check again.", Fore.RED)
            return

        self.prepare_session()

        raw = self.query_list[index]
        try:
            raw_display = raw if isinstance(raw, str) else str(raw)
        except Exception:
            raw_display = "<unprintable>"
        self.log(f"📋 Using raw creds: {raw_display[:24]}... (truncated)", Fore.CYAN)

        # parse email|password (use maxsplit=1 so password may contain '|')
        email = None
        password = None
        try:
            if isinstance(raw, str):
                parts = raw.split("|", 1)
                if len(parts) >= 1:
                    email = parts[0].strip()
                if len(parts) >= 2:
                    password = parts[1].strip()
            elif isinstance(raw, (list, tuple)):
                if len(raw) >= 1:
                    email = str(raw[0]).strip()
                if len(raw) >= 2:
                    password = str(raw[1]).strip()
            else:
                s = str(raw)
                parts = s.split("|", 1)
                if len(parts) >= 1:
                    email = parts[0].strip()
                if len(parts) >= 2:
                    password = parts[1].strip()
        except Exception as e:
            self.log(f"❌ Error parsing credentials: {e}", Fore.RED)
            return

        if not email or not password:
            self.log(
                "❌ Bad credential format (expected email|password). Aborting.",
                Fore.RED,
            )
            return

        payload = {"email": email, "password": password}

        auth_resp = None
        auth_data = None
        try:
            self.log("📡 Sending auth/login request...", Fore.CYAN)
            # NOTE: do NOT pass headers param — _request uses self.HEADERS automatically
            auth_resp, auth_data = self._request(
                "POST",
                "auth/login",
                json_data=payload,
                timeout=DEFAULT_TIMEOUT,
                parse=True,
                retries=2,
                backoff=0.5,
            )
        except requests.exceptions.RequestException as e:
            self.log(f"❌ Failed to send auth request: {e}", Fore.RED)
            if auth_resp is not None:
                try:
                    self.log(f"📄 Response content: {auth_resp.text}", Fore.RED)
                except Exception:
                    pass
            return
        except Exception as e:
            self.log(f"❌ Unexpected error during auth: {e}", Fore.RED)
            if auth_resp is not None:
                try:
                    self.log(f"📄 Response content: {auth_resp.text}", Fore.RED)
                except Exception:
                    pass
            return

        # process auth response
        try:
            # support fields "access"/"refresh" or fallback to "token"
            access = None
            refresh = None
            if isinstance(auth_data, dict):
                access = auth_data.get("access") or auth_data.get("token") or ""
                refresh = auth_data.get("refresh") or ""
            else:
                raise ValueError("Auth response not a dict")

            if not access:
                raise ValueError("Access token not found in auth response")

            # store token
            self.HEADERS["authorization"] = f"Bearer {access}"

            self.log("✅ Auth successful! Stored access token.", Fore.GREEN)
        except Exception as e:
            self.log(f"❌ Error processing auth response: {e}", Fore.RED)
            return

        # fetch profile
        profile_resp = None
        profile_data = None
        try:
            self.log(
                "📡 Fetching profile: GET public/v1/accounts/profile ...", Fore.CYAN
            )
            profile_resp, profile_data = self._request(
                "GET",
                "public/v1/accounts/profile",
                timeout=DEFAULT_TIMEOUT,
                parse=True,
                retries=1,
            )
        except requests.exceptions.RequestException as e:
            self.log(f"❌ Failed to fetch profile: {e}", Fore.RED)
            if profile_resp is not None:
                try:
                    self.log(f"📄 Response content: {profile_resp.text}", Fore.RED)
                except Exception:
                    pass
            return
        except Exception as e:
            self.log(f"❌ Unexpected error fetching profile: {e}", Fore.RED)
            if profile_resp is not None:
                try:
                    self.log(f"📄 Response content: {profile_resp.text}", Fore.RED)
                except Exception:
                    pass
            return

        # display important profile fields
        try:
            if not isinstance(profile_data, dict):
                raise ValueError("Profile response not a dict")

            # Important fields to show
            account_id = profile_data.get("account_id", "N/A")
            username = profile_data.get("username", "N/A")
            email_p = profile_data.get("email", "N/A")
            date_joined = profile_data.get("date_joined", "N/A")
            verified_email = profile_data.get("verified_email", False)
            verified_kyc = profile_data.get("verified_kyc", 0)
            mfa_enabled = profile_data.get("mfa_enabled", False)
            first_name = profile_data.get("first_name", "")
            last_name = profile_data.get("last_name", "")
            phone = profile_data.get("phone_number", "")
            country = profile_data.get("country", "")
            city = profile_data.get("city", "")
            share_code = profile_data.get("share_code", "")
            roles = profile_data.get("roles", [])

            self.log("👤 Profile Summary:", Fore.GREEN)
            self.log(f"    - Account ID : {account_id}", Fore.CYAN)
            self.log(f"    - Username   : {username}", Fore.CYAN)
            self.log(f"    - Email      : {email_p}", Fore.CYAN)
            if first_name or last_name:
                self.log(
                    f"    - Name       : {first_name} {last_name}".strip(), Fore.CYAN
                )
            self.log(f"    - Joined     : {date_joined}", Fore.CYAN)
            self.log(
                f"    - Verified E.: {verified_email}  |  KYC level: {verified_kyc}",
                Fore.CYAN,
            )
            self.log(f"    - MFA        : {mfa_enabled}", Fore.CYAN)
            if phone:
                self.log(f"    - Phone      : {phone}", Fore.CYAN)
            if country or city:
                self.log(f"    - Location   : {country} / {city}", Fore.CYAN)
            if share_code:
                self.log(f"    - Share Code : {share_code}", Fore.CYAN)
            if roles:
                self.log(f"    - Roles      : {', '.join(map(str, roles))}", Fore.CYAN)

            self.log("✅ Login + profile fetch complete", Fore.GREEN)
        except Exception as e:
            self.log(f"❌ Error processing profile response: {e}", Fore.RED)
            return
        finally:
            # lightweight local cleanup to avoid leaking large objects
            for name in [
                "raw",
                "email",
                "password",
                "payload",
                "auth_resp",
                "auth_data",
                "access",
                "refresh",
                "profile_resp",
                "profile_data",
            ]:
                try:
                    if name in locals():
                        del locals()[name]
                except Exception:
                    pass

    def mining(self) -> None:
        """
        Mining flow (activate-only):
        - extension.txt is source of truth: index_account|node_id|signature (one entry per line).
        - Filter entries by current account index (supports 'akunN' or 'N').
        - Count nodes for this account; if less than node_per_account -> create more until satisfied.
        - After ensuring enough nodes, check each node status:
        - If status == "active" -> skip
        - Else -> attempt activate (no deactivate step)
        - Do NOT create/update account.txt.
        """

        EXT_FILE = "extension.txt"
        DEFAULT_CREATE_TRIES = 6

        def safe_read(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    return fh.read()
            except FileNotFoundError:
                return ""
            except Exception as e:
                self.log(f"⚠️ Failed to read {path}: {e}", Fore.YELLOW)
                return ""

        def safe_append_lines(path, lines):
            try:
                with open(path, "a", encoding="utf-8") as fh:
                    for ln in lines:
                        fh.write(ln + "\n")
                    fh.flush()
                    try:
                        os.fsync(fh.fileno())
                    except Exception:
                        pass
            except Exception as e:
                self.log(f"⚠️ Failed to append to {path}: {e}", Fore.YELLOW)

        def repair_concat_and_split(raw):
            raw = raw or ""
            lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
            if len(lines) == 0:
                return []
            if len(lines) == 1 and "|" in lines[0]:
                s = lines[0]
                patt = re.compile(
                    r"(?:akun\d+|\d+)\|0x[0-9a-fA-F]{40}\|[0-9a-fA-F]{64}"
                )
                found = patt.findall(s)
                if found:
                    return found
                parts = re.split(r"(?=akun\d+\|)", s)
                cleaned = [p.strip() for p in parts if p.strip()]
                if cleaned:
                    return cleaned
            return lines

        def parse_for_account(lines, acct_idx):
            if acct_idx is None:
                keys = ["akun0", "0"]
            else:
                try:
                    ai = int(acct_idx)
                    keys = [f"akun{ai}", str(ai)]
                except Exception:
                    keys = [f"akun{acct_idx}", str(acct_idx)]

            out = []
            for ln in lines:
                parts = ln.split("|")
                if len(parts) < 3:
                    continue
                idx = parts[0].strip()
                nid = parts[1].strip()
                sig = parts[2].strip()
                if not nid or not sig:
                    continue
                if not nid.startswith("0x") and re.fullmatch(r"[0-9a-fA-F]{40}", nid):
                    nid = "0x" + nid
                if idx in keys:
                    out.append({"node_id": nid, "signature": sig, "line": ln})
            return out

        def get_ua_from_headers_or_fallback():
            try:
                hdrs = getattr(self, "HEADERS", {}) or {}
                ua = hdrs.get("user-agent") or hdrs.get("User-Agent")
                if ua and not isinstance(ua, str):
                    ua = str(ua)
                if not ua:
                    try:
                        ua_applied, _ = self.rotate_proxy_and_ua(
                            force_new_proxy=False, quick_test=False
                        )
                        if isinstance(ua_applied, str):
                            ua = ua_applied
                    except Exception:
                        pass
                if not ua:
                    try:
                        u = self.get_ua()
                        if u is not None:
                            ua = str(u)
                    except Exception:
                        ua = None
                if not ua:
                    ua = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{random.randint(120,150)}.0.{random.randint(1000,9999)}.{random.randint(0,9999)} Safari/537.36"
                return ua
            except Exception:
                return "Mozilla/5.0"

        def make_random_create_payload():
            ua = get_ua_from_headers_or_fallback()
            platforms = [
                ("Win32", ["1366x768", "1440x900", "1920x1080"]),
                ("Win64", ["1366x768", "1920x1080", "1600x900"]),
                ("MacIntel", ["1440x900", "1536x864", "2560x1440"]),
                ("Linux x86_64", ["1366x768", "1920x1080"]),
                ("Android", ["360x800", "412x915", "412x892"]),
                ("iPhone", ["390x844", "428x926"]),
            ]
            platform, reslist = random.choice(platforms)
            screen_resolution = random.choice(reslist)
            browser_family = random.choice(["Chrome", "Edge", "Firefox", "Safari"])
            if browser_family in ("Chrome", "Edge"):
                app_version = f"{browser_family} {random.randint(120,150)}.0.{random.randint(1000,9999)}.{random.randint(0,9999)}"
            elif browser_family == "Firefox":
                app_version = f"Firefox/{random.randint(100,130)}.0"
            else:
                app_version = f"Safari/{random.randint(14,18)}.0.{random.randint(1,50)}"

            def webgl():
                gpu = random.choice(
                    [
                        "Intel(R) UHD Graphics",
                        "Intel(R) Iris Xe Graphics",
                        "NVIDIA GeForce RTX 30",
                        "AMD Radeon RX 6xx",
                        "Apple M1",
                    ]
                )
                rn = random.randint(300, 1400)
                hx = random.randint(0x1000, 0xFFFF)
                return f"Google Inc. (Intel)-ANGLE (Intel, {gpu} {rn} (0x{hx:04x}))"

            payload = {
                "user_agent": ua,
                "language": random.choice(["id-ID", "en-US", "en-GB", "fr-FR"]),
                "screen_resolution": screen_resolution,
                "platform": platform,
                "app_version": app_version,
                "vendor": random.choice(["Google Inc.", "Apple Computer, Inc."]),
                "webgl_vendor": webgl(),
            }
            if random.random() < 0.35:
                payload["timezone"] = random.choice(
                    ["UTC+07:00", "UTC+01:00", "UTC-05:00", "UTC+09:00"]
                )
            if random.random() < 0.45:
                payload["device_id"] = str(uuid.uuid4())
            if random.random() < 0.55:
                payload["hardware_id"] = secrets.token_hex(16)
                payload["browser_fingerprint"] = secrets.token_hex(32)
            if random.random() < 0.25:
                name_user = f"user{random.randint(1000,99999)}@gmail.com"
                payload["node_name"] = f"{name_user} Node"
            return payload

        # ---- start ----
        self.log(
            "⛏️ Phase: Starting mining (activate-only, ext-only source)...", Fore.GREEN
        )

        # read and parse extension.txt
        acct_idx = getattr(self, "index_account", None)
        raw = safe_read(EXT_FILE)
        lines = repair_concat_and_split(raw)
        account_entries = parse_for_account(lines, acct_idx)

        # dedupe preserving order
        seen = set()
        uniq_entries = []
        for e in account_entries:
            nid = e.get("node_id")
            if nid and nid not in seen:
                seen.add(nid)
                uniq_entries.append(e)
        account_entries = uniq_entries

        self.log(
            f"🔍 Found {len(account_entries)} entry(ies) in {EXT_FILE} for account index {acct_idx}",
            Fore.CYAN,
        )

        # node_per_account
        cfg = getattr(self, "config", {}) or {}
        try:
            node_per_account = int(cfg.get("node_per_account", 1) or 1)
        except Exception:
            node_per_account = 1
        node_per_account = max(1, node_per_account)
        self.log(f"🔢 node_per_account = {node_per_account}", Fore.CYAN)

        # create shortfall if needed
        shortfall = max(0, node_per_account - len(account_entries))
        created_lines = []
        if shortfall > 0:
            self.log(
                f"🔧 Need to create {shortfall} node(s) for account {acct_idx}",
                Fore.CYAN,
            )
            acct_label = None
            try:
                acct_label = f"akun{int(acct_idx)}" if acct_idx is not None else "akun0"
            except Exception:
                acct_label = f"akun{acct_idx}" if acct_idx is not None else "akun0"

            attempts = 0
            max_attempts = shortfall * DEFAULT_CREATE_TRIES
            while shortfall > 0 and attempts < max_attempts:
                attempts += 1
                payload = make_random_create_payload()
                hdrs = dict(getattr(self, "HEADERS", {}) or {})
                hdrs.update(
                    {
                        "origin": "chrome-extension://hnhcbcjlbklgapodaeinagopcjmfkbak",
                        "content-type": "application/json",
                        "accept": "application/json, text/plain, */*",
                        "accept-encoding": "gzip, deflate, br, zstd",
                        "user-agent": str(payload.get("user_agent"))
                        or get_ua_from_headers_or_fallback(),
                    }
                )

                created_ok = False
                for use_proxy in (False, True):
                    try:
                        if not use_proxy:
                            self.log(
                                f"📡 Create node try (no-proxy) attempt {attempts}",
                                Fore.CYAN,
                            )
                            resp_obj, resp_data = self._request(
                                "POST",
                                "public/v1/mining/nodes",
                                headers=hdrs,
                                json_data=payload,
                                timeout=DEFAULT_TIMEOUT,
                                parse=True,
                                retries=1,
                                allow_proxy=False,
                            )
                        else:
                            try:
                                ua_applied, _ = self.rotate_proxy_and_ua(
                                    force_new_proxy=True, quick_test=True
                                )
                                if isinstance(ua_applied, str):
                                    payload["user_agent"] = ua_applied
                                    hdrs["user-agent"] = ua_applied
                            except Exception:
                                pass
                            self.log(
                                f"📡 Create node try (with-proxy) attempt {attempts}",
                                Fore.CYAN,
                            )
                            resp_obj, resp_data = self._request(
                                "POST",
                                "public/v1/mining/nodes",
                                headers=hdrs,
                                json_data=payload,
                                timeout=DEFAULT_TIMEOUT,
                                parse=True,
                                retries=2,
                                backoff=0.5,
                                allow_proxy=True,
                            )

                        if isinstance(resp_data, dict):
                            nid = resp_data.get("node_id_hash") or (
                                resp_data.get("results") or {}
                            ).get("node_id_hash")
                            sig = resp_data.get("signature") or (
                                resp_data.get("results") or {}
                            ).get("signature")
                            if nid and sig:
                                line = f"{acct_label}|{nid}|{sig}"
                                created_lines.append(line)
                                account_entries.append(
                                    {"node_id": nid, "signature": sig, "line": line}
                                )
                                self.log(f"✅ Node created: {nid}", Fore.GREEN)
                                shortfall -= 1
                                created_ok = True
                                break
                            if resp_data.get("is_existing"):
                                nid = resp_data.get("node_id_hash") or (
                                    resp_data.get("results") or {}
                                ).get("node_id_hash")
                                sig = resp_data.get("signature") or (
                                    resp_data.get("results") or {}
                                ).get("signature")
                                if nid and sig:
                                    line = f"{acct_label}|{nid}|{sig}"
                                    created_lines.append(line)
                                    account_entries.append(
                                        {"node_id": nid, "signature": sig, "line": line}
                                    )
                                    self.log(
                                        f"ℹ️ Existing node captured: {nid}", Fore.CYAN
                                    )
                                    shortfall -= 1
                                    created_ok = True
                                    break
                            self.log(
                                f"⚠️ Create returned unexpected JSON: {resp_data}",
                                Fore.YELLOW,
                            )
                        else:
                            self.log(
                                "⚠️ Create returned non-dict/empty response", Fore.YELLOW
                            )
                    except requests.exceptions.RequestException as cre:
                        resp = getattr(cre, "response", None)
                        if resp is not None:
                            try:
                                txt = getattr(resp, "text", "") or ""
                                self.log(
                                    f"⚠️ Create request HTTP error {getattr(resp,'status_code','?')}: {txt[:300]}",
                                    Fore.YELLOW,
                                )
                            except Exception:
                                self.log(
                                    f"⚠️ Create request HTTP error: {cre}", Fore.YELLOW
                                )
                        else:
                            self.log(f"⚠️ Create request error: {cre}", Fore.YELLOW)
                    except Exception as e:
                        self.log(
                            f"❌ Unexpected error during create attempt: {e}", Fore.RED
                        )
                    time.sleep(0.12)

                if not created_ok:
                    time.sleep(0.25)

            if created_lines:
                safe_append_lines(EXT_FILE, created_lines)
                raw = safe_read(EXT_FILE)
                lines = repair_concat_and_split(raw)
                account_entries = parse_for_account(lines, acct_idx)
                seen = set()
                uniq_entries = []
                for e in account_entries:
                    nid = e.get("node_id")
                    if nid and nid not in seen:
                        seen.add(nid)
                        uniq_entries.append(e)
                account_entries = uniq_entries

        # 4) For each entry: check status; if not active -> activate (NO deactivate)
        self.log(
            f"🔍 Post-create we have {len(account_entries)} entries; checking statuses and activating where needed",
            Fore.CYAN,
        )
        for e in account_entries:
            nid = e.get("node_id")
            sig = e.get("signature")
            if not nid or not sig:
                self.log(f"⚠️ Skipping malformed entry: {e}", Fore.YELLOW)
                continue

            is_active = False
            try:
                _, node_data = self._request(
                    "GET",
                    f"public/v1/mining/nodes/{nid}",
                    timeout=DEFAULT_TIMEOUT,
                    parse=True,
                    retries=1,
                )
                if isinstance(node_data, dict):
                    status = (
                        node_data.get("status_display")
                        or (node_data.get("results") or {}).get("status_display")
                        or node_data.get("current_status")
                    )
                    if status and str(status).lower() == "active":
                        is_active = True
            except Exception:
                is_active = False

            if is_active:
                self.log(
                    f"✅ Node {nid} already active -> skipping activation.", Fore.GREEN
                )
                continue

            # attempt activate (no deactivate step)
            try:
                try:
                    ua_applied, proxy_applied = self.rotate_proxy_and_ua(
                        force_new_proxy=True, quick_test=True
                    )
                except Exception:
                    ua_applied, proxy_applied = (None, getattr(self, "proxy", None))

                ua_header = (
                    self.HEADERS.get("user-agent") or get_ua_from_headers_or_fallback()
                )
                if isinstance(ua_applied, str):
                    ua_header = ua_applied

                activate_payload = {
                    "signature": sig,
                    "extension_version": getattr(self, "extension_version", "1.1.12"),
                    "user_agent": str(ua_header),
                    "language": random.choice(["id-ID", "en-US", "en-GB"]),
                    "screen_resolution": random.choice(
                        ["1366x768", "1920x1080", "1536x864"]
                    ),
                    "platform": random.choice(
                        ["Win32", "Win64", "MacIntel", "Linux x86_64"]
                    ),
                    "app_version": str(ua_header),
                    "vendor": random.choice(["Google Inc.", "Apple Computer, Inc."]),
                    "webgl_vendor": f"Google Inc. (Intel)-ANGLE (Intel, Intel(R) UHD Graphics {random.randint(300,999)} (0x{random.randint(1000,9999):04x}))",
                }
                if random.random() < 0.28:
                    activate_payload["timezone"] = random.choice(
                        ["UTC+07:00", "UTC+01:00", "UTC-05:00"]
                    )
                if random.random() < 0.22:
                    activate_payload["device_id"] = str(uuid.uuid4())
                if random.random() < 0.15:
                    activate_payload["screen_resolution"] = random.choice(
                        ["1440x900", "1600x900", "1366x768"]
                    )

                self.log(
                    f"➡️ Activating node {nid} (sig: {sig[:8]}..., proxy: {getattr(self,'proxy',None) or 'local'})",
                    Fore.CYAN,
                )
                try:
                    resp_obj, resp_data = self._request(
                        "POST",
                        f"public/v1/mining/nodes/{nid}/activate",
                        json_data=activate_payload,
                        timeout=DEFAULT_TIMEOUT,
                        parse=True,
                        retries=2,
                        backoff=0.5,
                    )
                    if isinstance(resp_data, dict) and resp_data.get("success"):
                        self.log(
                            f"🎉 Activate OK for {nid}: {resp_data.get('message','Activated')}",
                            Fore.GREEN,
                        )
                    else:
                        self.log(
                            f"❌ Activate non-success for {nid}: {resp_data}", Fore.RED
                        )
                except requests.exceptions.RequestException as are:
                    resp = getattr(are, "response", None)
                    if resp is not None:
                        txt = getattr(resp, "text", "") or ""
                        try:
                            j = resp.json()
                        except Exception:
                            j = None
                        if j and (j.get("current_status") or "").lower() == "active":
                            self.log(
                                f"ℹ️ Server says {nid} already active -> skipping.",
                                Fore.CYAN,
                            )
                        else:
                            self.log(
                                f"❌ HTTP error activating {nid}: {getattr(resp,'status_code','?')} {txt[:300]}",
                                Fore.RED,
                            )
                    else:
                        self.log(f"❌ Request error activating {nid}: {are}", Fore.RED)
            except Exception as e:
                self.log(f"❌ Unexpected error activating {nid}: {e}", Fore.RED)

            time.sleep(0.35)

        # cleanup locals (best-effort)
        for name in [
            "raw",
            "lines",
            "account_entries",
            "seen",
            "uniq_entries",
            "shortfall",
            "created_lines",
            "payload",
            "hdrs",
            "ua_applied",
            "proxy_applied",
            "activate_payload",
            "node_data",
            "resp_obj",
            "resp_data",
        ]:
            try:
                if name in locals():
                    del locals()[name]
            except Exception:
                pass

        self.log("✅ Mining flow finished.", Fore.GREEN)

    def load_proxies(self, filename="proxy.txt"):
        try:
            if not os.path.exists(filename):
                return []
            with open(filename, "r", encoding="utf-8") as file:
                proxies = list(
                    dict.fromkeys([line.strip() for line in file if line.strip()])
                )
            if not proxies:
                raise ValueError("Proxy file is empty.")
            return proxies
        except Exception as e:
            self.log(f"❌ Proxy load error: {e}", Fore.RED)
            return []

    def decode_response(self, response: object) -> object:
        if isinstance(response, str):
            try:
                return json.loads(response)
            except json.JSONDecodeError:
                return response

        content_encoding = getattr(response.headers, "get", lambda k, d=None: d)(
            "Content-Encoding", ""
        ).lower()
        data = response.content
        try:
            if content_encoding == "gzip":
                data = gzip.decompress(data)
            elif content_encoding in ["br", "brotli"]:
                data = brotli.decompress(data)
            elif content_encoding in ["deflate", "zlib"]:
                data = zlib.decompress(data)
        except Exception:
            pass

        content_type = getattr(response.headers, "get", lambda k, d=None: d)(
            "Content-Type", ""
        ).lower()
        charset = "utf-8"
        if "charset=" in content_type:
            charset = content_type.split("charset=")[-1].split(";")[0].strip()

        try:
            text = data.decode(charset)
        except Exception:
            detected = chardet.detect(data)
            text = data.decode(detected.get("encoding", "utf-8"), errors="replace")

        stripped = text.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                pass
        return text

    def prepare_session(self) -> None:
        try:
            if self.config.get("proxy") and not getattr(self, "proxy_manager", None):
                try:
                    # buat proxy manager yang mengetes langsung ke target (lebih relevan)
                    self.proxy_manager = ProxyManager(
                        self.proxy_list or [], test_url=self.BASE_URL, test_timeout=4.0
                    )
                except Exception:
                    self.proxy_manager = None
        except Exception:
            pass

        class TimeoutHTTPAdapter(HTTPAdapter):
            def __init__(self, *args, **kwargs):
                self.timeout = kwargs.pop("timeout", 10)
                super().__init__(*args, **kwargs)

            def send(self, request, **kwargs):
                kwargs["timeout"] = kwargs.get("timeout", self.timeout)
                return super().send(request, **kwargs)

        session = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            raise_on_status=False,
        )
        adapter = TimeoutHTTPAdapter(max_retries=retries, timeout=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        try:
            ua = self.get_ua()
            headers = (
                {**self.HEADERS, "User-Agent": ua.random} if ua else {**self.HEADERS}
            )
            session.headers.update(headers)
        except Exception as e:
            self.log(f"⚠️ UA warning: {e}", Fore.YELLOW)

        self.proxy = None

        if self.config.get("proxy") and self.proxy_manager:
            tried_proxies = set()
            total_proxies = len(self.proxy_list)
            result = {"proxy": None}

            def test_proxy(proxy: str):
                if result["proxy"]:
                    return
                test_sess = requests.Session()
                test_sess.headers.update(session.headers)
                test_sess.proxies = {"http": proxy, "https": proxy}
                try:
                    resp = test_sess.get("https://httpbin.org/ip", timeout=5)
                    resp.raise_for_status()
                    ip = resp.json().get("origin", "Unknown")
                    if not result["proxy"]:
                        result["proxy"] = proxy
                        self.log(f"✅ Proxy ok: {proxy}", Fore.GREEN)
                        time.sleep(0.5)
                except Exception:
                    pass

            threads = []
            shuffled_proxies = self.proxy_list[:]
            random.shuffle(shuffled_proxies)
            proxy_iter = iter(shuffled_proxies)

            while not result["proxy"] and len(tried_proxies) < total_proxies:
                threads.clear()
                for _ in range(2):
                    try:
                        proxy = next(proxy_iter)
                        if proxy in tried_proxies:
                            continue
                        tried_proxies.add(proxy)
                        t = threading.Thread(target=test_proxy, args=(proxy,))
                        threads.append(t)
                        t.start()
                    except StopIteration:
                        break
                for t in threads:
                    t.join()

            if result["proxy"]:
                session.proxies = {"http": result["proxy"], "https": result["proxy"]}
                self.proxy = result["proxy"]
                self._proxy_use_count = 0
            else:
                if not self._suppress_local_session_log:
                    self.log("⚠️ No working proxy, using local", Fore.YELLOW)
                session.proxies = {}
        else:
            session.proxies = {}
            # Only log local-ip style message for main instance (not worker silent instances)
            if not self._suppress_local_session_log:
                self.log("🌐 Using local IP (no proxy)", Fore.YELLOW)

        self.session = session

    def close(self):
        try:
            if hasattr(self, "session") and self.session:
                try:
                    self.session.close()
                except Exception:
                    pass
                self.session = None
        finally:
            self.proxy = None
            if hasattr(self, "proxy_list"):
                self.proxy_list = []


# tasks_config global so operator or config can override
# emojis glued to labels for user-friendly display
tasks_config = {"mining": "Auto mining point"}


async def process_account(account, original_index, account_label, blu: iflux):
    display_account = account[:12] + "..." if len(account) > 12 else account
    blu.log(f"👤 {account_label}: {display_account}", Fore.YELLOW)

    # reload config per-account so changes apply immediately (silent to avoid log spam)
    try:
        blu.config = blu.load_config(suppress_log=True)
    except Exception:
        blu.config = blu.config or {}

    if blu.config.get("proxy") and not getattr(blu, "proxy_manager", None):
        try:
            blu.proxy_manager = ProxyManager(blu.proxy_list or [])
        except Exception:
            blu.proxy_manager = None

    # ensure this blu instance uses the given account as its query source:
    await run_in_thread(blu.login, original_index)

    # show enabled tasks in one line
    cfg = blu.config or {}
    enabled = [name for key, name in tasks_config.items() if cfg.get(key, False)]
    if enabled:
        blu.log("🛠️ Tasks enabled: " + ", ".join(enabled), Fore.CYAN)
    else:
        blu.log("🛠️ Tasks enabled: (none)", Fore.RED)

    # run tasks (they will log their own phase details)
    for task_key, task_name in tasks_config.items():
        task_status = cfg.get(task_key, False)
        if task_status:
            if not hasattr(blu, task_key) or not callable(getattr(blu, task_key)):
                blu.log(f"⚠️ {task_key} missing", Fore.YELLOW)
                continue
            try:
                await run_in_thread(getattr(blu, task_key))
            except Exception as e:
                blu.log(f"❌ {task_key} error: {e}", Fore.RED)

    delay_switch = cfg.get("delay_account_switch", 10)
    blu.log(f"➡️ Done {account_label}. wait {delay_switch}s", Fore.CYAN)
    await asyncio.sleep(delay_switch)

    if blu.config.get("proxy") and getattr(blu, "proxy_manager", None) and blu.proxy:
        try:
            blu.proxy_manager.release_proxy(blu.proxy)
            blu.log(f"🔁 Proxy released", Fore.GREEN)
        except Exception as e:
            blu.log(f"⚠️ release proxy failed", Fore.YELLOW)
        finally:
            blu.proxy = None


# ---------- producer & worker (streaming tail + once) ----------
async def stream_producer(
    file_path: str,
    queue: asyncio.Queue,
    stop_event: asyncio.Event,
    base_blu: iflux,
    poll_interval=0.8,
    dedupe=True,
):
    idx = 0
    seen = BoundedSet(maxlen=10000) if dedupe else None

    f = None
    inode = None
    first_open = True

    def handle_cmd(line: str):
        cmd = line[len("__CMD__") :].strip()
        if cmd.upper().startswith("SET "):
            body = cmd[4:].split("=", 1)
            if len(body) == 2:
                k, v = body[0].strip(), body[1].strip()
                if v.lower() in ("true", "false"):
                    parsed = v.lower() == "true"
                else:
                    try:
                        parsed = int(v)
                    except:
                        try:
                            parsed = float(v)
                        except:
                            parsed = v
                base_blu.config[k] = parsed
                base_blu.log(f"⚙️ set {k}={parsed}", Fore.CYAN)
        elif cmd.upper() == "RELOAD_CONFIG":
            base_blu.config = base_blu.load_config()
            base_blu.log("🔁 reload config", Fore.CYAN)
        elif cmd.upper() == "SHUTDOWN":
            stop_event.set()
            base_blu.log("⛔ shutdown", Fore.MAGENTA)
        else:
            base_blu.log(f"⚠️ unknown cmd: {cmd}", Fore.YELLOW)

    while not stop_event.is_set():
        if f is None:
            try:
                f = open(file_path, "r", encoding="utf-8")
                try:
                    inode = os.fstat(f.fileno()).st_ino
                except Exception:
                    inode = None

                # first open: ingest existing content then switch to tail mode
                if first_open:
                    first_open = False
                    f.seek(0)
                    for line in f:
                        line = line.strip()
                        if not line:
                            idx += 1
                            continue
                        if line.startswith("__CMD__"):
                            try:
                                handle_cmd(line)
                            except Exception:
                                base_blu.log("❌ cmd error", Fore.RED)
                            idx += 1
                            continue
                        if seen is not None:
                            if line in seen:
                                idx += 1
                                continue
                            seen.add(line)
                        await queue.put((idx, line))
                        idx += 1
                    # go to end for tailing new lines
                    f.seek(0, os.SEEK_END)
                else:
                    f.seek(0, os.SEEK_END)
            except FileNotFoundError:
                await asyncio.sleep(poll_interval)
                continue

        line = f.readline()
        if not line:
            await asyncio.sleep(poll_interval)
            try:
                st = os.stat(file_path)
                if inode is not None and st.st_ino != inode:
                    try:
                        f.close()
                    except:
                        pass
                    f = open(file_path, "r", encoding="utf-8")
                    inode = os.fstat(f.fileno()).st_ino
                    f.seek(0, os.SEEK_END)
                else:
                    if f.tell() > st.st_size:
                        f.seek(0, os.SEEK_END)
            except FileNotFoundError:
                try:
                    if f:
                        f.close()
                except:
                    pass
                f = None
                inode = None
            continue

        line = line.strip()
        if not line:
            continue

        if line.startswith("__CMD__"):
            try:
                handle_cmd(line)
            except Exception:
                base_blu.log("❌ cmd error", Fore.RED)
            continue

        if seen is not None:
            if line in seen:
                continue
            seen.add(line)

        await queue.put((idx, line))
        idx += 1

    try:
        if f:
            f.close()
    except:
        pass


async def once_producer(file_path: str, queue: asyncio.Queue):
    idx = 0
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    idx += 1
                    continue
                if line.startswith("__CMD__"):
                    idx += 1
                    continue
                await queue.put((idx, line))
                idx += 1
    except FileNotFoundError:
        return


# track outstanding to_thread tasks so we can await them before exiting
_BG_THREAD_TASKS: set = set()


async def run_in_thread(fn, *args, **kwargs):
    """
    Wrapper around asyncio.to_thread that registers the created task into
    _BG_THREAD_TASKS so main dapat menunggu semua background threads finish.
    Use this instead of direct asyncio.to_thread(...) for long-running background ops.
    """
    coro = asyncio.to_thread(fn, *args, **kwargs)
    task = asyncio.create_task(coro)
    _BG_THREAD_TASKS.add(task)
    try:
        return await task
    finally:
        _BG_THREAD_TASKS.discard(task)


async def worker(worker_id: int, base_blu: iflux, queue: asyncio.Queue):
    # create worker blu WITHOUT initial config load to avoid duplicate config logs.
    blu = iflux(
        use_proxy=base_blu.config.get("proxy", False),
        proxy_list=base_blu.proxy_list,
        load_on_init=False,
    )
    try:
        blu.query_list = list(base_blu.query_list)
    except Exception:
        blu.query_list = []
    blu.log(f"👷 Worker-{worker_id} started", Fore.CYAN)

    while True:
        try:
            original_index, account = await queue.get()
        except asyncio.CancelledError:
            break

        account_label = f"W{worker_id}-A{original_index+1}"
        blu.index_account = original_index + 1
        try:
            await process_account(account, original_index, account_label, blu)
        except Exception as e:
            blu.log(f"❌ {account_label} error: {e}", Fore.RED)
        finally:
            try:
                queue.task_done()
            except Exception:
                pass

    await run_in_thread(blu.close)
    base_blu.log(f"🧾 Worker-{worker_id} stopped", Fore.CYAN)


# ---------- AUTOTUNE (respect 'thread' manual) ----------


def estimate_network_latency(host="1.1.1.1", port=53, attempts=2, timeout=0.6):
    latencies = []
    for _ in range(attempts):
        try:
            t0 = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((host, port))
            s.close()
            latencies.append(time.time() - t0)
        except Exception:
            latencies.append(timeout)
    try:
        return statistics.median(latencies)
    except:
        return timeout


def auto_tune_config_respecting_thread(
    existing_cfg: dict | None = None, prefer_network_check: bool = True
) -> dict:
    cfg = dict(existing_cfg or {})

    try:
        phys = psutil.cpu_count(logical=False) or 1
        logical = psutil.cpu_count(logical=True) or phys
    except:
        phys = logical = 1
    try:
        total_mem_gb = psutil.virtual_memory().total / (1024**3)
    except:
        total_mem_gb = 1.0
    try:
        disk_free_gb = shutil.disk_usage(os.getcwd()).free / (1024**3)
    except:
        disk_free_gb = 1.0

    net_lat = estimate_network_latency() if prefer_network_check else 1.0

    user_thread = cfg.get("thread", None)
    if user_thread is None:
        if logical >= 8:
            rec_thread = min(32, logical * 2)
        else:
            rec_thread = max(1, logical)
    else:
        rec_thread = int(user_thread)

    if total_mem_gb < 1.0:
        per_t = 20
    elif total_mem_gb < 2.5:
        per_t = 75
    elif total_mem_gb < 8:
        per_t = 200
    else:
        per_t = 1000
    q_recommend = int(min(max(50, rec_thread * per_t), 1000))  # cap 1000

    if total_mem_gb < 1 or phys <= 1:
        poll = 1.0
    elif net_lat < 0.05:
        poll = 0.2
    elif net_lat < 0.2:
        poll = 0.5
    else:
        poll = 0.8

    dedupe = bool(total_mem_gb < 2.0)
    run_mode = cfg.get("run_mode", "continuous")

    merged = dict(cfg)
    if "queue_maxsize" not in merged:
        merged["queue_maxsize"] = q_recommend
    if "poll_interval" not in merged:
        merged["poll_interval"] = poll
    if "dedupe" not in merged:
        merged["dedupe"] = dedupe
    if "run_mode" not in merged:
        merged["run_mode"] = run_mode

    merged["_autotune_meta"] = {
        "phys_cores": int(phys),
        "logical_cores": int(logical),
        "total_mem_gb": round(total_mem_gb, 2),
        "disk_free_gb": round(disk_free_gb, 2),
        "net_latency_s": round(net_lat, 3),
        "queue_recommendation": int(q_recommend),
        "poll_recommendation": float(poll),
    }

    return merged


# ---------- DYNAMIC TUNER (non-thread) ----------
async def dynamic_tuner_nonthread(
    base_blu, queue: asyncio.Queue, stop_event: asyncio.Event, interval=6.0
):
    base_blu.log("🤖 Tuner started (non-thread)", Fore.CYAN)
    while not stop_event.is_set():
        try:
            cpu = psutil.cpu_percent(interval=None)
            qsize = queue.qsize() if queue is not None else 0
            cur_q = int(base_blu.config.get("queue_maxsize", 200))
            cur_poll = float(base_blu.config.get("poll_interval", 0.8))
            cur_dedupe = bool(base_blu.config.get("dedupe", True))

            cap = max(50, cur_q)
            if qsize > 0.8 * cap and cpu < 85:
                new_q = min(cur_q * 2, 10000)
            elif qsize < 0.2 * cap and cur_q > 100:
                new_q = max(int(cur_q / 2), 50)
            else:
                new_q = cur_q

            if cpu > 80:
                new_poll = min(cur_poll + 0.2, 2.0)
            elif cpu < 30 and qsize > 0.2 * cap:
                new_poll = max(cur_poll - 0.1, 0.1)
            else:
                new_poll = cur_poll

            vm = psutil.virtual_memory()
            if vm.available / (1024**2) < 200 and cur_dedupe:
                new_dedupe = False
            else:
                new_dedupe = cur_dedupe

            changed = []
            if new_q != cur_q:
                base_blu.config["queue_maxsize"] = int(new_q)
                changed.append(f"q:{cur_q}->{new_q}")
            if abs(new_poll - cur_poll) > 0.01:
                base_blu.config["poll_interval"] = float(round(new_poll, 3))
                changed.append(f"p:{cur_poll}->{round(new_poll,3)}")
            if new_dedupe != cur_dedupe:
                base_blu.config["dedupe"] = bool(new_dedupe)
                changed.append(f"d:{cur_dedupe}->{new_dedupe}")

            if changed:
                base_blu.log("🔧 Tuner: " + ", ".join(changed), Fore.MAGENTA)
        except Exception as e:
            base_blu.log(f"⚠️ tuner error", Fore.YELLOW)
        await asyncio.sleep(interval)
    base_blu.log("🤖 Tuner stopped", Fore.MAGENTA)


# ---------- producer (once) ----------
async def producer_once(file_path, queue: asyncio.Queue):
    idx = 0
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    idx += 1
                    continue
                if line.startswith("__CMD__"):
                    idx += 1
                    continue
                await queue.put((idx, line))
                idx += 1
    except FileNotFoundError:
        return


def cleanup_after_batch(base_blu, keep_refs: dict | None = None):
    """
    Best-effort cleanup between batches:
    - clear some caches/cached attributes on base_blu
    - run gc.collect()
    """
    try:
        # 1) tidy up any finished background tasks
        try:
            for t in list(_BG_THREAD_TASKS):
                if t.done():
                    _BG_THREAD_TASKS.discard(t)
        except Exception:
            pass

        # 2) clear session cookies (cheap)
        try:
            if getattr(base_blu, "session", None):
                try:
                    base_blu.session.cookies.clear()
                except Exception:
                    pass
        except Exception:
            pass

        # 3) drop common large attrs if present
        if keep_refs is None:
            keep_refs = {}

        for k in ("last_items", "promo_data", "last_shop", "items_data"):
            try:
                if hasattr(base_blu, k) and k not in keep_refs:
                    setattr(base_blu, k, None)
            except Exception:
                pass

        # 4) force GC
        try:
            gc.collect()
        except Exception:
            pass

        # 5) log small cleanup result
        try:
            base_blu.log(f"♻️ cleanup done | {memory_monitor()}", Fore.LIGHTBLACK_EX)
        except Exception:
            pass

    except Exception as e:
        try:
            base_blu.log(f"⚠️ cleanup error: {e}", Fore.YELLOW)
        except Exception:
            pass


# ---------- memory monitor ----------
def memory_monitor():
    try:
        p = psutil.Process()
        mem = p.memory_info().rss
        return f"RSS={mem/1024/1024:.2f} MB"
    except Exception:

        tracemalloc.start()
        s = tracemalloc.take_snapshot()
        total = sum([stat.size for stat in s.statistics("filename")])
        return f"tracemalloc_total={total/1024/1024:.2f} MB"


# ---------- main ----------
async def main():
    base_blu = iflux()  # main instance loads config normally
    cfg_file = base_blu.config

    # apply autotune for non-thread params but RESPECT user 'thread' if set
    effective = auto_tune_config_respecting_thread(cfg_file)

    # FORCE repeat mode in code (process all accounts each batch, then sleep -> repeat)
    run_mode = "repeat"

    # apply into base_blu.config
    base_blu.config = effective

    # concise welcome + nicer config/meta logs
    base_blu.log(
        f"🎉 [LIVEXORDS] === Welcome to {NAME_BOT} Automation === [LIVEXORDS]",
        Fore.YELLOW,
    )

    # Nicely format effective config
    cfg_summary = {
        "thread": int(effective.get("thread", 1)),
        "queue_maxsize": int(effective.get("queue_maxsize", 200)),
        "poll_interval": float(effective.get("poll_interval", 0.8)),
        "dedupe": bool(effective.get("dedupe", True)),
        "delay_loop": int(effective.get("delay_loop", 30)),
        "delay_account_switch": int(effective.get("delay_account_switch", 10)),
        "proxy": bool(effective.get("proxy", False)),
    }
    base_blu.log("")
    base_blu.log("🔧 Effective config:", Fore.CYAN)
    for k, v in cfg_summary.items():
        base_blu.log(f"    • {k:<20}: {v}", Fore.CYAN)

    base_blu.log("📊 Autotune metadata:", Fore.MAGENTA)
    meta = effective.get("_autotune_meta", {})
    for k, v in meta.items():
        base_blu.log(f"    • {k:<20}: {v}", Fore.MAGENTA)

    # core runtime variables (will be re-read each batch)
    query_file = effective.get("query_file", "query.txt")
    queue_maxsize = int(effective.get("queue_maxsize", 200))
    poll_interval = float(effective.get("poll_interval", 0.8))
    dedupe = bool(effective.get("dedupe", True))
    num_threads = int(effective.get("thread", 1))

    base_blu.banner()
    base_blu.log(f"📂 {query_file} | q={queue_maxsize} | mode={run_mode}", Fore.YELLOW)

    stop_event = asyncio.Event()

    # graceful signal handling (best-effort)
    try:
        loop = asyncio.get_running_loop()
        try:

            loop.add_signal_handler(signal.SIGINT, lambda: stop_event.set())
            loop.add_signal_handler(signal.SIGTERM, lambda: stop_event.set())
        except Exception:
            pass
    except Exception:
        pass

    while True:
        # reload queries at the start of each batch (silent to avoid log spam)
        try:
            base_blu.query_list = base_blu.load_query(
                base_blu.config.get("query_file", query_file)
            )
        except Exception:
            base_blu.query_list = base_blu.load_query(query_file)

        # create the real queue so tuner and workers observe same state
        queue = asyncio.Queue(maxsize=queue_maxsize)

        # start non-thread dynamic tuner (watching the real queue)
        tuner_task = asyncio.create_task(
            dynamic_tuner_nonthread(base_blu, queue, stop_event)
        )

        # use producer_once -> read the file once this batch and enqueue all entries
        prod_task = asyncio.create_task(producer_once(query_file, queue))

        # start workers (worker creates iflux(..., load_on_init=False) to avoid duplicate logs)
        workers = [
            asyncio.create_task(worker(i + 1, base_blu, queue))
            for i in range(num_threads)
        ]

        try:
            await prod_task
            await queue.join()
        except asyncio.CancelledError:
            pass

        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        # stop tuner for this batch
        tuner_task.cancel()
        try:
            await tuner_task
        except:
            pass

        # wait any outstanding background to_thread calls finish (if using run_in_thread)
        if _BG_THREAD_TASKS:
            base_blu.log(
                f"⏳ waiting for {len(_BG_THREAD_TASKS)} background thread(s) to finish...",
                Fore.CYAN,
            )
            await asyncio.gather(*list(_BG_THREAD_TASKS), return_exceptions=True)

        try:
            sys.stdout.flush()
        except Exception:
            pass

        # cleanup memory + drop refs
        try:
            cleanup_after_batch(base_blu)
        except Exception:
            pass

        # also release local references so GC can free them
        try:
            prod_task = None
            workers = None
            queue = None
        except Exception:
            pass

        base_blu.log("🔁 batch done", Fore.CYAN)
        base_blu.log(f"🧾 {memory_monitor()}", Fore.MAGENTA)

        # sleep then repeat (since run_mode == "repeat")
        delay_loop = int(effective.get("delay_loop", 30))
        base_blu.log(f"⏳ sleep {delay_loop}s before next batch", Fore.CYAN)
        for _ in range(delay_loop):
            if stop_event.is_set():
                break
            await asyncio.sleep(1)
        if stop_event.is_set():
            break

    # shutdown
    stop_event.set()
    base_blu.log("✅ shutdown", Fore.MAGENTA)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted by user. Exiting...")
