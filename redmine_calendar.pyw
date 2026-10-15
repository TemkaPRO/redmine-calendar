"""Redmine-календарь: задачи мои и команды, разложенные по срокам, с комментариями, сменой статуса и таймером.

Локальный сервер на 127.0.0.1 + окно Edge/Chrome в режиме приложения (без адресной строки).
Сервер сам ходит в Redmine, API-ключ в браузер не отдаётся. Закрыл окно — сервер завершился.

«Доступ с телефона» (включается в настройках) поднимает второй сервер на всех сетевых интерфейсах:
вход по PIN, сессия в cookie, защита от перебора. Пока он включён, программа работает в фоне без окна.

    pythonw redmine_calendar.pyw          — обычный режим
    python  redmine_calendar.pyw --demo   — выдуманные задачи, без Redmine
"""
import datetime as dt
import hashlib
import hmac
import json
import socket
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_ID = "redmine-calendar"
APP_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(APP_DIR, "web")
APPDATA = os.environ.get("APPDATA", os.path.expanduser("~"))
CONFIG_DIR = os.path.join(APPDATA, "RedmineCalendar")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
TIMER_PATH = os.path.join(CONFIG_DIR, "timer-demo.json" if "--demo" in sys.argv else "timer.json")
WINDOW_PROFILE = os.path.join(CONFIG_DIR, "window")
STARTUP_FILE = os.path.join(APPDATA, r"Microsoft\Windows\Start Menu\Programs\Startup", "RedmineCalendar.vbs")

PORT = int(os.environ.get("RC_PORT") or 47823)
DEMO = "--demo" in sys.argv
TOKEN = secrets.token_urlsafe(24)  # подставляется в страницу; без него API не отвечает

DEFAULT_CONFIG = {
    "url": "",
    "api_key": "",
    "refresh_min": 15,
    "verify_ssl": True,
    "workday_hours": 8,
    "team": [],  # [{"id": 123, "name": "И. И. Иванов", "project": {...}}]
    # доступ с телефона
    "remote_enabled": False,
    "remote_port": 47824,
    "pin_salt": "",
    "pin_hash": "",
    "secret": "",
    "sessions": [],  # [{"hash", "created", "last", "ua", "ip"}]
}

SESSION_TTL = 30 * 86400
CFG_LOCK = threading.Lock()
STATIC = {  # файлы без авторизации: иконки, манифест, service worker
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
    "/sw.js": ("sw.js", "text/javascript; charset=utf-8"),
    "/icon-192.png": ("icon-192.png", "image/png"),
    "/icon-512.png": ("icon-512.png", "image/png"),
    "/apple-touch-icon.png": ("icon-180.png", "image/png"),
}
CSP = ("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; manifest-src 'self'; worker-src 'self'; frame-ancestors 'none'")

PING_TIMEOUT = 180  # свёрнутое окно Chromium пингует раз в минуту, берём с запасом
BYE_GRACE = 4       # после закрытия вкладки ждём, вдруг это была перезагрузка


class Life:
    lock = threading.Lock()
    last_ping = time.monotonic()
    bye_at = None

    @classmethod
    def ping(cls):
        with cls.lock:
            cls.last_ping = time.monotonic()

    @classmethod
    def bye(cls):
        with cls.lock:
            cls.bye_at = time.monotonic()


# ---------------------------------------------------------------- конфиг, таймер

def load_config():
    cfg = dict(DEFAULT_CONFIG)
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg.update({k: v for k, v in json.load(f).items() if k in DEFAULT_CONFIG})
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def load_timer():
    try:
        with open(TIMER_PATH, encoding="utf-8") as f:
            t = json.load(f)
        return t if t.get("issue_id") and t.get("started") else None
    except (OSError, ValueError):
        return None


def save_timer(timer):
    if timer is None:
        if os.path.exists(TIMER_PATH):
            os.remove(TIMER_PATH)
        return
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(TIMER_PATH, "w", encoding="utf-8") as f:
        json.dump(timer, f, ensure_ascii=False)


def persist(cfg):
    if not DEMO:  # в демо ничего не пишем на диск — настоящий конфиг не трогаем
        save_config(cfg)


def hash_pin(pin, salt_hex):
    return hashlib.pbkdf2_hmac("sha256", pin.encode("utf-8"), bytes.fromhex(salt_hex), 200_000).hex()


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Guard:
    """Защита PIN от перебора: 5 ошибок с одного адреса за 15 минут или 30 ошибок за час всего — пауза."""
    lock = threading.Lock()
    by_ip = {}
    all_fails = []

    @classmethod
    def blocked(cls, ip):
        now = time.time()
        with cls.lock:
            cls.all_fails = [t for t in cls.all_fails if now - t < 3600]
            cls.by_ip[ip] = [t for t in cls.by_ip.get(ip, []) if now - t < 900]
            return len(cls.by_ip[ip]) >= 5 or len(cls.all_fails) >= 30

    @classmethod
    def fail(cls, ip):
        now = time.time()
        with cls.lock:
            cls.by_ip.setdefault(ip, []).append(now)
            cls.all_fails.append(now)

    @classmethod
    def success(cls, ip):
        with cls.lock:
            cls.by_ip.pop(ip, None)


def lan_addresses():
    """IPv4-адреса компьютера в локальных сетях — для подсказки «открой на телефоне …»."""
    out = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            out.add(info[4][0])
    except OSError:
        pass
    try:  # адрес интерфейса, через который идёт «наружу», — без реального подключения
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("10.255.255.255", 1))
            out.add(sock.getsockname()[0])
    except OSError:
        pass
    return sorted(a for a in out if not a.startswith(("127.", "169.254.")))


class RemoteServer:
    """Второй сервер для телефона. Запускается/останавливается по настройкам."""
    lock = threading.Lock()
    srv = None
    port = None
    error = None

    @classmethod
    def apply(cls, main):
        cfg = main.cfg
        want = bool(cfg.get("remote_enabled") and cfg.get("pin_hash"))
        port = int(cfg.get("remote_port") or 47824)
        with cls.lock:
            if cls.srv and (not want or cls.port != port):
                cls.srv.shutdown()
                cls.srv.server_close()
                cls.srv = None
            cls.error = None
            if want and not cls.srv:
                try:
                    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
                except OSError as e:
                    cls.error = f"Порт {port} занят или недоступен: {e}"
                    return cls.error
                srv.daemon_threads = True
                srv.remote = True
                srv.cfg, srv.demo, srv.timer_lock = main.cfg, main.demo, main.timer_lock
                threading.Thread(target=srv.serve_forever, daemon=True).start()
                cls.srv, cls.port = srv, port
        return None

    @classmethod
    def running(cls):
        return cls.srv is not None


def autostart_enabled():
    return os.path.exists(STARTUP_FILE)


def set_autostart(enabled):
    if not enabled:
        if os.path.exists(STARTUP_FILE):
            os.remove(STARTUP_FILE)
        return
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pyw):
        pyw = sys.executable
    # utf-16 с BOM — WSH так понимает кириллицу в путях
    with open(STARTUP_FILE, "w", encoding="utf-16") as f:
        f.write(f'CreateObject("WScript.Shell").Run """{pyw}"" ""{os.path.abspath(__file__)}"" --autostart", 0\n')


def normalize_url(url):
    url = (url or "").strip().rstrip("/")
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def clean_team(team):
    out, seen = [], set()
    for m in team if isinstance(team, list) else []:
        try:
            uid = int(m["id"])
        except (KeyError, TypeError, ValueError):
            continue
        if uid not in seen:
            seen.add(uid)
            item = {"id": uid, "name": str(m.get("name") or f"#{uid}")[:100]}
            proj = m.get("project")
            if isinstance(proj, dict) and str(proj.get("id", "")).isdigit():
                item["project"] = {"id": int(proj["id"]), "name": str(proj.get("name") or "")[:200]}
            out.append(item)
    return out


# ---------------------------------------------------------------- Redmine API

class RedmineError(Exception):
    def __init__(self, message, errors=None):
        super().__init__(message)
        self.errors = errors or []


BLANK_RE = re.compile(r"^(.+?)\s+(не может быть пуст\w*|cannot be blank)$", re.IGNORECASE)


def parse_custom_fields(body):
    out = []
    try:
        for c in body.get("custom_fields") or []:
            value = c["value"]
            out.append({"id": int(c["id"]),
                        "value": [str(v) for v in value] if isinstance(value, list) else str(value or "")})
    except (KeyError, TypeError) as e:
        raise ValueError("bad custom field") from e
    return out


def blank_fields(errors):
    """«Блок Системы не может быть пустым» → ["Блок Системы"]."""
    out = []
    for err in errors:
        m = BLANK_RE.match(str(err).strip())
        if m:
            out.append(m.group(1).strip(" «»\"'"))
    return out


def api_request(cfg, method, path, params=None, body=None, timeout=30):
    url = cfg["url"].rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"X-Redmine-API-Key": cfg["api_key"], "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    ctx = None if cfg.get("verify_ssl", True) else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            raw = r.read()
            return json.loads(raw) if raw.strip() else None
    except urllib.error.HTTPError as e:
        if e.code == 422:
            try:
                errors = json.load(e).get("errors") or []
            except ValueError:
                errors = []
            raise RedmineError("Redmine не принял изменения: " + "; ".join(errors) if errors
                               else "Redmine не принял изменения (422)", errors) from e
        if e.code == 401:
            raise RedmineError("Redmine не принял API-ключ (401)") from e
        if e.code == 403:
            raise RedmineError("Нет прав на это в Redmine (403)" if method != "GET"
                               else "Нет доступа (403): нет прав или в Redmine выключен REST API") from e
        if e.code == 404:
            raise RedmineError("Не найдено в Redmine (404)") from e
        raise RedmineError(f"Redmine ответил HTTP {e.code}") from e
    except urllib.error.URLError as e:
        if isinstance(e.reason, ssl.SSLError):
            raise RedmineError("Ошибка SSL-сертификата — попробуй выключить «Проверять SSL»") from e
        raise RedmineError(f"Нет связи с Redmine: {e.reason}") from e
    except (TimeoutError, OSError) as e:
        raise RedmineError(f"Нет связи с Redmine: {e}") from e
    except ValueError as e:
        raise RedmineError("Redmine вернул не JSON — проверь адрес") from e


def api_get(cfg, path, params=None, timeout=30):
    return api_request(cfg, "GET", path, params, timeout=timeout)


def api_download(cfg, attachment_id, limit=25 << 20):
    """Файл вложения: (байты, content-type). Redmine отдаёт его только с API-ключом, поэтому — через нас."""
    url = f"{cfg['url'].rstrip('/')}/attachments/download/{attachment_id}"
    req = urllib.request.Request(url, headers={"X-Redmine-API-Key": cfg["api_key"]})
    ctx = None if cfg.get("verify_ssl", True) else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=60, context=ctx) as r:
            data = r.read(limit + 1)
            if len(data) > limit:
                raise RedmineError("Файл больше 25 МБ — открой его в Redmine")
            return data, (r.headers.get("Content-Type") or "application/octet-stream").split(";")[0].strip()
    except urllib.error.HTTPError as e:
        raise RedmineError("Нет доступа к файлу" if e.code in (401, 403) else f"Redmine ответил HTTP {e.code}") from e
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise RedmineError(f"Нет связи с Redmine: {e}") from e


def parse_hours(raw):
    """«1:24», «1,5», «1.5» → часы; пусто → None; мусор → ValueError."""
    raw = str(raw if raw is not None else "").strip().replace(",", ".")
    if not raw:
        return None
    if ":" in raw:
        h, m = raw.split(":", 1)
        return round(int(h) + int(m) / 60, 4)
    return round(float(raw), 4)


_cache = {}
_cache_lock = threading.Lock()


def cached(key, ttl, fn):
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and now - hit[0] < ttl:
            return hit[1]
    value = fn()
    with _cache_lock:
        _cache[key] = (now, value)
    return value


def hm(hours):
    """Часы из Redmine («1.4») → «1:24»."""
    try:
        mins = round(float(hours) * 60)
    except (TypeError, ValueError):
        return "—"
    return f"{mins // 60}:{mins % 60:02d}"


def _name(obj):
    return (obj or {}).get("name", "")


def _ref(obj):
    return {"id": obj["id"], "name": obj.get("name", "")} if obj else None


def parse_issue(raw):
    return {
        "id": raw["id"],
        "subject": raw.get("subject", ""),
        "project": _name(raw.get("project")),
        "project_id": (raw.get("project") or {}).get("id"),
        "tracker": _name(raw.get("tracker")),
        "tracker_id": (raw.get("tracker") or {}).get("id"),
        "status": _name(raw.get("status")),
        "status_id": (raw.get("status") or {}).get("id"),
        "priority": _name(raw.get("priority")),
        "priority_id": (raw.get("priority") or {}).get("id", 0),
        "assignee": _ref(raw.get("assigned_to")),
        "due": raw.get("due_date"),
        "start": raw.get("start_date"),
        "est": raw.get("estimated_hours"),
        "done": raw.get("done_ratio", 0),
        "updated": raw.get("updated_on"),
    }


class RealBackend:
    """Всё общение с настоящим Redmine."""

    def __init__(self, cfg):
        self.cfg = cfg

    def _key(self, *parts):
        return (self.cfg["url"], *parts)

    def me(self):
        u = cached(self._key("me", self.cfg["api_key"]), 3600,
                   lambda: api_get(self.cfg, "/users/current.json")["user"])
        return {"id": u.get("id"), "firstname": u.get("firstname", ""), "lastname": u.get("lastname", "")}

    def issues(self, assignee_ids):
        """assignee_ids=None — мои задачи, иначе задачи перечисленных людей."""
        if assignee_ids is None:
            base = [("assigned_to_id", "me"), ("status_id", "open")]
        elif len(assignee_ids) == 1:
            base = [("assigned_to_id", str(assignee_ids[0])), ("status_id", "open")]
        else:
            base = [("f[]", "status_id"), ("op[status_id]", "o"),
                    ("f[]", "assigned_to_id"), ("op[assigned_to_id]", "=")]
            base += [("v[assigned_to_id][]", str(i)) for i in assignee_ids]
        out, offset = [], 0
        while True:
            q = base + [("sort", "due_date"), ("limit", "100"), ("offset", str(offset))]
            data = api_get(self.cfg, "/issues.json?" + urllib.parse.urlencode(q))
            out += [parse_issue(r) for r in data.get("issues", [])]
            offset += 100
            if offset >= data.get("total_count", 0) or not data.get("issues"):
                return out

    def _statuses(self):
        return cached(self._key("statuses"), 3600, lambda: {
            s["id"]: s["name"] for s in api_get(self.cfg, "/issue_statuses.json")["issue_statuses"]})

    def _trackers(self):
        def load():
            try:
                return {t["id"]: t["name"] for t in api_get(self.cfg, "/trackers.json")["trackers"]}
            except RedmineError:
                return {}
        return cached(self._key("trackers"), 3600, load)

    def _activities(self):
        def load():
            try:
                return api_get(self.cfg, "/enumerations/time_entry_activities.json")["time_entry_activities"]
            except RedmineError:
                return []
        return cached(self._key("activities"), 3600, load)

    def _project(self, pid):
        return cached(self._key("project", pid), 600, lambda: api_get(
            self.cfg, f"/projects/{pid}.json", {"include": "trackers,time_entry_activities"})["project"])

    def _members(self, pid):
        def load():
            out, offset = {}, 0
            try:
                while offset < 1000:
                    d = api_get(self.cfg, f"/projects/{pid}/memberships.json", {"limit": 100, "offset": offset})
                    for m in d.get("memberships", []):
                        who = m.get("user") or m.get("group")
                        if who:
                            out[who["id"]] = who["name"].strip() + (" (группа)" if "group" in m else "")
                    offset += 100
                    if offset >= d.get("total_count", 0) or not d.get("memberships"):
                        break
            except RedmineError:
                pass
            return out
        return cached(self._key("members", pid), 600, load)

    def user_name(self, uid):
        def load():
            try:
                u = api_get(self.cfg, f"/users/{uid}.json")["user"]
                return f"{u.get('firstname', '')} {u.get('lastname', '')}".strip() or f"#{uid}"
            except RedmineError:
                return f"#{uid}"
        return cached(self._key("user", uid), 3600, load)

    def _journals(self, journals, members):
        statuses, trackers = self._statuses(), self._trackers()

        def by_id(names, value):
            if value in (None, ""):
                return "—"
            try:
                return names.get(int(value)) or f"#{value}"
            except ValueError:
                return str(value)

        def person(value):
            if value in (None, ""):
                return "никто"
            uid = int(value)
            return members.get(uid) or self.user_name(uid)

        def day(value):
            return dt.date.fromisoformat(value).strftime("%d.%m.%Y") if value else "—"

        out = []
        for j in journals:
            changes = []
            for d in j.get("details", []):
                prop, name = d.get("property"), d.get("name")
                old, new = d.get("old_value"), d.get("new_value")
                if prop == "attr":
                    if name == "status_id":
                        changes.append(f"Статус: {by_id(statuses, old)} → {by_id(statuses, new)}")
                    elif name == "tracker_id":
                        changes.append(f"Трекер: {by_id(trackers, old)} → {by_id(trackers, new)}")
                    elif name == "assigned_to_id":
                        changes.append(f"Исполнитель: {person(old)} → {person(new)}")
                    elif name == "due_date":
                        changes.append(f"Срок: {day(old)} → {day(new)}")
                    elif name == "start_date":
                        changes.append(f"Дата начала: {day(old)} → {day(new)}")
                    elif name == "done_ratio":
                        changes.append(f"Готовность: {old or 0}% → {new or 0}%")
                    elif name == "estimated_hours":
                        changes.append(f"Оценка: {hm(old)} → {hm(new)}")
                    elif name == "description":
                        changes.append("Изменено описание")
                    elif name == "subject":
                        changes.append("Изменена тема")
                    elif name == "priority_id":
                        changes.append("Изменён приоритет")
                    elif name == "project_id":
                        changes.append("Задача перенесена в другой проект")
                    elif name == "parent_id":
                        changes.append("Изменена родительская задача")
                    else:
                        changes.append(f"Изменено поле «{name}»")
                elif prop == "attachment":
                    changes.append(f"Файл {'добавлен' if new else 'удалён'}: {new or old}")
                elif prop == "cf":
                    changes.append("Изменено дополнительное поле")
            notes = j.get("notes") or ""
            if notes or changes:
                out.append({
                    "id": j.get("id"),
                    "user": _name(j.get("user")),
                    "created": j.get("created_on"),
                    "notes": notes,
                    "private": bool(j.get("private_notes")),
                    "changes": changes,
                })
        return out

    def details(self, issue_id):
        raw = api_get(self.cfg, f"/issues/{issue_id}.json",
                      {"include": "journals,allowed_statuses,children,attachments"})["issue"]
        issue = parse_issue(raw)
        issue.update({
            "description": raw.get("description") or "",
            "author": _name(raw.get("author")),
            "created": raw.get("created_on"),
            "spent": raw.get("spent_hours") or raw.get("total_spent_hours"),
            "custom_fields": [{"id": c["id"], "name": c["name"], "value": c.get("value"),
                               "multiple": bool(c.get("multiple"))} for c in raw.get("custom_fields", [])],
        })
        pid = issue["project_id"]
        try:
            project = self._project(pid)
        except RedmineError:
            project = {}
        members = self._members(pid)

        def ensure(options, cur_id, cur_name):
            if cur_id and not any(o["id"] == cur_id for o in options):
                options.insert(0, {"id": cur_id, "name": cur_name})
            return options

        statuses = [{"id": s["id"], "name": s["name"]} for s in raw.get("allowed_statuses", [])]
        if not raw.get("allowed_statuses"):  # старый Redmine — даём весь список, лишнее он отклонит сам
            statuses = [{"id": k, "name": v} for k, v in self._statuses().items()]
        trackers = [{"id": t["id"], "name": t["name"]} for t in project.get("trackers", [])]
        assignees = sorted(({"id": k, "name": v} for k, v in members.items()), key=lambda m: m["name"])
        cur = issue["assignee"]

        global_acts = self._activities()
        default_act = next((a["id"] for a in global_acts if a.get("is_default")), None)
        acts = project.get("time_entry_activities") or [a for a in global_acts if a.get("active", True)]
        activities = [{"id": a["id"], "name": a["name"]} for a in acts]
        if default_act not in {a["id"] for a in activities}:
            default_act = activities[0]["id"] if activities else None

        issue["options"] = {
            "statuses": ensure(statuses, issue["status_id"], issue["status"]),
            "trackers": ensure(trackers, issue["tracker_id"], issue["tracker"]),
            "assignees": ensure(assignees, cur and cur["id"], cur and cur["name"]),
            "activities": activities,
            "default_activity": default_act,
        }
        issue["journals"] = self._journals(raw.get("journals", []), members)
        issue["children"] = self._children(raw.get("children", []))
        issue["parent"] = self._parent(raw.get("parent"))
        issue["attachments"] = [{"id": a["id"], "filename": a.get("filename", ""), "type": a.get("content_type") or "",
                                 "size": a.get("filesize") or 0, "description": a.get("description") or ""}
                                for a in raw.get("attachments", [])]
        return issue

    def attachment(self, attachment_id):
        return api_download(self.cfg, attachment_id)

    def priorities(self):
        return cached(self._key("priorities"), 3600, lambda: [
            {"id": p["id"], "name": p["name"], "default": bool(p.get("is_default"))}
            for p in api_get(self.cfg, "/enumerations/issue_priorities.json")["issue_priorities"]])

    def create(self, fields):
        r = api_request(self.cfg, "POST", "/issues.json", body={"issue": fields})
        return r["issue"]["id"]

    def _children(self, tree):
        """Дерево подзадач → плоский список с глубиной, статусом, исполнителем и сроком."""
        flat = []

        def walk(items, depth):
            for c in items:
                flat.append({"id": c["id"], "subject": c.get("subject", ""), "tracker": _name(c.get("tracker")),
                             "depth": depth, "status": "", "closed": None, "assignee": None, "due": None, "done": 0})
                walk(c.get("children", []), depth + 1)

        walk(tree, 0)
        if not flat:
            return []
        info = {}
        ids = [c["id"] for c in flat]
        for n in range(0, len(ids), 100):
            try:
                d = api_get(self.cfg, "/issues.json", {"issue_id": ",".join(map(str, ids[n:n + 100])),
                                                       "status_id": "*", "limit": 100})
                info.update({i["id"]: i for i in d.get("issues", [])})
            except RedmineError:
                pass
        # что не пришло списком (бывает с задачами из других проектов) — добираем по одной, но без фанатизма
        for cid in [c for c in ids if c not in info][:20]:
            try:
                info[cid] = api_get(self.cfg, f"/issues/{cid}.json")["issue"]
            except RedmineError:
                pass
        for c in flat:
            i = info.get(c["id"])
            if i:
                c.update({"status": _name(i.get("status")), "closed": bool((i.get("status") or {}).get("is_closed")),
                          "assignee": _ref(i.get("assigned_to")), "due": i.get("due_date"),
                          "done": i.get("done_ratio", 0)})
        return flat

    def _parent(self, ref):
        if not ref:
            return None
        try:
            i = api_get(self.cfg, f"/issues/{ref['id']}.json")["issue"]
            return {"id": i["id"], "subject": i.get("subject", ""), "status": _name(i.get("status"))}
        except RedmineError:
            return {"id": ref["id"], "subject": "", "status": ""}

    def update(self, issue_id, fields):
        api_request(self.cfg, "PUT", f"/issues/{issue_id}.json", body={"issue": fields})

    def log_time(self, issue_id, hours, activity_id, comments, spent_on):
        entry = {"issue_id": issue_id, "hours": hours, "comments": comments, "spent_on": spent_on}
        if activity_id:
            entry["activity_id"] = activity_id
        api_request(self.cfg, "POST", "/time_entries.json", body={"time_entry": entry})

    def candidates(self):
        def load():
            me_id = self.me()["id"]
            counts, names = {}, {}

            def add(person, weight):
                if person and person["id"] != me_id:
                    counts[person["id"]] = counts.get(person["id"], 0) + weight
                    names[person["id"]] = person["name"].strip()

            def scan(params, limit, fn):
                offset = 0
                while offset < limit:
                    d = api_get(self.cfg, "/issues.json", {**params, "status_id": "*", "sort": "updated_on:desc",
                                                           "limit": 100, "offset": offset})
                    for i in d.get("issues", []):
                        fn(i)
                    offset += 100
                    if offset >= d.get("total_count", 0):
                        break

            # те, кому я ставлю задачи или за чьими задачами слежу, — наверх списка
            for flt in ({"author_id": "me"}, {"watcher_id": "me"}):
                scan(flt, 300, lambda i: add(i.get("assigned_to"), 1))
            # плюс все, кто мелькал в недавно обновлённых задачах, — чтобы находились и люди без общих задач
            scan({}, 500, lambda i: (add(i.get("assigned_to"), 0), add(i.get("author"), 0)))
            order = sorted(names, key=lambda uid: (-counts[uid], names[uid]))
            return [{"id": uid, "name": names[uid], "count": counts[uid]} for uid in order]
        return cached(self._key("candidates"), 3600, load)

    def projects(self):
        """Проекты, где у меня есть роль, — куда вообще можно переносить задачи."""
        def load():
            me = api_get(self.cfg, "/users/current.json", {"include": "memberships"})["user"]
            seen = {m["project"]["id"]: m["project"]["name"].strip() for m in me.get("memberships", [])}
            return sorted(({"id": k, "name": v} for k, v in seen.items()), key=lambda p: p["name"].lower())
        return cached(self._key("projects"), 3600, load)

    def project_options(self, pid):
        project = self._project(pid)
        members = self._members(pid)
        return {
            "id": pid,
            "name": project.get("name", ""),
            "trackers": [{"id": t["id"], "name": t["name"]} for t in project.get("trackers", [])],
            "assignees": sorted(({"id": k, "name": v} for k, v in members.items()), key=lambda m: m["name"]),
        }

    def cf_values(self, cf_id, seed=()):
        """Известные значения доп. поля — по задачам, которые мне видны (список значений отдаёт только админу)."""
        def load():
            vals = {}
            try:
                offset = 0
                while offset < 300:
                    d = api_get(self.cfg, "/issues.json", {f"cf_{cf_id}": "*", "status_id": "*",
                                                           "sort": "updated_on:desc", "limit": 100, "offset": offset})
                    for i in d.get("issues", []):
                        for c in i.get("custom_fields", []):
                            if c["id"] == cf_id:
                                for v in c["value"] if isinstance(c.get("value"), list) else [c.get("value")]:
                                    if v not in (None, ""):
                                        vals[v] = vals.get(v, 0) + 1
                    offset += 100
                    if offset >= d.get("total_count", 0):
                        break
            except RedmineError:
                pass
            return vals
        vals = dict(cached(self._key("cfvals", cf_id), 3600, load))
        for v in seed:
            vals.setdefault(v, 0)
        return sorted(vals)

    def project_custom_fields(self, pid):
        def load():
            try:
                p = api_get(self.cfg, f"/projects/{pid}.json", {"include": "issue_custom_fields"})["project"]
                return {c["name"].strip(): c["id"] for c in p.get("issue_custom_fields", [])}
            except RedmineError:
                return {}
        return cached(self._key("pcf", pid), 3600, load)

    def tracker_fields(self, pid, tracker_id):
        """Доп. поля, которые в этом проекте и трекере обычно заполнены, — по последним задачам."""
        def load():
            d = api_get(self.cfg, "/issues.json", {"project_id": pid, "tracker_id": tracker_id, "status_id": "*",
                                                   "subproject_id": "!*", "sort": "updated_on:desc", "limit": 100})
            issues = d.get("issues", [])
            stats = {}
            for i in issues:
                for c in i.get("custom_fields", []):
                    st = stats.setdefault(c["id"], {"id": c["id"], "name": c["name"].strip(),
                                                    "multiple": bool(c.get("multiple")), "filled": 0, "seen": set()})
                    v = c.get("value")
                    if v not in (None, "", []):
                        st["filled"] += 1
                        st["seen"].update(v if isinstance(v, list) else [v])
            out = []
            for st in stats.values():
                required = len(issues) >= 3 and st["filled"] >= 0.9 * len(issues)
                out.append({"id": st["id"], "name": st["name"], "multiple": st["multiple"], "likely_required": required,
                            "values": self.cf_values(st["id"], st["seen"]) if required else sorted(st["seen"])})
            return out
        return cached(self._key("tfields", pid, tracker_id), 1800, load)

    def describe_fields(self, pid, names):
        """Имена полей из ошибки Redmine → поля с id и значениями."""
        ids = self.project_custom_fields(pid)
        return [{"id": ids[n], "name": n, "multiple": False, "likely_required": True, "values": self.cf_values(ids[n])}
                for n in names if n in ids]

    def home_project(self, uid, name):
        """Личный проект сотрудника: где лежит больше всего его задач, с приоритетом проекта с его фамилией."""
        d = api_get(self.cfg, "/issues.json", {"assigned_to_id": uid, "status_id": "*", "sort": "updated_on:desc",
                                               "limit": 100})
        counts, names = {}, {}
        for i in d.get("issues", []):
            p = i["project"]
            counts[p["id"]] = counts.get(p["id"], 0) + 1
            names[p["id"]] = p["name"].strip()
        if not counts:
            return None
        surname = (name or "").replace(".", " ").split()[-1:] or [""]
        surname = surname[0].lower()
        own = [pid for pid in counts if surname and len(surname) > 2 and surname in names[pid].lower()]
        best = max(own or counts, key=counts.get)
        return {"id": best, "name": names[best]}

    def find_user(self, uid):
        u = api_get(self.cfg, f"/users/{uid}.json")["user"]
        # как Redmine показывает в задачах: «И. И. Иванов»
        initials = [f"{w[0]}." for w in (u.get("firstname") or "").split()]
        return {"id": u["id"], "name": " ".join(initials + [(u.get("lastname") or "").strip()]).strip() or f"#{uid}"}


# ---------------------------------------------------------------- демо

class DemoBackend:
    """Выдуманный Redmine в памяти — чтобы посмотреть и потыкать без настоящего."""

    PEOPLE = {1: "Демо Режим", 2: "А. Иванова", 3: "П. Сидоров", 4: "К. Смирнова"}
    STATUSES = [(1, "Новая"), (2, "В работе"), (8, "Проблема"), (3, "Решена"), (5, "Закрыта")]
    TRACKERS = [(1, "Баг (Hot-fix)"), (2, "Разработка (Dev)"), (5, "Контроль"), (39, "Тестирование")]
    ACTIVITIES = [(93, "Выполнение своих обязанностей"), (159, "Тестирование"), (9, "Разработка")]
    HOME = {1: (201, "➡️[QA] Режим Д."), 2: (202, "[QA] Иванова А."), 3: (203, "[QA] Сидоров П."), 4: (204, "[QA] Смирнова К.")}

    def __init__(self):
        self.lock = threading.Lock()
        today = dt.date.today()
        rows = [
            (1, -4, "Остатки на складе не проверяли принадлежность склада организации", "Склад", 4, "Срочный", 2),
            (1, -1, "Фильтр «Артикул» в списании материалов показывает наименование", "Склад", 3, "Высокий", 1),
            (1, 0, "Перемещение материала: проверка остатка склада-источника", "Склад", 3, "Высокий", 3),
            (1, 0, "Разобрать баги после ревью и расписать пачкой", "Льготы", 2, "Нормальный", 4),
            (1, 0, "Регресс по квитанциям после релиза", "Квитанции", 2, "Нормальный", 1.5),
            (1, 1, "Поля количества в перемещении принимают отрицательные значения", "Склад", 2, "Нормальный", 1),
            (1, 2, "Проверить выгрузку DBF для расчётного центра", "Интеграции", 2, "Нормальный", None),
            (1, 4, "Автотесты кабинета жильца: оплата через ГПБ", "Кабинет", 3, "Высокий", 6),
            (1, 9, "Нагрузочный прогон диспетчерской", "Диспетчер", 2, "Нормальный", 8),
            (1, None, "Разобрать старые задачи в бэклоге", "Общее", 1, "Низкий", None),
            (2, -2, "Тест-кейсы на перемещение материалов", "Склад", 2, "Нормальный", 2),
            (2, 0, "Смоук кабинета жильца на стенде", "Кабинет", 3, "Высокий", 3),
            (2, 0, "Проверка льгот Ленобласти через рабочую область", "Льготы", 2, "Нормальный", 4),
            (2, 0, "Регресс оплаты без входа", "Кабинет", 4, "Срочный", 3),
            (2, 3, "Документация по привязке домов", "Документация", 1, "Низкий", 2),
            (3, 0, "Проверить карты в ЛКЖ после фикса 404", "Кабинет", 3, "Высокий", 1),
            (3, 1, "Отчёт по просроченным счётчикам в XLSX", "Отчёты", 2, "Нормальный", 2),
            (3, 5, "Smoke-набор по модулю «Отчёты»", "Отчёты", 2, "Нормальный", 6),
            (4, -6, "Проверка консьюмеров кафки в s300-auth", "Авторизация", 2, "Нормальный", 3),
            (4, -1, "Ссылка на заявку не показывает вложение исполнителя", "Заявки", 3, "Высокий", 1),
            (4, 2, "Тестирование Резидент ID на проде", "Авторизация", 4, "Срочный", 4),
        ]
        self.store = {}
        self.projects_by_name = {name: pid for pid, name in self.HOME.values()}
        for _, _, _, proj, _, _, _ in rows:
            self.projects_by_name.setdefault(proj, 300 + len(self.projects_by_name))
        for n, (who, off, subj, proj, pid, pname, est) in enumerate(rows):
            due = today + dt.timedelta(days=off) if off is not None else None
            iid = 580100 + n
            st = self.STATUSES[n % 3]
            tr = self.TRACKERS[n % 4]
            self.store[iid] = {
                "id": iid, "subject": subj, "project": proj, "project_id": self.projects_by_name[proj],
                "tracker": tr[1], "tracker_id": tr[0], "status": st[1], "status_id": st[0],
                "priority": pname, "priority_id": pid, "assignee": {"id": who, "name": self.PEOPLE[who]},
                "due": due.isoformat() if due else None,
                "start": (due - dt.timedelta(days=3)).isoformat() if due else None,
                "est": est, "done": (n * 20) % 100, "updated": dt.datetime.now().isoformat(timespec="seconds"),
                "description": "h3. Шаги\n\n# Открыть раздел\n# Выполнить действие\n# Проверить результат\n\n"
                               "*Ожидаемый результат:* всё работает.\n*Фактический:* не работает.",
                "author": "Иван Петров", "created": "2026-10-01T10:00:00Z", "spent": 0,
            }
        self.store[580110].update(status_id=5, status="Закрыта", done=100)  # закрытая подзадача для демо
        self.journals = {iid: [{"id": 1, "user": "Иван Петров", "created": "2026-10-02T09:15:00Z",
                                "notes": "Посмотри, пожалуйста, до конца недели.", "private": False,
                                "changes": ["Статус: Новая → В работе"]}] for iid in self.store}

    def me(self):
        return {"id": 1, "firstname": "Демо", "lastname": "Режим"}

    def issues(self, assignee_ids):
        ids = {1} if assignee_ids is None else set(assignee_ids)
        with self.lock:
            return [{k: v for k, v in i.items() if k not in ("description", "author", "created", "spent")}
                    for i in self.store.values() if i["assignee"] and i["assignee"]["id"] in ids
                    and i["status_id"] != 5]

    def details(self, issue_id):
        with self.lock:
            if issue_id not in self.store:
                raise RedmineError("Не найдено в Redmine (404)")
            issue = dict(self.store[issue_id])
            issue["journals"] = list(self.journals[issue_id])
            issue["custom_fields"] = ([{"id": 73, "name": "Блок Системы", "value": issue["cf73"], "multiple": False}]
                                      if issue.get("cf73") else [])
            issue["attachments"] = []
            self._demo_tree(issue)
        issue["options"] = {
            "statuses": [{"id": a, "name": b} for a, b in self.STATUSES],
            "trackers": [{"id": a, "name": b} for a, b in self.TRACKERS],
            "assignees": [{"id": a, "name": b} for a, b in self.PEOPLE.items()],
            "activities": [{"id": a, "name": b} for a, b in self.ACTIVITIES],
            "default_activity": 93,
        }
        return issue

    def update(self, issue_id, fields):
        with self.lock:
            i = self.store.get(issue_id)
            if not i:
                raise RedmineError("Не найдено в Redmine (404)")
            tracker = int(fields.get("tracker_id") or i["tracker_id"])
            cfs = {c["id"]: c["value"] for c in fields.get("custom_fields", [])}
            moving = "tracker_id" in fields or "project_id" in fields
            if moving and tracker == 39 and not (cfs.get(73) or i.get("cf73")):
                raise RedmineError("Redmine не принял изменения: Блок Системы не может быть пустым",
                                   ["Блок Системы не может быть пустым"])
            changes = []
            if cfs.get(73):
                i["cf73"] = cfs[73]
                changes.append(f"Блок Системы: {cfs[73]}")
            if "status_id" in fields:
                name = dict(self.STATUSES)[int(fields["status_id"])]
                changes.append(f"Статус: {i['status']} → {name}")
                i["status_id"], i["status"] = int(fields["status_id"]), name
            if "tracker_id" in fields:
                name = dict(self.TRACKERS)[int(fields["tracker_id"])]
                changes.append(f"Трекер: {i['tracker']} → {name}")
                i["tracker_id"], i["tracker"] = int(fields["tracker_id"]), name
            if "assigned_to_id" in fields:
                uid = fields["assigned_to_id"]
                new = {"id": int(uid), "name": self.PEOPLE[int(uid)]} if uid else None
                changes.append(f"Исполнитель: {(i['assignee'] or {}).get('name', 'никто')} → "
                               f"{(new or {}).get('name', 'никто')}")
                i["assignee"] = new
            if "due_date" in fields:
                changes.append(f"Срок: {i['due'] or '—'} → {fields['due_date'] or '—'}")
                i["due"] = fields["due_date"] or None
            if "project_id" in fields:
                pid = int(fields["project_id"])
                name = next((k for k, v in self.projects_by_name.items() if v == pid), f"#{pid}")
                changes.append(f"Проект: {i['project']} → {name}")
                i["project_id"], i["project"] = pid, name
            if "start_date" in fields:
                changes.append(f"Дата начала: {i['start'] or '—'} → {fields['start_date'] or '—'}")
                i["start"] = fields["start_date"] or None
            if "done_ratio" in fields:
                changes.append(f"Готовность: {i['done']}% → {fields['done_ratio']}%")
                i["done"] = int(fields["done_ratio"])
            i["updated"] = dt.datetime.now().isoformat(timespec="seconds")
            self.journals[issue_id].append({
                "id": len(self.journals[issue_id]) + 1, "user": "Демо Режим",
                "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "notes": fields.get("notes", ""), "private": False, "changes": changes,
            })

    def log_time(self, issue_id, hours, activity_id, comments, spent_on):
        with self.lock:
            if issue_id not in self.store:
                raise RedmineError("Не найдено в Redmine (404)")
            self.store[issue_id]["spent"] = round((self.store[issue_id]["spent"] or 0) + hours, 2)

    def candidates(self):
        return [{"id": k, "name": v, "count": 10 - k} for k, v in self.PEOPLE.items() if k != 1]

    def projects(self):
        return sorted(({"id": v, "name": k} for k, v in self.projects_by_name.items()), key=lambda p: p["name"].lower())

    def project_options(self, pid):
        name = next((k for k, v in self.projects_by_name.items() if v == pid), "")
        return {"id": pid, "name": name,
                "trackers": [{"id": a, "name": b} for a, b in self.TRACKERS],
                "assignees": [{"id": a, "name": b} for a, b in self.PEOPLE.items()]}

    CHILDREN = {580102: [580105, 580106, 580110]}

    def _demo_tree(self, issue):
        kids = []
        for cid in self.CHILDREN.get(issue["id"], []):
            c = self.store[cid]
            kids.append({"id": cid, "subject": c["subject"], "tracker": c["tracker"], "depth": 0,
                         "status": c["status"], "closed": c["status_id"] == 5, "assignee": c["assignee"],
                         "due": c["due"], "done": c["done"]})
        parent = next((pid for pid, ids in self.CHILDREN.items() if issue["id"] in ids), None)
        issue["children"] = kids
        issue["parent"] = {"id": parent, "subject": self.store[parent]["subject"],
                           "status": self.store[parent]["status"]} if parent else None

    CF_VALUES = ["01. Начисления", "06. Личный кабинет жителя", "08. Заявки", "18. Авторизация", "20. Иное"]

    def tracker_fields(self, pid, tracker_id):
        if tracker_id != 39:
            return []
        return [{"id": 73, "name": "Блок Системы", "multiple": False, "likely_required": True, "values": self.CF_VALUES}]

    def describe_fields(self, pid, names):
        return [f for f in self.tracker_fields(pid, 39) if f["name"] in names]

    def priorities(self):
        return [{"id": 3, "name": "Низкий", "default": False}, {"id": 4, "name": "Нормальный", "default": True},
                {"id": 5, "name": "Высокий", "default": False}, {"id": 6, "name": "Срочный", "default": False}]

    def attachment(self, attachment_id):
        raise RedmineError("В демо-режиме файлов нет")

    def create(self, fields):
        with self.lock:
            tracker = int(fields["tracker_id"])
            cfs = {c["id"]: c["value"] for c in fields.get("custom_fields", [])}
            if tracker == 39 and not cfs.get(73):
                raise RedmineError("Redmine не принял изменения: Блок Системы не может быть пустым",
                                   ["Блок Системы не может быть пустым"])
            iid = max(self.store) + 1
            pid = int(fields["project_id"])
            uid = fields.get("assigned_to_id")
            prio = {p["id"]: p["name"] for p in self.priorities()}
            self.store[iid] = {
                "id": iid, "subject": fields["subject"], "project_id": pid,
                "project": next((k for k, v in self.projects_by_name.items() if v == pid), f"#{pid}"),
                "tracker_id": tracker, "tracker": dict(self.TRACKERS).get(tracker, "Задача"),
                "status_id": 1, "status": "Новая",
                "priority_id": int(fields.get("priority_id") or 4), "priority": prio.get(int(fields.get("priority_id") or 4), ""),
                "assignee": {"id": int(uid), "name": self.PEOPLE[int(uid)]} if uid else None,
                "due": fields.get("due_date") or None, "start": fields.get("start_date") or None,
                "est": fields.get("estimated_hours"), "done": 0,
                "updated": dt.datetime.now().isoformat(timespec="seconds"),
                "description": fields.get("description", ""), "author": "Демо Режим",
                "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "spent": 0,
                "cf73": cfs.get(73),
            }
            self.journals[iid] = []
            parent = fields.get("parent_issue_id")
            if parent:
                self.CHILDREN.setdefault(int(parent), []).append(iid)
            return iid

    def home_project(self, uid, name):
        pid, pname = self.HOME.get(uid, (None, None))
        return {"id": pid, "name": pname} if pid else None

    def find_user(self, uid):
        if uid not in self.PEOPLE:
            raise RedmineError("Не найдено в Redmine (404)")
        return {"id": uid, "name": self.PEOPLE[uid]}


# ---------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    server_version = "RedmineCalendar"

    def log_message(self, *args):
        pass

    @property
    def cfg(self):
        return self.server.cfg

    @property
    def backend(self):
        return self.server.demo if DEMO else RealBackend(dict(self.server.cfg))

    # --- helpers

    @property
    def remote(self):
        return getattr(self.server, "remote", False)

    def _host_ok(self):
        if self.remote:  # телефон приходит по IP или через туннель — защищает вход по PIN
            return True
        port = self.server.server_address[1]
        return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _client_ip(self):
        peer = self.client_address[0]
        if peer in ("127.0.0.1", "::1"):  # через туннель (cloudflared, ngrok) настоящий адрес — в заголовке
            fwd = self.headers.get("CF-Connecting-IP") or (self.headers.get("X-Forwarded-For") or "").split(",")[0]
            return fwd.strip() or peer
        return peer

    def _session(self):
        """(сессия, токен) по cookie телефона или None."""
        try:
            morsel = SimpleCookie(self.headers.get("Cookie", "")).get("rc_session")
        except CookieError:
            return None
        if not morsel or not morsel.value:
            return None
        h, now = sha256(morsel.value), time.time()
        for sess in self.cfg.get("sessions", []):
            if hmac.compare_digest(sess["hash"], h) and now - sess.get("last", 0) < SESSION_TTL:
                if now - sess.get("last", 0) > 600:  # отмечаем активность, но не дёргаем диск на каждый запрос
                    with CFG_LOCK:
                        sess["last"] = now
                        persist(self.cfg)
                return sess, morsel.value
        return None

    def _csrf(self, token):
        return hmac.new(self.cfg["secret"].encode(), token.encode(), hashlib.sha256).hexdigest()[:40]

    def _page_token(self):
        if not self.remote:
            return TOKEN
        sess = self._session()
        return self._csrf(sess[1]) if sess else None

    def _authed(self):
        expected = self._page_token()
        got = self.headers.get("X-RC-Token") or ""
        if not got and self.command == "GET":  # картинки во вложениях грузятся через <img src>, заголовок не добавить
            got = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("t", [""])[0]
        return bool(expected) and secrets.compare_digest(got, expected)

    def _send(self, code, body, ctype, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def _body(self):
        length = min(int(self.headers.get("Content-Length") or 0), 1 << 20)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw or b"{}")
            return body if isinstance(body, dict) else {}
        except ValueError:
            return {}

    def _configured(self):
        return DEMO or bool(self.cfg["url"] and self.cfg["api_key"])

    def _state(self):
        cfg = self.cfg
        return {
            "demo": DEMO,
            "configured": self._configured(),
            "url": cfg["url"],
            "has_key": bool(cfg["api_key"]),
            "refresh_min": cfg["refresh_min"],
            "verify_ssl": cfg["verify_ssl"],
            "workday_hours": cfg["workday_hours"],
            "team": cfg["team"],
            "autostart": autostart_enabled(),
            "version": ui_version(),
            "remote": self.remote,
            "remote_enabled": bool(cfg.get("remote_enabled")),
            "remote_running": RemoteServer.running(),
            "remote_error": RemoteServer.error,
            "remote_port": cfg.get("remote_port") or 47824,
            "has_pin": bool(cfg.get("pin_hash")),
            **({} if self.remote else {
                "lan_urls": [f"http://{a}:{cfg.get('remote_port') or 47824}/" for a in lan_addresses()],
                "sessions": [{"id": x["hash"][:12], "created": x.get("created"), "last": x.get("last"),
                              "ua": x.get("ua", ""), "ip": x.get("ip", "")} for x in cfg.get("sessions", [])
                             if time.time() - x.get("last", 0) < SESSION_TTL],
            }),
        }

    def _timer_view(self, timer):
        if not timer:
            return None
        return {**timer, "elapsed": max(0, int(time.time() - timer["started"]))}

    # --- routes

    def do_GET(self):
        self._safe(self._get)

    def do_POST(self):
        self._safe(self._post)

    def _safe(self, fn):
        try:
            fn()
        except Exception as e:  # noqa: BLE001 — любая ошибка должна дойти до окна, а не оборвать соединение
            try:
                self._json(500, {"error": f"Внутренняя ошибка программы: {e}"})
            except OSError:
                pass

    def _get(self):
        if not self._host_ok():
            return self._json(403, {"error": "bad host"})
        url = urllib.parse.urlparse(self.path)
        path, query = url.path, urllib.parse.parse_qs(url.query)

        if path in ("/", "/index.html"):
            token = self._page_token()
            page = "index.html" if token else "login.html"
            with open(os.path.join(WEB_DIR, page), encoding="utf-8") as f:
                html = (f.read().replace("__RC_TOKEN__", token or "").replace("__RC_DEMO__", "true" if DEMO else "false")
                        .replace("__RC_REMOTE__", "true" if self.remote else "false"))
            return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8",
                              {"Content-Security-Policy": CSP, "Referrer-Policy": "no-referrer"})
        if path in STATIC:
            name, ctype = STATIC[path]
            try:
                with open(os.path.join(WEB_DIR, name), "rb") as f:
                    return self._send(200, f.read(), ctype)
            except OSError:
                return self._json(404, {"error": "not found"})
        if path == "/api/hello":
            return self._json(200, {"app": APP_ID})

        if not self._authed():
            return self._json(401 if self.remote else 403, {"error": "Нужно войти заново" if self.remote else "forbidden"})
        if not self.remote:
            Life.ping()
        q = lambda k: query.get(k, [""])[0]  # noqa: E731

        if path == "/api/ping":
            return self._json(200, {"ok": True, "version": ui_version()})
        if path == "/api/state":
            return self._json(200, self._state())
        if path == "/api/timer":
            return self._json(200, {"timer": self._timer_view(load_timer())})
        if not self._configured():
            return self._json(409, {"error": "Не указан адрес Redmine или API-ключ"})
        try:
            if path == "/api/issues":
                return self._issues(q("who") or "me")
            if path == "/api/issue":
                if not q("id").isdigit():
                    return self._json(400, {"error": "bad id"})
                return self._json(200, self.backend.details(int(q("id"))))
            if path == "/api/projects":
                return self._json(200, {"projects": self.backend.projects()})
            if path == "/api/priorities":
                return self._json(200, {"priorities": self.backend.priorities()})
            if path == "/api/attachment":
                if not q("id").isdigit():
                    return self._json(400, {"error": "bad id"})
                return self._attachment(int(q("id")), q("name"))
            if path == "/api/project":
                if not q("id").isdigit():
                    return self._json(400, {"error": "bad id"})
                return self._json(200, self.backend.project_options(int(q("id"))))
            if path == "/api/fields":
                if not (q("project").isdigit() and q("tracker").isdigit()):
                    return self._json(400, {"error": "bad project/tracker"})
                return self._json(200, {"fields": self.backend.tracker_fields(int(q("project")), int(q("tracker")))})
            if path == "/api/team/home":
                if not q("id").isdigit():
                    return self._json(400, {"error": "bad id"})
                return self._json(200, {"project": self.backend.home_project(int(q("id")), q("name"))})
            if path == "/api/team/candidates":
                return self._json(200, {"people": self.backend.candidates()})
            if path == "/api/user":
                m = re.search(r"(\d+)\D*$", q("q"))
                if not m:
                    return self._json(400, {"error": "Вставь ссылку на профиль или номер пользователя"})
                return self._json(200, self.backend.find_user(int(m.group(1))))
        except RedmineError as e:
            return self._json(502, {"error": str(e)})
        return self._json(404, {"error": "not found"})

    def _post(self):
        if not self._host_ok():
            return self._json(403, {"error": "bad host"})
        path = urllib.parse.urlparse(self.path).path
        body = self._body()

        if path == "/api/bye":  # sendBeacon не умеет заголовки — токен приходит в теле
            if not self.remote and secrets.compare_digest(str(body.get("token", "")), TOKEN):
                Life.bye()
            return self._json(200, {"ok": True})
        if path == "/api/login" and self.remote:
            return self._login(body)

        if not self._authed():
            return self._json(401 if self.remote else 403, {"error": "Нужно войти заново" if self.remote else "forbidden"})
        if self.remote:
            if path == "/api/logout":
                return self._logout()
            if path in ("/api/config", "/api/check", "/api/open", "/api/pin", "/api/sessions/revoke"):
                return self._json(403, {"error": "Это можно сделать только на компьютере"})
        else:
            Life.ping()

        if path == "/api/pin":
            return self._set_pin(body)
        if path == "/api/sessions/revoke":
            return self._revoke(body)
        if path == "/api/config":
            return self._save_config(body)
        if path == "/api/check":
            return self._check(body)
        if path == "/api/open":
            return self._open(body)
        if not self._configured():
            return self._json(409, {"error": "Не указан адрес Redmine или API-ключ"})
        try:
            if path == "/api/issue/update":
                return self._update(body)
            if path == "/api/issue/create":
                return self._create(body)
            if path == "/api/time":
                return self._log_time(body)
            if path == "/api/timer/start":
                return self._timer_start(body)
            if path == "/api/timer/stop":
                return self._timer_stop(body)
        except RedmineError as e:
            return self._json(502, {"error": str(e)})
        return self._json(404, {"error": "not found"})

    # --- handlers

    def _issues(self, who):
        if who == "me":
            ids = None
        elif who == "team":
            ids = [m["id"] for m in self.cfg["team"]]
            if not ids:
                return self._json(200, {"user": self.backend.me(), "issues": []})
        elif who.isdigit():
            ids = [int(who)]
        else:
            return self._json(400, {"error": "bad who"})
        backend = self.backend
        return self._json(200, {"user": backend.me(), "who": who, "issues": backend.issues(ids)})

    def _update(self, body):
        issue_id = body.get("id")
        if not isinstance(issue_id, int):
            return self._json(400, {"error": "bad id"})
        fields = {}
        if str(body.get("notes") or "").strip():
            fields["notes"] = str(body["notes"]).strip()
        for key in ("project_id", "status_id", "tracker_id", "done_ratio"):
            if body.get(key) not in (None, ""):
                fields[key] = int(body[key])  # мусор → ValueError → 500 с текстом
        if "assigned_to_id" in body:
            fields["assigned_to_id"] = int(body["assigned_to_id"]) if body["assigned_to_id"] not in (None, "") else ""
        for key in ("due_date", "start_date"):
            if key in body:
                value = str(body[key] or "")
                if value and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                    return self._json(400, {"error": "Неверная дата"})
                fields[key] = value
        try:
            cfs = parse_custom_fields(body)
        except ValueError:
            return self._json(400, {"error": "Неверное доп. поле"})
        if cfs:
            fields["custom_fields"] = cfs
        if not fields:
            return self._json(400, {"error": "Нечего сохранять"})
        try:
            self.backend.update(issue_id, fields)
        except RedmineError as e:
            names = blank_fields(e.errors)
            pid = fields.get("project_id") or body.get("context_project_id")
            missing = self.backend.describe_fields(int(pid), names) if names and str(pid).isdigit() else []
            return self._json(422 if missing else 502, {"error": str(e), "missing": missing})
        return self._json(200, {"ok": True})

    def _create(self, body):
        subject = str(body.get("subject") or "").strip()
        if not subject:
            return self._json(400, {"error": "Напиши тему задачи"})
        try:
            fields = {"project_id": int(body["project_id"]), "tracker_id": int(body["tracker_id"]),
                      "subject": subject[:255], "description": str(body.get("description") or "")}
            for key in ("priority_id", "assigned_to_id", "parent_issue_id"):
                if str(body.get(key) or "").strip():
                    fields[key] = int(str(body[key]).strip().lstrip("#"))
            est = parse_hours(body.get("estimated_hours"))
            if est:
                fields["estimated_hours"] = est
            for key in ("due_date", "start_date"):
                value = str(body.get(key) or "")
                if value:
                    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                        return self._json(400, {"error": "Неверная дата"})
                    fields[key] = value
            cfs = parse_custom_fields(body)
        except (KeyError, TypeError, ValueError):
            return self._json(400, {"error": "Проверь поля: проект, трекер, оценка и номер родительской задачи"})
        if cfs:
            fields["custom_fields"] = cfs
        try:
            issue_id = self.backend.create(fields)
        except RedmineError as e:
            names = blank_fields(e.errors)
            missing = self.backend.describe_fields(fields["project_id"], names) if names else []
            return self._json(422 if missing else 502, {"error": str(e), "missing": missing})
        return self._json(200, {"ok": True, "id": issue_id})

    def _attachment(self, attachment_id, name):
        data, ctype = self.backend.attachment(attachment_id)
        inline = ctype in ("image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain")
        fname = urllib.parse.quote(name or f"file-{attachment_id}")
        return self._send(200, data, ctype if inline else "application/octet-stream", {
            "Content-Disposition": f"{'inline' if inline else 'attachment'}; filename*=UTF-8''{fname}",
            "Content-Security-Policy": "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'",
        })

    def _time_args(self, body):
        try:
            hours = parse_hours(body.get("hours")) or 0  # 0:07 = 0.1167 ч — Redmine покажет ровно 7 минут
        except ValueError:
            hours = 0
        if not 0 < hours <= 24:
            raise ValueError("Время должно быть больше 0:00 и не больше 24:00")
        spent_on = str(body.get("spent_on") or dt.date.today().isoformat())
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", spent_on):
            raise ValueError("Неверная дата")
        act = body.get("activity_id")
        return hours, int(act) if act else None, str(body.get("comments") or "")[:1000], spent_on

    def _log_time(self, body):
        issue_id = body.get("issue_id")
        if not isinstance(issue_id, int):
            return self._json(400, {"error": "bad id"})
        try:
            hours, act, comments, spent_on = self._time_args(body)
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        self.backend.log_time(issue_id, hours, act, comments, spent_on)
        return self._json(200, {"ok": True, "hours": hours})

    def _timer_start(self, body):
        issue_id = body.get("id")
        if not isinstance(issue_id, int):
            return self._json(400, {"error": "bad id"})
        with self.server.timer_lock:
            current = load_timer()
            if current and current["issue_id"] != issue_id:
                return self._json(409, {"error": f"Уже идёт таймер по задаче #{current['issue_id']} — сначала останови его",
                                        "timer": self._timer_view(current)})
            if not current:
                current = {"issue_id": issue_id, "subject": str(body.get("subject") or "")[:300],
                           "started": time.time()}
                save_timer(current)
        warning = None
        if body.get("status_id"):
            try:
                self.backend.update(issue_id, {"status_id": int(body["status_id"])})
            except RedmineError as e:
                warning = f"Таймер запущен, но статус не сменился: {e}"
        return self._json(200, {"timer": self._timer_view(current), "warning": warning})

    def _timer_stop(self, body):
        with self.server.timer_lock:
            current = load_timer()
            if not current:
                return self._json(200, {"timer": None, "logged": 0})
            logged = 0
            if body.get("log"):
                try:
                    hours, act, comments, spent_on = self._time_args(body)
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                self.backend.log_time(current["issue_id"], hours, act, comments, spent_on)  # ошибка — таймер остаётся
                logged = hours
            save_timer(None)
        return self._json(200, {"timer": None, "logged": logged})

    def _login(self, body):
        ip = self._client_ip()
        if Guard.blocked(ip):
            return self._json(429, {"error": "Слишком много неверных попыток — подожди 15 минут"})
        cfg = self.cfg
        if not cfg.get("pin_hash"):
            return self._json(403, {"error": "PIN не задан — задай его в настройках на компьютере"})
        pin = str(body.get("pin") or "")
        if not hmac.compare_digest(hash_pin(pin, cfg["pin_salt"]), cfg["pin_hash"]):
            Guard.fail(ip)
            time.sleep(1)
            return self._json(401, {"error": "Неверный PIN"})
        Guard.success(ip)
        token, now = secrets.token_urlsafe(32), time.time()
        sess = {"hash": sha256(token), "created": now, "last": now,
                "ua": (self.headers.get("User-Agent") or "")[:200], "ip": ip}
        with CFG_LOCK:
            alive = [x for x in cfg.get("sessions", []) if now - x.get("last", 0) < SESSION_TTL]
            cfg["sessions"] = alive[-19:] + [sess]
            persist(cfg)
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
        body = json.dumps({"ok": True}).encode()
        return self._send(200, body, "application/json; charset=utf-8", {
            "Set-Cookie": f"rc_session={token}; Path=/; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Lax{secure}"})

    def _logout(self):
        sess = self._session()
        if sess:
            with CFG_LOCK:
                self.cfg["sessions"] = [x for x in self.cfg.get("sessions", []) if x["hash"] != sess[0]["hash"]]
                persist(self.cfg)
        body = json.dumps({"ok": True}).encode()
        return self._send(200, body, "application/json; charset=utf-8",
                          {"Set-Cookie": "rc_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax"})

    def _set_pin(self, body):
        pin = str(body.get("pin") or "").strip()
        if len(pin) < 6:
            return self._json(400, {"error": "PIN — минимум 6 символов"})
        with CFG_LOCK:
            salt = secrets.token_hex(16)
            self.cfg.update(pin_salt=salt, pin_hash=hash_pin(pin, salt), sessions=[])  # новый PIN — все телефоны заново
            if not self.cfg.get("secret"):
                self.cfg["secret"] = secrets.token_hex(32)
            persist(self.cfg)
        err = RemoteServer.apply(self.server)
        return self._json(200, {"state": self._state(), "warning": err})

    def _revoke(self, body):
        with CFG_LOCK:
            if body.get("all"):
                self.cfg["sessions"] = []
            else:
                sid = str(body.get("id") or "")
                self.cfg["sessions"] = [x for x in self.cfg.get("sessions", []) if not x["hash"].startswith(sid) or not sid]
            persist(self.cfg)
        return self._json(200, {"state": self._state()})

    def _save_config(self, body):
        cfg = self.cfg
        if "url" in body:
            cfg["url"] = normalize_url(body["url"])
        if body.get("api_key"):
            cfg["api_key"] = str(body["api_key"]).strip()
        try:
            if "refresh_min" in body:
                cfg["refresh_min"] = max(1, min(240, int(body["refresh_min"])))
            if "workday_hours" in body:
                cfg["workday_hours"] = max(1, min(24, float(body["workday_hours"])))
        except (TypeError, ValueError):
            pass
        if "verify_ssl" in body:
            cfg["verify_ssl"] = bool(body["verify_ssl"])
        if "team" in body:
            cfg["team"] = clean_team(body["team"])
        if "remote_enabled" in body:
            cfg["remote_enabled"] = bool(body["remote_enabled"])
        if "remote_port" in body:
            try:
                cfg["remote_port"] = max(1024, min(65535, int(body["remote_port"])))
            except (TypeError, ValueError):
                pass
        warn = None
        try:
            persist(cfg)
            if "autostart" in body and not DEMO:
                set_autostart(bool(body["autostart"]))
        except OSError as e:
            warn = f"Не удалось сохранить: {e}"
        warn = RemoteServer.apply(self.server) or warn
        if cfg.get("remote_enabled") and not cfg.get("pin_hash"):
            warn = warn or "Задай PIN — без него доступ с телефона не включится"
        return self._json(200, {"state": self._state(), "warning": warn})

    def _check(self, body):
        if DEMO:
            return self._json(200, {"ok": True, "user": "Демо Режим", "total": 10})
        cfg = {
            "url": normalize_url(body.get("url")) or self.cfg["url"],
            "api_key": str(body.get("api_key") or "").strip() or self.cfg["api_key"],
            "verify_ssl": bool(body.get("verify_ssl", True)),
        }
        if not (cfg["url"] and cfg["api_key"]):
            return self._json(200, {"ok": False, "error": "Заполни адрес и ключ"})
        try:
            user = api_get(cfg, "/users/current.json", timeout=10)["user"]
            total = api_get(cfg, "/issues.json", {"assigned_to_id": "me", "status_id": "open", "limit": 1},
                            timeout=10).get("total_count", 0)
        except RedmineError as e:
            return self._json(200, {"ok": False, "error": str(e)})
        name = f"{user.get('firstname', '')} {user.get('lastname', '')}".strip()
        return self._json(200, {"ok": True, "user": name, "total": total})

    def _open(self, body):
        issue_id = str(body.get("id", ""))
        base = self.cfg["url"]
        if not issue_id.isdigit() or not base:
            return self._json(400, {"error": "Нечего открывать"})
        webbrowser.open(f"{base}/issues/{issue_id}")
        return self._json(200, {"ok": True})


def ui_version():
    try:
        return int(os.path.getmtime(os.path.join(WEB_DIR, "index.html")))
    except OSError:
        return 0


# ---------------------------------------------------------------- окно и жизненный цикл

def find_browser():
    roots = [os.environ.get(v, "") for v in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA")]
    for rel in (r"Microsoft\Edge\Application\msedge.exe", r"Google\Chrome\Application\chrome.exe"):
        for root in roots:
            path = os.path.join(root, rel)
            if root and os.path.exists(path):
                return path
    return None


def open_window(url):
    exe = find_browser()
    if not exe:
        webbrowser.open(url)
        return
    subprocess.Popen([
        exe,
        f"--app={url}",
        f"--user-data-dir={WINDOW_PROFILE}",
        "--window-size=1400,900",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=Translate",
    ])


def existing_instance_alive():
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{PORT}/api/hello", timeout=2) as r:
            return json.load(r).get("app") == APP_ID
    except (OSError, ValueError):
        return False


def make_server():
    for port in (PORT, 0):
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
            server.daemon_threads = True
            return server
        except OSError:
            if port == PORT and existing_instance_alive():
                return None
    raise OSError("не удалось открыть порт")


def main():
    if not os.path.exists(os.path.join(WEB_DIR, "index.html")):
        raise SystemExit(f"Нет файла интерфейса: {WEB_DIR}\\index.html")

    server = make_server()
    if server is None:  # уже запущено — просто открыть ещё одно окно
        open_window(f"http://127.0.0.1:{PORT}/")
        return
    server.cfg = load_config()
    server.demo = None
    if DEMO:
        server.cfg = dict(DEFAULT_CONFIG, team=[
            {"id": k, "name": v, "project": {"id": DemoBackend.HOME[k][0], "name": DemoBackend.HOME[k][1]}}
            for k, v in DemoBackend.PEOPLE.items() if k != 1])
        server.demo = DemoBackend()
    server.timer_lock = threading.Lock()
    if not server.cfg.get("secret"):
        server.cfg["secret"] = secrets.token_hex(32)
        persist(server.cfg)
    url = f"http://127.0.0.1:{server.server_address[1]}/"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    RemoteServer.apply(server)
    # автозапуск при включённом доступе с телефона — тихо, без окна
    background = "--autostart" in sys.argv and RemoteServer.running()
    if "--no-window" in sys.argv or background:
        print(url, flush=True)
    else:
        open_window(url)

    Life.ping()
    prev = time.monotonic()
    while True:
        time.sleep(1)
        now = time.monotonic()
        if now - prev > 30:  # компьютер спал — не считаем это тишиной окна
            Life.ping()
        prev = now
        with Life.lock:
            closed = Life.bye_at is not None and Life.last_ping < Life.bye_at and now - Life.bye_at > BYE_GRACE
            silent = now - Life.last_ping > PING_TIMEOUT
        if (closed or silent) and not RemoteServer.running():  # пока включён доступ с телефона — работаем в фоне
            break
    server.shutdown()


if __name__ == "__main__":
    main()
