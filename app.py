\
import os
import re
import json
import decimal
from datetime import datetime, date, timedelta
from urllib.parse import urlparse

from flask import (
    Flask, request, redirect, url_for, render_template, flash, session, abort
)
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Text, Enum, Numeric, ForeignKey, Date
)
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from sqlalchemy.exc import OperationalError
from dotenv import load_dotenv
import requests
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Response, send_file

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "please-change-me")

def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = SessionLocal()
    try:
        u = db.query(User).get(uid)
        return u
    finally:
        db.close()

@app.context_processor
def inject_globals():
    db = SessionLocal()
    try:
        open_credits = db.query(Credit).filter(Credit.remaining_amount > decimal.Decimal("0.00")).order_by(Credit.created_at.desc()).all()
    except Exception:
        open_credits = []
    finally:
        db.close()
    u = get_current_user()
    return {"role": (u.role if u else None), "open_credits": open_credits, "current_user": u}

DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
if not DATABASE_URL:
    DATABASE_URL = "sqlite:///damage.db"

# psycopg requires 'postgresql+psycopg://' URI
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)

engine = create_engine(DATABASE_URL, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()

STATUSES = ("open", "in-progress", "awaiting-credit", "credited", "closed")

class Item(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=True)
    vendor = Column(String(255), nullable=True)
    po_number = Column(String(128), index=True, nullable=True)
    sku = Column(String(128), index=True, nullable=True)
    quantity = Column(Integer, default=1)
    unit_cost = Column(Numeric(12,2), nullable=True)
    description = Column(Text, nullable=True)
    status = Column(Enum(*STATUSES, name="status_enum"), default="open", index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)

    attachments = relationship("Attachment", back_populates="item", cascade="all, delete-orphan")
    email_logs = relationship("EmailLog", back_populates="item", cascade="all, delete-orphan")
    applications = relationship("CreditApplication", back_populates="item", cascade="all, delete-orphan")

class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey("items.id"), index=True)
    drive_file_id = Column(String(255), nullable=True)
    drive_file_url = Column(String(1024), nullable=True)
    webview_link = Column(String(1024), nullable=True)
    filename = Column(String(255), nullable=True)
    mime_type = Column(String(255), nullable=True)
    name = Column(String(255), nullable=True)  # user label
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    source = Column(String(64), default="manual")  # manual|zap

    item = relationship("Item", back_populates="attachments")

class EmailLog(Base):
    __tablename__ = "email_logs"
    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey("items.id"), index=True, nullable=True)
    vendor = Column(String(255), nullable=True)
    gmail_msg_id = Column(String(255), nullable=True, unique=False)
    subject = Column(String(512), nullable=True)
    from_address = Column(String(255), nullable=True)
    to_address = Column(String(255), nullable=True)
    body_snippet = Column(Text, nullable=True)
    received_at = Column(DateTime, nullable=True)
    payload_json = Column(Text, nullable=True)  # raw zap payload snippet
    created_at = Column(DateTime, default=datetime.utcnow)

    item = relationship("Item", back_populates="email_logs")

class Credit(Base):
    __tablename__ = "credits"
    id = Column(Integer, primary_key=True)
    reference = Column(String(255), nullable=True)  # e.g. Vendor Credit #1234
    vendor = Column(String(255), nullable=True)
    original_amount = Column(Numeric(12,2), nullable=False, default=decimal.Decimal("0.00"))
    remaining_amount = Column(Numeric(12,2), nullable=False, default=decimal.Decimal("0.00"))
    issued_date = Column(Date, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    applications = relationship("CreditApplication", back_populates="credit", cascade="all, delete-orphan")

class CreditApplication(Base):
    __tablename__ = "credit_applications"
    id = Column(Integer, primary_key=True)
    credit_id = Column(Integer, ForeignKey("credits.id"), index=True)
    item_id = Column(Integer, ForeignKey("items.id"), index=True)
    amount_applied = Column(Numeric(12,2), nullable=False, default=decimal.Decimal("0.00"))
    applied_date = Column(DateTime, default=datetime.utcnow)

    credit = relationship("Credit", back_populates="applications")
    item = relationship("Item", back_populates="applications")


class Vendor(Base):
    __tablename__ = "vendors"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    email = Column(String(255), nullable=True)
    phone = Column(String(64), nullable=True)
    sla_days = Column(Integer, nullable=True)
    email_template = Column(Text, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="viewer")
    created_at = Column(DateTime, default=datetime.utcnow)

class ChangeLog(Base):
    __tablename__ = "changelog"
    id = Column(Integer, primary_key=True)
    actor_role = Column(String(32))
    action = Column(String(64))
    entity = Column(String(64))
    entity_id = Column(Integer)
    details = Column(Text, nullable=True)
    at = Column(DateTime, default=datetime.utcnow)



def init_db():
    Base.metadata.create_all(engine)

init_db()

ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "changeme")

ZAPIER_SECRET = os.getenv("ZAPIER_SECRET", "zap-secret")
OUTGOING_WEBHOOK_URL = os.getenv("OUTGOING_WEBHOOK_URL", "").strip()


def current_role():
    return session.get("role")

def require_role(*roles):
    from functools import wraps
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = get_current_user()
            if not u or (roles and u.role not in roles):
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def log_change(actor_role, action, entity, entity_id, details=None):
    db = SessionLocal()
    try:
        db.add(ChangeLog(actor_role=actor_role, action=action, entity=entity, entity_id=entity_id, details=json.dumps(details)[:4000] if details else None))
        db.commit()
    finally:
        db.close()


def require_login(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    db = SessionLocal()
    user_count = db.query(User).count()
    db.close()
    show_bootstrap = (user_count == 0)
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        db = SessionLocal()
        u = db.query(User).filter(User.email == email).first()
        db.close()
        if u and check_password_hash(u.password_hash, password):
            session["user_id"] = u.id
            return redirect(url_for("index"))
        else:
            error = "Invalid credentials."
    return render_template("login.html", error=error, show_bootstrap=show_bootstrap)

@app.route("/bootstrap-admin", methods=["POST"])
def bootstrap_admin():
    db = SessionLocal()
    if db.query(User).count() > 0:
        db.close()
        return redirect(url_for("login"))
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")
    if not email or not password:
        db.close()
        return redirect(url_for("login"))
    u = User(email=email, password_hash=generate_password_hash(password), role="admin")
    db.add(u); db.commit(); uid = u.id
    db.close()
    session["user_id"] = uid
    return redirect(url_for("index"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------------
# Helpers
# ---------------------

money_re = re.compile(r"\$?\s*([0-9]+(?:\.[0-9]{1,2})?)")
sku_re = re.compile(r"\bSKU[:\s\-#]*([A-Za-z0-9\-_.]+)\b", re.IGNORECASE)
po_re = re.compile(r"\bPO[:\s\-#]*([A-Za-z0-9\-_.]+)\b", re.IGNORECASE)
credit_re = re.compile(r"\bcredit(?:\s+of|\s+for|\s*[:\-])?\s*\$?\s*([0-9]+(?:\.[0-9]{1,2})?)", re.IGNORECASE)

def to_decimal(val):
    if val is None or val == "":
        return None
    if isinstance(val, (int, float, decimal.Decimal)):
        return decimal.Decimal(str(val))
    m = money_re.search(str(val))
    if m:
        return decimal.Decimal(m.group(1))
    return None

def guess_vendor(from_addr, subject, body):
    vendor = None
    if from_addr and "@" in from_addr:
        domain = from_addr.split("@")[-1].lower()
        # heuristic: left of first dot
        vendor = domain.split(".")[0].capitalize()
    # fallback from subject keywords
    if not vendor and subject:
        for token in ("Ashley", "Liberty", "Coaster", "Steve Silver", "Leick", "Parker House", "Riverside"):
            if token.lower() in subject.lower():
                vendor = token
                break
    return vendor or "Unknown"

def parse_email_payload(payload):
    """Return dict with fields for Item and EmailLog. Payload is Zapier-built JSON."""
    subject = payload.get("subject", "")
    body_plain = payload.get("body_plain", "") or ""
    body_html = payload.get("body_html", "") or ""
    body = f"{subject}\n{body_plain}\n{body_html}"
    from_addr = payload.get("from", "")
    to_addr = payload.get("to", "")
    received_at = payload.get("received_at")

    vendor = guess_vendor(from_addr, subject, body)
    sku = None
    po = None
    credit_amount = None

    m = sku_re.search(body)
    if m:
        sku = m.group(1).strip()

    m = po_re.search(body)
    if m:
        po = m.group(1).strip()

    m = credit_re.search(body)
    if m:
        credit_amount = to_decimal(m.group(1))

    attachments = payload.get("attachments") or []

    return {
        "vendor": vendor,
        "sku": sku,
        "po": po,
        "credit_amount": credit_amount,
        "from": from_addr,
        "to": to_addr,
        "subject": subject,
        "body_snippet": (body_plain or subject)[:800],
        "received_at": received_at,
        "attachments": attachments,
        "gmail_msg_id": payload.get("message_id"),
    }

def compute_sla(item, vendor):
    if not vendor or not vendor.sla_days:
        return None, None
    # SLA based on created_at + sla_days
    due_date = (item.created_at or datetime.utcnow()) + timedelta(days=int(vendor.sla_days))
    days_left = (due_date - datetime.utcnow()).days
    if days_left < 0:
        return "overdue", days_left
    if days_left <= 3:
        return "due", days_left
    return "ok", days_left

def build_sla_digest(db):
    # Group open items by vendor with SLA status
    from collections import defaultdict
    rows = db.query(Item).filter(Item.status.in_(("open","in-progress","awaiting-credit"))).order_by(Item.vendor.asc(), Item.created_at.asc()).all()
    summary = defaultdict(lambda: {"overdue": [], "due": [], "ok": []})
    for it in rows:
        v = db.query(Vendor).filter(Vendor.name.ilike(it.vendor)).first() if it.vendor else None
        status, days_left = compute_sla(it, v)
        it_slim = {
            "id": it.id,
            "title": it.title,
            "po": it.po_number,
            "sku": it.sku,
            "created_at": (it.created_at or datetime.utcnow()).isoformat(),
            "days_left": days_left,
            "vendor": it.vendor or "Unknown",
            "status": it.status
        }
        if status == "overdue":
            summary[it_slim["vendor"]]["overdue"].append(it_slim)
        elif status == "due":
            summary[it_slim["vendor"]]["due"].append(it_slim)
        else:
            summary[it_slim["vendor"]]["ok"].append(it_slim)
    # Build a simple HTML
    html_parts = [f"<h2>SLA Digest — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</h2>"]
    for vendor, groups in summary.items():
        total = sum(len(v) for v in groups.values())
        if total == 0: 
            continue
        html_parts.append(f"<h3>{vendor} — {total} open</h3>")
        for label in ("overdue","due","ok"):
            items = groups[label]
            if not items: continue
            color = {"overdue":"#991b1b", "due":"#92400e", "ok":"#166534"}[label]
            html_parts.append(f"<div style='color:{color};font-weight:600;text-transform:uppercase;margin:6px 0'>{label} ({len(items)})</div>")
            html_parts.append("<ul>")
            for r in items[:100]:
                html_parts.append(f"<li>#{r['id']} · PO {r['po'] or '-'} · SKU {r['sku'] or '-'} · {r['title'] or 'Item'} · days_left={r['days_left']}</li>")
            html_parts.append("</ul>")
    return {"summary": summary, "html": "\n".join(html_parts)}

def notify(event_type, data):
    if not OUTGOING_WEBHOOK_URL:
        return
    try:
        requests.post(OUTGOING_WEBHOOK_URL, json={
            "event": event_type,
            "data": data,
            "ts": datetime.utcnow().isoformat()
        }, timeout=5)
    except Exception:
        # Best-effort only
        pass

# ---------------------
# UI Routes
# ---------------------

@app.route("/")
@require_login
def index():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    vendor = request.args.get("vendor", "").strip()
    date_from = request.args.get("date_from", "").strip()
    sla = request.args.get("sla","").strip()

    db = SessionLocal()
    query = db.query(Item)
    if q:
        like = f"%{q}%"
        query = query.filter((Item.title.ilike(like)) | (Item.po_number.ilike(like)) | (Item.sku.ilike(like)))
    if status:
        query = query.filter(Item.status == status)
    if vendor:
        query = query.filter(Item.vendor.ilike(f"%{vendor}%"))
    if date_from:
        try:
            dt = datetime.fromisoformat(date_from)
            query = query.filter(Item.created_at >= dt)
        except Exception:
            pass
    items = query.order_by(Item.updated_at.desc()).limit(500).all()
    # compute SLA per item and optionally filter
    items_annotated = []
    for it in items:
        v = db.query(Vendor).filter(Vendor.name.ilike(it.vendor)).first() if it.vendor else None
        sla_status, days_left = compute_sla(it, v)
        it.sla_status = sla_status
        it.sla_days_left = days_left
        if sla == "overdue" and sla_status != "overdue":
            continue
        if sla == "due" and sla_status != "due":
            continue
        if sla == "ok" and sla_status != "ok":
            continue
        items_annotated.append(it)
    db.close()

    return render_template("index.html", items=items_annotated, statuses=STATUSES)

@app.route("/item/new", methods=["GET", "POST"])
@require_login
@require_role('admin','accountant')
def new_item():
    if request.method == "POST":
        db = SessionLocal()
        it = Item(
            title=request.form.get("title"),
            vendor=request.form.get("vendor"),
            po_number=request.form.get("po_number"),
            sku=request.form.get("sku"),
            quantity=int(request.form.get("quantity") or 1),
            unit_cost=to_decimal(request.form.get("unit_cost")),
            description=request.form.get("description"),
            status=request.form.get("status") or "open",
        )
        db.add(it)
        db.commit()
        flash("Item created.")
        notify("item.created", {"id": it.id, "po": it.po_number, "sku": it.sku})
        db.close()
        return redirect(url_for("item_detail", item_id=it.id))
    return render_template("new_item.html", statuses=STATUSES)

@app.route("/item/<int:item_id>")
@require_login
def item_detail(item_id):
    db = SessionLocal()
    it = db.query(Item).get(item_id)
    if not it:
        db.close()
        abort(404)
    emails = db.query(EmailLog).filter(EmailLog.item_id == item_id).order_by(EmailLog.received_at.desc().nullslast()).all()
    open_credits = db.query(Credit).filter(Credit.remaining_amount > decimal.Decimal("0.00")).order_by(Credit.created_at.desc()).all()
    applications = db.query(CreditApplication).filter(CreditApplication.item_id == item_id).order_by(CreditApplication.applied_date.desc()).all()
    item_vendor = db.query(Vendor).filter(Vendor.name.ilike(it.vendor)).first() if it.vendor else None
    sla_status, days_left = compute_sla(it, item_vendor)
    it.sla_status = sla_status
    it.sla_days_left = days_left if days_left is not None else "-"
    resp = render_template("item_detail.html", item=it, item_vendor=item_vendor, emails=emails, statuses=STATUSES, open_credits=open_credits, applications=applications)
    db.close()
    return resp

@app.route("/item/<int:item_id>/status", methods=["POST"])
@require_login
def update_item_status(item_id):
    status = request.form.get("status")
    if status not in STATUSES:
        flash("Invalid status.")
        return redirect(url_for("item_detail", item_id=item_id))
    db = SessionLocal()
    it = db.query(Item).get(item_id)
    if not it:
        db.close()
        abort(404)
    it.status = status
    db.commit()
    flash("Status updated.")
    notify("item.status", {"id": it.id, "status": it.status})
    db.close()
    return redirect(url_for("item_detail", item_id=item_id))

@app.route("/item/<int:item_id>/attach", methods=["POST"])
@require_login
def add_attachment(item_id):
    url = (request.form.get("url") or "").strip()
    name = request.form.get("name") or None
    if not url:
        flash("Please provide a URL.")
        return redirect(url_for("item_detail", item_id=item_id))

    db = SessionLocal()
    it = db.query(Item).get(item_id)
    if not it:
        db.close()
        abort(404)

    # Try to detect if it's a Google Drive link
    parsed = urlparse(url)
    drive_id = None
    if "drive.google.com" in parsed.netloc and "/file/d/" in parsed.path:
        # pattern: /file/d/<id>/view
        parts = parsed.path.split("/")
        if "d" in parts:
            try:
                drive_id = parts[parts.index("d")+1]
            except Exception:
                drive_id = None

    att = Attachment(
        item_id=item_id,
        drive_file_id=drive_id,
        drive_file_url=url if drive_id else None,
        webview_link=url,
        filename=name or os.path.basename(parsed.path) or "link",
        mime_type="link",
        name=name
    )
    db.add(att)
    db.commit()
    flash("Attachment added.")
    db.close()
    return redirect(url_for("item_detail", item_id=item_id))

@app.route("/credits")
@require_login
def credits():
    db = SessionLocal()
    creds = db.query(Credit).order_by(Credit.created_at.desc()).all()
    db.close()
    return render_template("credits.html", credits=creds)

@app.route("/credit/new", methods=["GET", "POST"])
@require_login
def new_credit():
    if request.method == "POST":
        db = SessionLocal()
        original_amount = to_decimal(request.form.get("original_amount") or "0")
        issued_date = request.form.get("issued_date") or None
        if issued_date:
            try:
                issued_date = datetime.strptime(issued_date, "%Y-%m-%d").date()
            except ValueError:
                issued_date = None
        c = Credit(
            reference=request.form.get("reference"),
            vendor=request.form.get("vendor"),
            original_amount=original_amount,
            remaining_amount=original_amount,
            issued_date=issued_date,
            notes=request.form.get("notes")
        )
        db.add(c)
        db.commit()
        flash("Credit created.")
        notify("credit.created", {"id": c.id, "reference": c.reference, "amount": float(c.original_amount)})
        db.close()
        return redirect(url_for("credits"))
    return render_template("new_credit.html")

@app.route("/credit/<int:credit_id>")
@require_login
def credit_detail(credit_id):
    db = SessionLocal()
    c = db.query(Credit).get(credit_id)
    if not c:
        db.close()
        abort(404)
    applications = db.query(CreditApplication).filter(CreditApplication.credit_id == credit_id).order_by(CreditApplication.applied_date.desc()).all()
    resp = render_template("credit_detail.html", credit=c, applications=applications)
    db.close()
    return resp

@app.route("/item/<int:item_id>/apply-credit", methods=["POST"])
@require_login
def apply_credit(item_id):
    credit_id = int(request.form.get("credit_id"))
    amount = to_decimal(request.form.get("amount") or "0")
    if not amount or amount <= decimal.Decimal("0.00"):
        flash("Amount must be > 0")
        return redirect(url_for("item_detail", item_id=item_id))

    db = SessionLocal()
    c = db.query(Credit).get(credit_id)
    it = db.query(Item).get(item_id)
    if not c or not it:
        db.close()
        abort(404)
    if c.remaining_amount < amount:
        flash("Not enough remaining on this credit.")
        db.close()
        return redirect(url_for("item_detail", item_id=item_id))

    ap = CreditApplication(credit_id=credit_id, item_id=item_id, amount_applied=amount)
    c.remaining_amount = (c.remaining_amount or decimal.Decimal("0")) - amount
    db.add(ap)
    db.commit()
    flash("Credit applied.")
    notify("credit.applied", {"credit_id": c.id, "item_id": it.id, "amount": float(amount)})
    db.close()
    return redirect(url_for("item_detail", item_id=item_id))

# ---------------------
# Zapier Webhook
# ---------------------

def check_bearer():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return False
    token = auth.split(" ", 1)[1].strip()
    return token and (token == ZAPIER_SECRET)

@app.route("/zap/webhook", methods=["POST"])
def zap_webhook():
    if not check_bearer():
        return {"error": "unauthorized"}, 401

    try:
        payload = request.get_json(silent=True) or {}
    except Exception:
        payload = {}

    parsed = parse_email_payload(payload)

    db = SessionLocal()

    # Try to find existing item by PO or SKU
    it = None
    if parsed["po"]:
        it = db.query(Item).filter(Item.po_number == parsed["po"]).order_by(Item.created_at.desc()).first()
    if not it and parsed["sku"]:
        it = db.query(Item).filter(Item.sku == parsed["sku"]).order_by(Item.created_at.desc()).first()

    created = False
    if not it:
        it = Item(
            title=parsed["subject"][:240] if parsed["subject"] else "Damage/Claim",
            vendor=parsed["vendor"],
            po_number=parsed["po"],
            sku=parsed["sku"],
            description=parsed["body_snippet"],
            status="open"
        )
        db.add(it)
        db.commit()
        created = True

    # Attachments
    for att in parsed["attachments"]:
        db.add(Attachment(
            item_id=it.id,
            drive_file_id=att.get("drive_file_id"),
            drive_file_url=att.get("webview_link") or att.get("drive_file_url"),
            webview_link=att.get("webview_link") or att.get("drive_file_url"),
            filename=att.get("name") or "attachment",
            mime_type=att.get("mime_type"),
            source="zap"
        ))

    # Email log
    received_at = None
    try:
        if parsed["received_at"]:
            received_at = datetime.fromisoformat(parsed["received_at"])
    except Exception:
        received_at = None

    db.add(EmailLog(
        item_id=it.id,
        vendor=parsed["vendor"],
        gmail_msg_id=parsed["gmail_msg_id"],
        subject=parsed["subject"],
        from_address=parsed["from"],
        to_address=parsed["to"],
        body_snippet=parsed["body_snippet"],
        received_at=received_at,
        payload_json=json.dumps({k: v for k, v in (request.get_json(silent=True) or {}).items() if k != "body_html"})[:8000]
    ))

    # Auto-create credit if email contained a "Credit $X" and vendor known
    if parsed["credit_amount"] and parsed["credit_amount"] > decimal.Decimal("0"):
        amount = parsed["credit_amount"]
        c = Credit(
            reference=f"Email credit {datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            vendor=parsed["vendor"],
            original_amount=amount,
            remaining_amount=amount,
            notes=f"Auto-created from email: {parsed['subject'][:200]}"
        )
        db.add(c)
        db.commit()

    db.commit()

    notify("zap.ingested", {"item_id": it.id, "created": created})
    db.close()

    return {"ok": True, "item_id": it.id, "created": created}

# ---------------------
# Dev entrypoint
# ---------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)

@app.route("/export/items.csv")
@require_login
def export_items_csv():
    db = SessionLocal()
    items = db.query(Item).order_by(Item.created_at.desc()).all()
    db.close()
    from io import StringIO
    import csv as _csv
    sio = StringIO()
    w = _csv.writer(sio)
    w.writerow(["id","title","vendor","po_number","sku","quantity","unit_cost","status","created_at","updated_at"])
    for it in items:
        w.writerow([it.id, it.title, it.vendor, it.po_number, it.sku, it.quantity, it.unit_cost, it.status, it.created_at, it.updated_at])
    from flask import Response
    return Response(sio.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=items.csv"})

@app.route("/export/credits.csv")
@require_login
def export_credits_csv():
    db = SessionLocal()
    credits = db.query(Credit).order_by(Credit.created_at.desc()).all()
    db.close()
    from io import StringIO
    import csv as _csv
    sio = StringIO()
    w = _csv.writer(sio)
    w.writerow(["id","reference","vendor","original_amount","remaining_amount","issued_date","created_at","notes"])
    for c in credits:
        w.writerow([c.id, c.reference, c.vendor, c.original_amount, c.remaining_amount, c.issued_date, c.created_at, (c.notes or "").replace("\n"," ")[:200]])
    from flask import Response
    return Response(sio.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=credits.csv"})

@app.route("/vendors")
@require_login
def vendors():
    db = SessionLocal()
    vs = db.query(Vendor).order_by(Vendor.name.asc()).all()
    db.close()
    return render_template("vendors.html", vendors=vs)

@app.route("/vendor/new", methods=["GET","POST"])
@require_role('admin','accountant')
def vendor_new():
    if request.method == "POST":
        db = SessionLocal()
        v = Vendor(
            name=request.form.get("name"),
            email=request.form.get("email"),
            phone=request.form.get("phone"),
            sla_days=int(request.form.get("sla_days") or 0),
            email_template=request.form.get("email_template"),
            notes=request.form.get("notes")
        )
        db.add(v); db.commit()
        log_change(current_role(), "create", "vendor", v.id, {"name": v.name})
        db.close()
        flash("Vendor created.")
        return redirect(url_for("vendors"))
    return render_template("vendor_form.html", vendor=None)

@app.route("/vendor/<int:vendor_id>", methods=["GET","POST"])
@require_role('admin','accountant')
def vendor_edit(vendor_id):
    db = SessionLocal()
    v = db.query(Vendor).get(vendor_id)
    if not v:
        db.close(); abort(404)
    if request.method == "POST":
        v.name = request.form.get("name")
        v.email = request.form.get("email")
        v.phone = request.form.get("phone")
        v.sla_days = int(request.form.get("sla_days") or 0)
        v.email_template = request.form.get("email_template")
        v.notes = request.form.get("notes")
        db.commit()
        log_change(current_role(), "update", "vendor", v.id, {"name": v.name})
        db.close()
        flash("Vendor updated.")
        return redirect(url_for("vendors"))
    resp = render_template("vendor_form.html", vendor=v)
    db.close()
    return resp

from io import TextIOWrapper
import csv as _csv

@app.route("/import", methods=["GET","POST"])
@require_role('admin','accountant')
def import_items():
    if request.method == "POST":
        f = request.files.get("file")
        if not f:
            flash("No file"); return redirect(url_for("import_items"))
        db = SessionLocal()
        reader = _csv.DictReader(TextIOWrapper(f.stream, encoding='utf-8'))
        count = 0
        for row in reader:
            it = Item(
                title=row.get("title") or None,
                vendor=row.get("vendor") or None,
                po_number=row.get("po_number") or None,
                sku=row.get("sku") or None,
                quantity=int(row.get("quantity") or 1),
                unit_cost=to_decimal(row.get("unit_cost")),
                description=row.get("description") or None,
                status=row.get("status") or "open",
            )
            db.add(it); db.commit()
            # attachments as comma-separated URLs
            atts = (row.get("attachments") or "").split(",")
            for u in [a.strip() for a in atts if a.strip()]:
                db.add(Attachment(item_id=it.id, webview_link=u, filename="link", mime_type="link"))
            count += 1
        db.commit()
        log_change(current_role(), "import", "items", 0, {"count": count})
        db.close()
        flash(f"Imported {count} items.")
        return redirect(url_for("index"))
    return render_template("import_items.html")

@app.route("/import/credits", methods=["POST"])
@require_role('admin','accountant')
def import_credits():
    f = request.files.get("file")
    if not f:
        flash("No file"); return redirect(url_for("import_items"))
    db = SessionLocal()
    reader = _csv.DictReader(TextIOWrapper(f.stream, encoding='utf-8'))
    count = 0
    for row in reader:
        amount = to_decimal(row.get("original_amount"))
        issued_date = None
        if row.get("issued_date"):
            try:
                issued_date = datetime.fromisoformat(row.get("issued_date")).date()
            except Exception:
                issued_date = None
        c = Credit(
            reference=row.get("reference") or None,
            vendor=row.get("vendor") or None,
            original_amount=amount or 0,
            remaining_amount=amount or 0,
            issued_date=issued_date,
            notes=row.get("notes") or None
        )
        db.add(c); db.commit(); count += 1
    db.close()
    flash(f"Imported {count} credits.")
    return redirect(url_for("credits"))

@app.route("/bulk/apply-credit", methods=["POST"])
@require_role('admin','accountant')
def bulk_apply_credit():
    credit_id = int(request.form.get("credit_id") or 0)
    total_amount = to_decimal(request.form.get("total_amount") or "0")
    item_ids = request.form.getlist("item_ids")
    item_ids = [int(x) for x in item_ids if x.isdigit()]
    if not credit_id or not total_amount or total_amount <= decimal.Decimal("0") or not item_ids:
        flash("Select items, a credit, and a total amount."); return redirect(url_for("index"))
    db = SessionLocal()
    c = db.query(Credit).get(credit_id)
    if not c or c.remaining_amount < total_amount:
        db.close(); flash("Not enough remaining on credit."); return redirect(url_for("index"))
    share = (total_amount / decimal.Decimal(len(item_ids))).quantize(decimal.Decimal("0.01"))
    applied_total = decimal.Decimal("0.00")
    for iid in item_ids:
        it = db.query(Item).get(iid)
        if not it: continue
        if c.remaining_amount < share: break
        ap = CreditApplication(credit_id=credit_id, item_id=iid, amount_applied=share)
        c.remaining_amount -= share
        db.add(ap); db.commit()
        applied_total += share
    log_change(current_role(), "bulk_apply_credit", "credit", c.id, {"applied_total": float(applied_total), "items": item_ids})
    flash(f"Applied ${applied_total} across {len(item_ids)} items.")
    db.close()
    return redirect(url_for("index"))

@app.route("/item/<int:item_id>/contact", methods=["POST"])
@require_role('admin','accountant')
def contact_vendor_webhook(item_id):
    if not OUTGOING_WEBHOOK_URL:
        flash("Set OUTGOING_WEBHOOK_URL to use Zapier send."); return redirect(url_for("item_detail", item_id=item_id))
    db = SessionLocal()
    it = db.query(Item).get(item_id)
    db.close()
    subject = request.form.get("subject")
    body = request.form.get("body")
    to = request.form.get("to")
    notify("vendor.contact_request", {"item_id": it.id, "to": to, "subject": subject, "body": body})
    flash("Sent to Zapier.")
    return redirect(url_for("item_detail", item_id=item_id))

@app.route("/users")
@require_role('admin')
def users():
    db = SessionLocal()
    users = db.query(User).order_by(User.created_at.desc()).all()
    cu = get_current_user()
    db.close()
    return render_template("users.html", users=users)

@app.route("/users/new", methods=["GET","POST"])
@require_role('admin')
def user_new():
    if request.method == "POST":
        email = request.form.get("email","").strip().lower()
        role = request.form.get("role","viewer")
        password = request.form.get("password","")
        if not email or not password:
            flash("Email and password required."); return redirect(url_for("user_new"))
        db = SessionLocal()
        if db.query(User).filter(User.email == email).first():
            db.close(); flash("Email already exists."); return redirect(url_for("user_new"))
        u = User(email=email, role=role, password_hash=generate_password_hash(password))
        db.add(u); db.commit(); db.close()
        flash("User created.")
        return redirect(url_for("users"))
    return render_template("user_form.html", user=None)

@app.route("/users/<int:user_id>", methods=["GET","POST"])
@require_role('admin')
def user_edit(user_id):
    db = SessionLocal()
    u = db.query(User).get(user_id)
    if not u:\n        db.close(); abort(404)
    if request.method == "POST":
        u.email = request.form.get("email","").strip().lower()
        u.role = request.form.get("role","viewer")
        pw = request.form.get("password","")
        if pw:
            u.password_hash = generate_password_hash(pw)
        db.commit(); db.close()
        flash("User updated.")
        return redirect(url_for("users"))
    resp = render_template("user_form.html", user=u)
    db.close()
    return resp

@app.route("/users/<int:user_id>/delete", methods=["POST"])
@require_role('admin')
def user_delete(user_id):
    db = SessionLocal()
    u = db.query(User).get(user_id)
    if not u:\n        db.close(); abort(404)
    db.delete(u); db.commit(); db.close()
    flash("User deleted.")
    return redirect(url_for("users"))

@app.route("/import/vendors", methods=["POST"])
@require_role('admin','accountant')
def import_vendors():
    from io import TextIOWrapper
    import csv as _csv
    f = request.files.get("file")
    if not f:
        flash("No file"); return redirect(url_for("vendors"))
    db = SessionLocal()
    reader = _csv.DictReader(TextIOWrapper(f.stream, encoding='utf-8'))
    count = 0
    for row in reader:
        name = row.get("name")
        if not name: continue
        v = db.query(Vendor).filter(Vendor.name.ilike(name)).first()
        if not v:
            v = Vendor(name=name)
            db.add(v)
        v.email = row.get("email") or v.email
        v.phone = row.get("phone") or v.phone
        try:\n            v.sla_days = int(row.get("sla_days") or v.sla_days or 0)\n        except Exception:\n            pass\n        v.notes = row.get("notes") or v.notes
        v.email_template = row.get("email_template") or v.email_template
        db.commit(); count += 1
    db.close()
    flash(f"Imported/updated {count} vendors.")
    return redirect(url_for("vendors"))

@app.route("/item/<int:item_id>/print")
@require_login
def print_item(item_id):
    db = SessionLocal()
    it = db.query(Item).get(item_id)
    if not it: db.close(); abort(404)
    applications = db.query(CreditApplication).filter(CreditApplication.item_id == item_id).order_by(CreditApplication.applied_date.desc()).all()
    vendor = db.query(Vendor).filter(Vendor.name.ilike(it.vendor)).first() if it.vendor else None
    html = render_template("print_item.html", item=it, applications=applications, vendor=vendor, now=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    db.close()
    return html

@app.route("/item/<int:item_id>/pdf")
@require_login
def pdf_item(item_id):
    from reportlab.lib.pagesizes import LETTER
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    from io import BytesIO

    db = SessionLocal()
    it = db.query(Item).get(item_id)
    if not it: db.close(); abort(404)
    applications = db.query(CreditApplication).filter(CreditApplication.item_id == item_id).order_by(CreditApplication.applied_date.desc()).all()
    vendor = db.query(Vendor).filter(Vendor.name.ilike(it.vendor)).first() if it.vendor else None

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=LETTER)
    width, height = LETTER
    y = height - 50
    def line(txt, size=10):
        nonlocal y
        c.setFont("Helvetica", size)
        c.drawString(50, y, txt[:110])
        y -= 14

    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, f"Damage Claim Packet — Item {it.id}"); y -= 18
    c.setFont("Helvetica", 9)
    c.drawString(50, y, datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")); y -= 18

    line(f"Title: {it.title or 'Item'}", 11)
    line(f"Vendor: {it.vendor or '-'}  Contact: {(vendor.email if vendor else '-')}, {(vendor.phone if vendor else '-')}", 10)
    line(f"PO: {it.po_number or '-'}  SKU: {it.sku or '-'}  Qty: {it.quantity}", 10)
    line(f"Status: {it.status}  Created: {it.created_at}  Updated: {it.updated_at}", 9)

    y -= 6
    c.setFont("Helvetica-Bold", 11); c.drawString(50, y, "Description/Notes"); y -= 14
    c.setFont("Helvetica", 9)
    for chunk in (it.description or "—").splitlines() or ["—"]:
        for i in range(0, len(chunk), 100):
            line(chunk[i:i+100], 9)

    y -= 6
    c.setFont("Helvetica-Bold", 11); c.drawString(50, y, "Attachments"); y -= 14
    c.setFont("Helvetica", 9)
    if it.attachments:
        for a in it.attachments:
            link = (a.webview_link or a.drive_file_url or a.filename or "")[:100]
            line(f"- {a.name or a.filename or 'Attachment'} — {link}", 9)
    else:
        line("—", 9)

    y -= 6
    c.setFont("Helvetica-Bold", 11); c.drawString(50, y, "Credits Applied"); y -= 14
    c.setFont("Helvetica", 9)
    if applications:
        for ap in applications:
            ref = ap.credit.reference if ap.credit else "Credit"
            when = ap.applied_date.strftime("%Y-%m-%d")
            line(f"- ${ap.amount_applied} from {ref} ({when})", 9)
    else:
        line("—", 9)

    c.showPage(); c.save()
    buf.seek(0)
    fname = f"claim_item_{item_id}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=fname)

@app.route("/reports/sla")
@require_role('admin','accountant')
def sla_report():
    db = SessionLocal()
    payload = build_sla_digest(db)
    db.close()
    if request.args.get("format") == "html":
        return payload["html"]
    return payload

@app.route("/send/sla-digest", methods=["POST"])
@require_role('admin','accountant')
def send_sla_digest():
    db = SessionLocal()
    payload = build_sla_digest(db)
    db.close()
    if not OUTGOING_WEBHOOK_URL:
        flash("Set OUTGOING_WEBHOOK_URL to deliver digest via Zapier."); 
        return redirect(url_for("index"))
    notify("digest.sla", {"html": payload["html"], "summary": payload["summary"]})
    flash("SLA digest sent to Zapier.")
    return redirect(url_for("index"))

@app.route("/zap/sla-digest", methods=["POST"])
def zap_sla_digest():
    # For Zapier Schedule to hit daily; secured by Bearer
    if not check_bearer():
        return {"error": "unauthorized"}, 401
    db = SessionLocal()
    payload = build_sla_digest(db)
    db.close()
    notify("digest.sla", {"html": payload["html"], "summary": payload["summary"]})
    return {"ok": True}

def make_claim_pdf_bytes(item_id):
    from reportlab.lib.pagesizes import LETTER
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    from io import BytesIO

    db = SessionLocal()
    it = db.query(Item).get(item_id)
    applications = db.query(CreditApplication).filter(CreditApplication.item_id == item_id).order_by(CreditApplication.applied_date.desc()).all()
    vendor = db.query(Vendor).filter(Vendor.name.ilike(it.vendor)).first() if it.vendor else None
    db.close()

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=LETTER)
    width, height = LETTER
    y = height - 50
    def line(txt, size=10):
        nonlocal y
        c.setFont("Helvetica", size); c.drawString(50, y, txt[:110]); y -= 14

    c.setFont("Helvetica-Bold", 14); c.drawString(50, y, f"Damage Claim Packet — Item {it.id}"); y -= 18
    c.setFont("Helvetica", 9); c.drawString(50, y, datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")); y -= 18
    line(f"Title: {it.title or 'Item'}", 11)
    line(f"Vendor: {it.vendor or '-'}  Contact: {(vendor.email if vendor else '-')}, {(vendor.phone if vendor else '-')}", 10)
    line(f"PO: {it.po_number or '-'}  SKU: {it.sku or '-'}  Qty: {it.quantity}", 10)
    line(f"Status: {it.status}  Created: {it.created_at}  Updated: {it.updated_at}", 9)
    y -= 6; c.setFont("Helvetica-Bold", 11); c.drawString(50, y, "Attachments"); y -= 14
    c.setFont("Helvetica", 9)
    if it.attachments:
        for a in it.attachments:
            link = (a.webview_link or a.drive_file_url or a.filename or "")[:100]
            line(f"- {a.name or a.filename or 'Attachment'} — {link}", 9)
    else:
        line("—", 9)
    y -= 6; c.setFont("Helvetica-Bold", 11); c.drawString(50, y, "Credits Applied"); y -= 14
    c.setFont("Helvetica", 9)
    if applications:
        for ap in applications:
            ref = ap.credit.reference if ap.credit else "Credit"
            when = ap.applied_date.strftime("%Y-%m-%d")
            line(f"- ${ap.amount_applied} from {ref} ({when})", 9)
    else:
        line("—", 9)
    c.showPage(); c.save(); buf.seek(0)
    return buf.getvalue()

@app.route("/item/<int:item_id>/send-claim", methods=["POST"])
@require_role('admin','accountant')
def send_claim(item_id):
    if not OUTGOING_WEBHOOK_URL:
        flash("Set OUTGOING_WEBHOOK_URL to deliver claim packet via Zapier."); 
        return redirect(url_for("item_detail", item_id=item_id))

    db = SessionLocal()
    it = db.query(Item).get(item_id)
    vendor = db.query(Vendor).filter(Vendor.name.ilike(it.vendor)).first() if it.vendor else None
    db.close()

    to = request.form.get("to") or (vendor.email if vendor else None)
    subject = request.form.get("subject") or f"Damage claim: PO {it.po_number or '-'} · SKU {it.sku or '-'} · {it.vendor or ''}"
    body = request.form.get("body") or f"Hello {it.vendor or ''},\\n\\nAttached is the claim packet for PO {it.po_number or '-'} / SKU {it.sku or '-'}.\\nLinks to photos are inside the packet.\\n\\nThank you,\\nFowhand Furniture Claims"
    pdf_bytes = make_claim_pdf_bytes(item_id)
    pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")

    notify("vendor.claim_packet", {
        "to": to,
        "subject": subject,
        "body": body,
        "attachments": [{
            "filename": f"claim_item_{item_id}.pdf",
            "content_type": "application/pdf",
            "content_base64": pdf_b64
        }],
        "item_id": item_id
    })
    flash("Claim packet sent to Zapier.")
    return redirect(url_for("item_detail", item_id=item_id))

@app.route("/reports")
@require_role('admin','accountant')
def reports():
    return render_template("reports.html")

@app.route("/api/reports/credits-by-vendor")
@require_role('admin','accountant')
def credits_by_vendor():
    db = SessionLocal()
    rows = db.query(Credit.vendor, Credit.original_amount, Credit.remaining_amount).all()
    db.close()
    agg = {}
    for vendor, orig, rem in rows:
        v = vendor or "Unknown"
        d = agg.setdefault(v, {"used": 0.0, "remaining": 0.0})
        o = float(orig or 0)
        r = float(rem or 0)
        d["remaining"] += r
        d["used"] += max(o - r, 0)
    labels = sorted(agg.keys())
    used = [agg[k]["used"] for k in labels]
    remaining = [agg[k]["remaining"] for k in labels]
    return {"labels": labels, "used": used, "remaining": remaining}

@app.route("/api/reports/items-by-month")
@require_role('admin','accountant')
def items_by_month():
    db = SessionLocal()
    rows = db.query(Item.created_at).all()
    db.close()
    from collections import Counter
    c = Counter()
    for (dt,) in rows:
        if not dt: continue
        key = dt.strftime("%Y-%m")
        c[key] += 1
    labels = sorted(c.keys())
    counts = [c[k] for k in labels]
    return {"labels": labels, "counts": counts}

@app.route("/api/reports/avg-days-to-credit-by-vendor")
@require_role('admin','accountant')
def avg_days_to_credit_by_vendor():
    db = SessionLocal()
    # compute days from item.created_at to latest credit application date for that item
    from collections import defaultdict
    latest_applied = defaultdict(lambda: None)
    for ap in db.query(CreditApplication).all():
        if ap.item_id not in latest_applied or (latest_applied[ap.item_id] and ap.applied_date and ap.applied_date > latest_applied[ap.item_id]):
            latest_applied[ap.item_id] = ap.applied_date
    sums = {}
    counts = {}
    for it in db.query(Item).all():
        if it.id in latest_applied and latest_applied[it.id] and it.created_at:
            days = (latest_applied[it.id] - it.created_at).days
            v = it.vendor or "Unknown"
            sums[v] = sums.get(v, 0) + max(days, 0)
            counts[v] = counts.get(v, 0) + 1
    db.close()
    labels = sorted(sums.keys())
    avg_days = [ round(sums[k] / counts[k], 1) for k in labels ]
    return {"labels": labels, "avg_days": avg_days}

@app.route("/item/<int:item_id>/upload-to-drive", methods=["POST"])
@require_role('admin','accountant')
def upload_to_drive(item_id):
    if not OUTGOING_WEBHOOK_URL:
        flash("Set OUTGOING_WEBHOOK_URL to enable Drive uploads via Zap."); 
        return redirect(url_for("item_detail", item_id=item_id))
    f = request.files.get("file")
    if not f or not f.filename:
        flash("No file provided."); 
        return redirect(url_for("item_detail", item_id=item_id))
    import base64, mimetypes
    content = base64.b64encode(f.read()).decode("ascii")
    mime = f.mimetype or mimetypes.guess_type(f.filename)[0] or "application/octet-stream"
    notify("file.upload_request", {
        "item_id": item_id,
        "filename": f.filename,
        "content_base64": content,
        "content_type": mime
    })
    flash("Sent to Zap for Drive upload. It will attach automatically when Zap calls back.")
    return redirect(url_for("item_detail", item_id=item_id))

@app.route("/zap/attach", methods=["POST"])
def zap_attach():
    # Zap callback: attach a Drive file link to an item
    if not check_bearer():
        return {"error": "unauthorized"}, 401
    payload = request.get_json(silent=True) or {}
    item_id = payload.get("item_id")
    link = payload.get("webview_link") or payload.get("url")
    name = payload.get("name") or "attachment"
    mime_type = payload.get("mime_type") or "link"
    drive_file_id = payload.get("drive_file_id")
    if not item_id or not link:
        return {"error": "missing item_id/link"}, 400
    db = SessionLocal()
    it = db.query(Item).get(int(item_id))
    if not it:\n        db.close(); return {"error":"item not found"}, 404
    att = Attachment(item_id=it.id, drive_file_id=drive_file_id, drive_file_url=link, webview_link=link, filename=name, mime_type=mime_type, source="zap")
    db.add(att); db.commit(); db.close()
    return {"ok": True}
