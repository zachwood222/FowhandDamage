import os, re, json, decimal, requests
from datetime import datetime, date, timedelta
from flask import (
    Flask, request, redirect, url_for, render_template, flash, session, abort,
    Response, send_file, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, Date, ForeignKey,
    Numeric, Boolean
)
from sqlalchemy.orm import sessionmaker, relationship, declarative_base

# ---------- Config ----------

def normalize_db_url(db_url: str | None) -> str:
    if not db_url:
        return "sqlite:///local.db"
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql+psycopg://", 1)
    elif db_url.startswith("postgresql://") and "+psycopg" not in db_url:
        db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)
    return db_url

DATABASE_URL = normalize_db_url(os.getenv("DATABASE_URL"))
SECRET_KEY = os.getenv("SECRET_KEY", "please-change-me")
ZAPIER_SECRET = os.getenv("ZAPIER_SECRET", "")
OUTGOING_WEBHOOK_URL = os.getenv("OUTGOING_WEBHOOK_URL", "")

app = Flask(__name__)
app.secret_key = SECRET_KEY

engine = create_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)
Base = declarative_base()

# ---------- Helpers ----------

STATUSES = ["open", "in-progress", "awaiting-credit", "resolved", "closed"]

def to_decimal(val):
    if val is None or val == "":
        return decimal.Decimal("0.00")
    if isinstance(val, (int, float, decimal.Decimal)):
        return decimal.Decimal(str(val)).quantize(decimal.Decimal("0.01"))
    s = str(val).strip().replace(",", "")
    m = re.search(r"-?\d+(?:\.\d{1,2})?", s)
    if not m:
        return decimal.Decimal("0.00")
    return decimal.Decimal(m.group(0)).quantize(decimal.Decimal("0.01"))

po_re = re.compile(r"\bPO[:#\s]*([A-Za-z0-9-]+)\b", re.I)
sku_re = re.compile(r"\bSKU[:#\s]*([A-Za-z0-9-]+)\b", re.I)
credit_re = re.compile(r"\bCredit\s*\$?\s*([0-9,.]+)\b", re.I)

def notify(event_type: str, data: dict):
    if not OUTGOING_WEBHOOK_URL:
        return {"skipped": True}
    try:
        requests.post(
            OUTGOING_WEBHOOK_URL,
            headers={"Content-Type": "application/json"},
            data=json.dumps({"event": event_type, "data": data})
        )
    except Exception:
        pass

def check_bearer():
    if not ZAPIER_SECRET:
        return False
    auth = request.headers.get("Authorization", "")
    return auth == f"Bearer {ZAPIER_SECRET}"

# ---------- Models ----------

class Item(Base):
    __tablename__ = "items"
    id = Column(Integer, primary_key=True)
    title = Column(String(255))
    vendor = Column(String(255), index=True)
    po_number = Column(String(128), index=True)
    sku = Column(String(128), index=True)
    quantity = Column(Integer, default=1)
    unit_cost = Column(Numeric(12, 2), default=decimal.Decimal("0.00"))
    description = Column(Text)
    status = Column(String(32), default="open", index=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    attachments = relationship("Attachment", back_populates="item", cascade="all, delete-orphan")
    applications = relationship("CreditApplication", back_populates="item", cascade="all, delete-orphan")

class Attachment(Base):
    __tablename__ = "attachments"
    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey("items.id", ondelete="CASCADE"), index=True)
    drive_file_id = Column(String(256))
    drive_file_url = Column(Text)
    webview_link = Column(Text)
    filename = Column(String(255))
    name = Column(String(255))
    mime_type = Column(String(128))
    source = Column(String(64))  # zap, upload, email
    created_at = Column(DateTime, default=datetime.utcnow)
    item = relationship("Item", back_populates="attachments")

class Credit(Base):
    __tablename__ = "credits"
    id = Column(Integer, primary_key=True)
    reference = Column(String(255))
    vendor = Column(String(255), index=True)
    original_amount = Column(Numeric(12, 2), default=decimal.Decimal("0.00"))
    remaining_amount = Column(Numeric(12, 2), default=decimal.Decimal("0.00"))
    issued_date = Column(Date)
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    applications = relationship("CreditApplication", back_populates="credit", cascade="all, delete-orphan")

class CreditApplication(Base):
    __tablename__ = "credit_applications"
    id = Column(Integer, primary_key=True)
    credit_id = Column(Integer, ForeignKey("credits.id", ondelete="CASCADE"), index=True)
    item_id = Column(Integer, ForeignKey("items.id", ondelete="CASCADE"), index=True)
    amount_applied = Column(Numeric(12, 2), default=decimal.Decimal("0.00"))
    applied_date = Column(Date, default=date.today)
    credit = relationship("Credit", back_populates="applications")
    item = relationship("Item", back_populates="applications")

class EmailLog(Base):
    __tablename__ = "email_logs"
    id = Column(Integer, primary_key=True)
    item_id = Column(Integer, ForeignKey("items.id", ondelete="SET NULL"), nullable=True, index=True)
    from_addr = Column(String(255))
    to_addr = Column(String(255))
    subject = Column(Text)
    body = Column(Text)
    received_at = Column(DateTime, default=datetime.utcnow)
    message_id = Column(String(255), index=True)

class Vendor(Base):
    __tablename__ = "vendors"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    email = Column(String(255))
    phone = Column(String(64))
    sla_days = Column(Integer)
    email_template = Column(Text)
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

class ChangeLog(Base):
    __tablename__ = "changelog"
    id = Column(Integer, primary_key=True)
    actor_role = Column(String(32))
    action = Column(String(64))
    entity = Column(String(64))
    entity_id = Column(Integer)
    details = Column(Text)
    at = Column(DateTime, default=datetime.utcnow)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), default="viewer", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(engine)

# ---------- Auth / Roles ----------

def get_current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = SessionLocal()
    try:
        return db.query(User).get(uid)
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

def require_role(*roles):
    def decorator(fn):
        from functools import wraps
        @wraps(fn)
        def wrapper(*args, **kwargs):
            u = get_current_user()
            if not u or (roles and u.role not in roles):
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator

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

# ---------- SLA ----------

def compute_sla(item, vendor):
    if not vendor or not vendor.sla_days:
        return None, None
    due_date = (item.created_at or datetime.utcnow()) + timedelta(days=int(vendor.sla_days or 0))
    days_left = (due_date - datetime.utcnow()).days
    if days_left < 0:
        return "overdue", days_left
    if days_left <= 3:
        return "due", days_left
    return "ok", days_left

# ---------- Auth routes ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    db = SessionLocal()
    user_count = db.query(User).count()
    db.close()
    show_bootstrap = (user_count == 0)
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
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
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
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

# ---------- Basic pages ----------

@app.route("/")
@require_login
def index():
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    vendor = request.args.get("vendor", "").strip()
    date_from = request.args.get("date_from", "").strip()
    sla = request.args.get("sla", "").strip()

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

# ---------- Items ----------

@app.route("/item/new", methods=["GET", "POST"])
@require_role("admin", "accountant")
def new_item():
    db = SessionLocal()
    if request.method == "POST":
        it = Item(
            title=request.form.get("title") or None,
            vendor=request.form.get("vendor") or None,
            po_number=request.form.get("po_number") or None,
            sku=request.form.get("sku") or None,
            quantity=int(request.form.get("quantity") or 1),
            unit_cost=to_decimal(request.form.get("unit_cost")),
            description=request.form.get("description") or None,
            status=request.form.get("status") or "open",
        )
        db.add(it); db.commit(); db.close()
        flash("Item created.")
        return redirect(url_for("item_detail", item_id=it.id))
    db.close()
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
@require_role("admin", "accountant")
def update_item_status(item_id):
    db = SessionLocal()
    it = db.query(Item).get(item_id)
    if not it:
        db.close()
        abort(404)
    it.status = request.form.get("status", it.status)
    it.updated_at = datetime.utcnow()
    db.commit(); db.close()
    flash("Status updated.")
    return redirect(url_for("item_detail", item_id=item_id))

@app.route("/item/<int:item_id>/attach", methods=["POST"])
@require_role("admin", "accountant")
def add_attachment(item_id):
    db = SessionLocal()
    it = db.query(Item).get(item_id)
    if not it:
        db.close()
        abort(404)
    url = request.form.get("url")
    if url:
        att = Attachment(item_id=item_id, webview_link=url, filename="link", mime_type="link", source="manual")
        db.add(att)
        db.commit()
    db.close()
    flash("Attachment added.")
    return redirect(url_for("item_detail", item_id=item_id))

# ---------- Credits ----------

@app.route("/credits", methods=["GET", "POST"])
@require_login
def credits():
    db = SessionLocal()
    if request.method == "POST":
        c = Credit(
            reference=request.form.get("reference") or None,
            vendor=request.form.get("vendor") or None,
            original_amount=to_decimal(request.form.get("original_amount")),
            remaining_amount=to_decimal(request.form.get("original_amount")),
            issued_date=(datetime.fromisoformat(request.form.get("issued_date")).date() if request.form.get("issued_date") else None),
            notes=request.form.get("notes") or None
        )
        db.add(c); db.commit()
        flash("Credit created.")
    rows = db.query(Credit).order_by(Credit.created_at.desc()).all()
    db.close()
    return render_template("credits.html", credits=rows)

@app.route("/credit/apply/<int:item_id>", methods=["POST"])
@require_role("admin", "accountant")
def apply_credit(item_id):
    db = SessionLocal()
    it = db.query(Item).get(item_id)
    if not it:
        db.close()
        abort(404)
    credit_id = int(request.form.get("credit_id"))
    amount = to_decimal(request.form.get("amount"))
    c = db.query(Credit).get(credit_id)
    if not c or c.remaining_amount < amount:
        db.close()
        flash("Not enough remaining on credit.")
        return redirect(url_for("item_detail", item_id=item_id))
    ap = CreditApplication(credit_id=credit_id, item_id=item_id, amount_applied=amount, applied_date=date.today())
    c.remaining_amount -= amount
    db.add(ap); db.commit(); db.close()
    flash("Credit applied.")
    return redirect(url_for("item_detail", item_id=item_id))

# ---------- Export ----------

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
    return Response(sio.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment; filename=credits.csv"})

# ---------- Vendors ----------

@app.route("/vendors")
@require_login
def vendors():
    db = SessionLocal()
    vs = db.query(Vendor).order_by(Vendor.name.asc()).all()
    db.close()
    return render_template("vendors.html", vendors=vs)

@app.route("/vendor/new", methods=["GET","POST"])
@require_role("admin","accountant")
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
        db.add(v); db.commit(); db.close()
        flash("Vendor created.")
        return redirect(url_for("vendors"))
    return render_template("vendor_form.html", vendor=None)

@app.route("/vendor/<int:vendor_id>", methods=["GET","POST"])
@require_role("admin","accountant")
def vendor_edit(vendor_id):
    db = SessionLocal()
    v = db.query(Vendor).get(vendor_id)
    if not v:
        db.close()
        abort(404)
    if request.method == "POST":
        v.name = request.form.get("name")
        v.email = request.form.get("email")
        v.phone = request.form.get("phone")
        try:
            v.sla_days = int(request.form.get("sla_days") or 0)
        except Exception:
            pass
        v.email_template = request.form.get("email_template")
        v.notes = request.form.get("notes")
        db.commit(); db.close()
        flash("Vendor updated.")
        return redirect(url_for("vendors"))
    resp = render_template("vendor_form.html", vendor=v)
    db.close()
    return resp

# ---------- Import ----------

from io import TextIOWrapper
import csv as _csv

@app.route("/import", methods=["GET","POST"])
@require_role("admin","accountant")
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
            atts = (row.get("attachments") or "").split(",")
            for u in [a.strip() for a in atts if a.strip()]:
                db.add(Attachment(item_id=it.id, webview_link=u, filename="link", mime_type="link"))
            count += 1
        db.commit(); db.close()
        flash(f"Imported {count} items.")
        return redirect(url_for("index"))
    return render_template("import_items.html")

@app.route("/import/credits", methods=["POST"])
@require_role("admin","accountant")
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

@app.route("/import/vendors", methods=["POST"])
@require_role("admin","accountant")
def import_vendors():
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
        try:
            v.sla_days = int(row.get("sla_days") or v.sla_days or 0)
        except Exception:
            pass
        v.notes = row.get("notes") or v.notes
        v.email_template = row.get("email_template") or v.email_template
        db.commit(); count += 1
    db.close()
    flash(f"Imported/updated {count} vendors.")
    return redirect(url_for("vendors"))

# ---------- Bulk credit ----------

@app.route("/bulk/apply-credit", methods=["POST"])
@require_role("admin","accountant")
def bulk_apply_credit():
    credit_id = int(request.form.get("credit_id") or 0)
    total_amount = to_decimal(request.form.get("total_amount") or "0")
    item_ids = [int(x) for x in request.form.getlist("item_ids") if x.isdigit()]
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
        ap = CreditApplication(credit_id=credit_id, item_id=iid, amount_applied=share, applied_date=date.today())
        c.remaining_amount -= share
        db.add(ap); db.commit()
        applied_total += share
    flash(f"Applied ${applied_total} across {len(item_ids)} items.")
    db.close()
    return redirect(url_for("index"))

# ---------- Contact / Zapier ----------

@app.route("/item/<int:item_id>/contact", methods=["POST"])
@require_role("admin","accountant")
def contact_vendor_webhook(item_id):
    if not OUTGOING_WEBHOOK_URL:
        flash("Set OUTGOING_WEBHOOK_URL to use Zapier send."); return redirect(url_for("item_detail", item_id=item_id))
    db = SessionLocal()
    it = db.query(Item).get(item_id); db.close()
    subject = request.form.get("subject")
    body = request.form.get("body")
    to = request.form.get("to")
    notify("vendor.contact_request", {"item_id": it.id, "to": to, "subject": subject, "body": body})
    flash("Sent to Zapier.")
    return redirect(url_for("item_detail", item_id=item_id))

@app.route("/zap/webhook", methods=["POST"])
def zap_webhook():
    if not check_bearer():
        return {"error": "unauthorized"}, 401
    payload = request.get_json(silent=True) or {}
    subj = payload.get("subject", "") or ""
    body = payload.get("body_plain", "") or payload.get("body", "") or ""
    vendor = payload.get("vendor") or None
    po = (po_re.search(subj or body).group(1) if (po_re.search(subj or body)) else None)
    sku = (sku_re.search(subj or body).group(1) if (sku_re.search(subj or body)) else None)
    credit_amt = (to_decimal(credit_re.search(subj or body).group(1)) if (credit_re.search(subj or body)) else None)

    db = SessionLocal()
    it = None
    if po:
        it = db.query(Item).filter(Item.po_number == po).order_by(Item.created_at.desc()).first()
    if not it:
        it = Item(title=subj[:200] or "Email import", vendor=vendor, po_number=po, sku=sku, description=body[:4000])
        db.add(it); db.commit()
    for att in payload.get("attachments", []):
        link = att.get("webview_link") or att.get("url") or att.get("drive_file_url")
        if link:
            db.add(Attachment(item_id=it.id, webview_link=link, filename=att.get("filename") or "file", mime_type=att.get("mime_type") or "link", source="email"))
    if credit_amt and credit_amt > decimal.Decimal("0"):
        c = Credit(reference=payload.get("message_id") or "Email credit", vendor=vendor, original_amount=credit_amt, remaining_amount=credit_amt, notes="From email webhook")
        db.add(c)
    db.add(EmailLog(item_id=it.id, from_addr=payload.get("from"), to_addr=payload.get("to"), subject=subj, body=body, received_at=datetime.utcnow(), message_id=payload.get("message_id")))
    db.commit(); db.close()
    return {"ok": True}

# ---------- Quick Capture / OCR ----------

def try_ocr_image(path):
    try:
        import pytesseract
        from PIL import Image
        return pytesseract.image_to_string(Image.open(path))
    except Exception:
        return ""

def try_pdf_text(path):
    try:
        from pypdf import PdfReader
        reader = PdfReader(path)
        return "\n".join([(p.extract_text() or "") for p in reader.pages])
    except Exception:
        return ""

@app.route("/item/new-upload", methods=["GET","POST"])
@require_role("admin","accountant")
def new_upload():
    ocr = None
    if request.method == "POST":
        file = request.files.get("file")
        vendor = request.form.get("vendor") or None
        title = request.form.get("title") or None
        if not file:
            flash("No file uploaded.")
            return redirect(url_for("new_upload"))
        fname = secure_filename(file.filename or f"upload-{int(datetime.utcnow().timestamp())}")
        os.makedirs("uploads", exist_ok=True)
        path = os.path.join("uploads", fname)
        file.save(path)
        text = try_pdf_text(path) if fname.lower().endswith(".pdf") else try_ocr_image(path)
        po = sku = None; credit_amt = None
        if text:
            m = po_re.search(text); po = m.group(1).strip() if m else None
            m = sku_re.search(text); sku = m.group(1).strip() if m else None
            m = credit_re.search(text); credit_amt = to_decimal(m.group(1)) if m else None
        ocr = {"text": text[:5000], "po": po, "sku": sku, "credit": float(credit_amt) if credit_amt else None, "vendor": vendor, "title": title, "attachment_url": f"/{path}"}
    return render_template("new_upload.html", ocr=ocr)

@app.route("/item/create-from-ocr", methods=["POST"])
@require_role("admin","accountant")
def create_from_ocr():
    vendor = request.form.get("vendor") or None
    title = request.form.get("title") or "Damage/Claim (OCR)"
    po = request.form.get("po") or None
    sku = request.form.get("sku") or None
    credit_str = request.form.get("credit") or None
    att_url = request.form.get("attachment_url") or None

    db = SessionLocal()
    it = Item(title=title, vendor=vendor, po_number=po, sku=sku, status="open")
    db.add(it); db.commit()

    if att_url:
        db.add(Attachment(item_id=it.id, webview_link=att_url, filename=os.path.basename(att_url), mime_type="link"))
        db.commit()

    if credit_str:
        try:
            amt = to_decimal(credit_str)
            if amt and amt > decimal.Decimal("0"):
                c = Credit(reference=f"OCR credit {datetime.utcnow().strftime('%Y%m%d%H%M%S')}", vendor=vendor, original_amount=amt, remaining_amount=amt, notes="Created from OCR upload")
                db.add(c); db.commit()
        except Exception:
            pass

    db.close()
    flash("Item created from OCR.")
    return redirect(url_for("item_detail", item_id=it.id))

@app.route('/uploads/<path:filename>')
@require_login
def serve_upload(filename):
    return send_from_directory('uploads', filename, as_attachment=False)

# ---------- Claim Packet (print/pdf + email via Zap) ----------

@app.route("/item/<int:item_id>/print")
@require_login
def print_item(item_id):
    db = SessionLocal()
    it = db.query(Item).get(item_id)
    if not it:
        db.close()
        abort(404)
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
    from io import BytesIO

    db = SessionLocal()
    it = db.query(Item).get(item_id)
    if not it:
        db.close()
        abort(404)
    applications = db.query(CreditApplication).filter(CreditApplication.item_id == item_id).order_by(CreditApplication.applied_date.desc()).all()
    vendor = db.query(Vendor).filter(Vendor.name.ilike(it.vendor)).first() if it.vendor else None
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=LETTER)
    width, height = LETTER
    y = height - 50
    def line(txt, size=10):
        nonlocal y
        c.setFont("Helvetica", size)
        c.drawString(50, y, (txt or "")[:110]); y -= 14
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
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=f"claim_item_{item_id}.pdf")

def pdf_item_bytes(item_id: int) -> bytes:
    from reportlab.lib.pagesizes import LETTER
    from reportlab.pdfgen import canvas
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
        c.setFont("Helvetica", size)
        c.drawString(50, y, (txt or "")[:110]); y -= 14
    c.setFont("Helvetica-Bold", 14); c.drawString(50, y, f"Damage Claim Packet — Item {it.id}"); y -= 18
    c.setFont("Helvetica", 9); c.drawString(50, y, datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")); y -= 18
    line(f"Title: {it.title or 'Item'}", 11)
    line(f"Vendor: {it.vendor or '-'}  Contact: {(vendor.email if vendor else '-')}, {(vendor.phone if vendor else '-')}", 10)
    line(f"PO: {it.po_number or '-'}  SKU: {it.sku or '-'}  Qty: {it.quantity}", 10)
    line(f"Status: {it.status}  Created: {it.created_at}  Updated: {it.updated_at}", 9)
    y -= 6; c.setFont("Helvetica-Bold", 11); c.drawString(50, y, "Attachments"); y -= 14
    c.setFont("Helvetica", 9)
    # attachments omitted in this minimal version (detail PDF includes them)
    c.showPage(); c.save(); buf.seek(0)
    return buf.getvalue()

@app.route("/item/<int:item_id>/send-claim", methods=["POST"])
@require_role("admin","accountant")
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
    body = request.form.get("body") or f"Hello {it.vendor or ''},\n\nAttached is the claim packet for PO {it.po_number or '-'} / SKU {it.sku or '-'}.\nLinks to photos are inside the packet.\n\nThank you,\nFowhand Furniture Claims"

    pdf_bytes = pdf_item_bytes(item_id)
    pdf_b64 = base64.b64encode(pdf_bytes).decode("ascii")

    notify("vendor.claim_packet", {
        "to": to, "subject": subject, "body": body,
        "attachments": [{
            "filename": f"claim_item_{item_id}.pdf",
            "content_type": "application/pdf",
            "content_base64": pdf_b64
        }],
        "item_id": item_id
    })
    flash("Claim packet sent to Zapier.")
    return redirect(url_for("item_detail", item_id=item_id))

# ---------- Reports & Digest ----------

def build_sla_digest(db):
    from collections import defaultdict
    rows = db.query(Item).filter(Item.status.in_(("open","in-progress","awaiting-credit"))).order_by(Item.vendor.asc(), Item.created_at.asc()).all()
    summary = defaultdict(lambda: {"overdue": [], "due": [], "ok": []})
    for it in rows:
        v = db.query(Vendor).filter(Vendor.name.ilike(it.vendor)).first() if it.vendor else None
        status, days_left = compute_sla(it, v)
        it_slim = {
            "id": it.id, "title": it.title, "po": it.po_number, "sku": it.sku,
            "created_at": (it.created_at or datetime.utcnow()).isoformat(),
            "days_left": days_left, "vendor": it.vendor or "Unknown", "status": it.status
        }
        if status == "overdue":
            summary[it_slim["vendor"]]["overdue"].append(it_slim)
        elif status == "due":
            summary[it_slim["vendor"]]["due"].append(it_slim)
        else:
            summary[it_slim["vendor"]]["ok"].append(it_slim)
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
    if not check_bearer():
        return {"error": "unauthorized"}, 401
    db = SessionLocal()
    payload = build_sla_digest(db)
    db.close()
    notify("digest.sla", {"html": payload["html"], "summary": payload["summary"]})
    return {"ok": True}

# --- Reports charts JSON ---

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
    from collections import defaultdict
    latest_applied = defaultdict(lambda: None)
    for ap in db.query(CreditApplication).all():
        if latest_applied[ap.item_id] is None or (ap.applied_date and ap.applied_date > latest_applied[ap.item_id]):
            latest_applied[ap.item_id] = ap.applied_date
    sums = {}; counts = {}
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

# ---------- Direct Upload to Drive via Zap ----------

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
    notify("file.upload_request", {"item_id": item_id, "filename": f.filename, "content_base64": content, "content_type": mime})
    flash("Sent to Zap for Drive upload. It will attach automatically when Zap calls back.")
    return redirect(url_for("item_detail", item_id=item_id))

@app.route("/zap/attach", methods=["POST"])
def zap_attach():
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
    if not it:
        db.close()
        return {"error":"item not found"}, 404
    att = Attachment(item_id=it.id, drive_file_id=drive_file_id, drive_file_url=link, webview_link=link, filename=name, mime_type=mime_type, source="zap")
    db.add(att); db.commit(); db.close()
    return {"ok": True}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
