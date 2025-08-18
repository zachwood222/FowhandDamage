# Fowhand Furniture — Damage Tracker (Flask)

A ready‑to‑run Flask web app to track damaged furniture across vendors, ingest updates from **Zapier** (watching one or more Gmail inboxes), save photo attachment links (via Google Drive), **track credits (issued/applied)**, and give you a clean, password‑protected UI to manage everything. Also supports **manual entry**.

> **Zero-cron design:** Free hosts often sleep. Instead of background workers, this app accepts **webhooks from Zapier** whenever a new email arrives, so nothing breaks while your dyno is asleep.

---

## Features

- **Dashboard**: filter/search by vendor, status, PO/SKU, date
- **Manual entry** of damaged items
- **Credits**: create credits (issued), apply credits to one or more items, see remaining balance
- **Attachments**: store Google Drive links (or plain URLs) for photos
- **Email ingestion via Zapier**:
  - Gmail (Account A + Account B) → (optional) Upload attachments to Google Drive → **POST to `/zap/webhook`**
  - Flexible parser: finds `PO`, `SKU`, `Credit $123.45`, and basic intent in subject/body
  - Auto‑links updates to an existing item (by PO/SKU) or creates a new item
- **Notifications** (optional): outgoing webhook on item/credit changes to fan out to Slack/Email via Zapier
- **Auth**: super‑simple password login for your internal team

---

## Quick Start (Local)

1) **Clone & install**

```bash
python -m venv .venv && source .venv/bin/activate   # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
```

2) **Configure `.env`**

- Choose a strong `SECRET_KEY` and `ADMIN_PASSWORD`
- For **local dev only**, you can leave `DATABASE_URL` blank → app uses `SQLite` file `damage.db`
- Set a long random `ZAPIER_SECRET` for inbound authentication
- (Optional) Set `OUTGOING_WEBHOOK_URL` to a Zapier Catch Hook URL for notifications

3) **Run**

```bash
python app.py
# or
gunicorn app:app --reload
```

Visit http://127.0.0.1:5000 — login with the password you set.

---

## Database

- **Local:** SQLite (`damage.db`)
- **Prod:** Use free **Neon** or **Supabase** Postgres and set `DATABASE_URL`:
  `postgresql+psycopg://USER:PASSWORD@HOST:5432/DBNAME`

Tables are auto‑created on startup with SQLAlchemy.

---

## Deploy (Render free)

1) Create a new Web Service → **Public Git repo** or upload these files
2) Build Command: `pip install -r requirements.txt`
3) Start Command: `gunicorn app:app`
4) Add environment variables (same as `.env.example`)
5) Use **Neon** for Postgres (free) and paste your `DATABASE_URL`

> **Note:** Free plans may sleep. That’s okay: Zapier will still deliver to your `/zap/webhook` when it’s up; consider adding a simple Uptime ping or keep‑alive if needed.

**Alternative hosts:** Fly.io, Railway, Koyeb, Deta Space, or Google Cloud Run (always‑free tier).

---

## Zapier Setup

**Goal:** Watch 2 Gmail inboxes for damage/credit/replacement emails. Upload their photo attachments to Google Drive. Send a JSON webhook to your app so it can create/update items and store links.

**Zap Outline (repeat for each Gmail account):**

1. **Trigger:** Gmail — *New Email Matching Search*
   - Example search: `subject:(damage OR credit OR replacement) OR to:claims@yourdomain.com`
   - Or lock it to a Label you apply with a Gmail filter (recommended)
2. **Action (optional but recommended):** Google Drive — *Upload File*
   - Map each attachment. Keep a folder per vendor like `/Damage Photos/<Vendor>`
   - Output fields: File ID, Name, WebViewLink
3. **Action:** Webhooks by Zapier — *POST*
   - **URL:** `https://YOUR-APP.onrender.com/zap/webhook`
   - **Headers:** `Authorization: Bearer <ZAPIER_SECRET>`
   - **Payload Type:** JSON
   - **Data** (example mapping):
     ```json
     {
       "message_id": "<<< Gmail Message ID >>>",
       "from": "<<< From >>>",
       "to": "<<< To >>>",
       "subject": "<<< Subject >>>",
       "body_plain": "<<< Plain body >>>",
       "body_html": "<<< HTML body >>>",
       "received_at": "<<< Date >>>",
       "attachments": [
         {
           "drive_file_id": "<<< GoogleDrive File ID >>>",
           "name": "<<< File name >>>",
           "mime_type": "<<< MIME >>>",
           "webview_link": "<<< GoogleDrive WebViewLink >>>"
         }
       ]
     }
     ```

**What the app does with the webhook:**

- Extracts `vendor` from the email domain (or guess from body/subject)
- Parses `PO`, `SKU`, and any `Credit $amount` in text
- Creates or updates an `Item`
- Persists Drive links into `Attachments`
- Records an `EmailLog`

---

## Using the App

- **Dashboard:** filter by Status/Vendor, search PO/SKU/Title
- **New Item:** click “New Item” to enter manually (no email required)
- **Item Detail:** add notes, change status, add attachment links
- **Credits:**
  - “New Credit” creates a **credit pool** with a **remaining balance**
  - Apply all or part of a credit to one or more items
  - See “remaining” update live

---

## Security Notes

- Uses a very simple password gate. Set `ADMIN_PASSWORD` to something strong.
- The Zapier webhook requires `Authorization: Bearer <ZAPIER_SECRET>` — keep it secret.
- Avoid committing real secrets to Git. Use `.env` locally and Render env vars in prod.

---

## Troubleshooting

- **OAuth with Google** not required: we let **Zapier** talk to Gmail/Drive and push to us.
- If you later want direct Gmail/Drive API, you can add a service account/OAuth flow — but
  free hosting is simpler/safer with the Zapier design.

---

## License

MIT — customize for your shop.


---

## New: Roles, Import/Export, Vendors, Bulk Credit, and Contact Helper

### Roles
- **admin** and **accountant**: full create/update permissions
- **viewer**: read-only
Set passwords in `.env`:
```
ADMIN_PASSWORD=...
ACCOUNTANT_PASSWORD=...
VIEWER_PASSWORD=...
```

### Vendor Management
- Add vendors with email, phone, SLA days, and a default email template (use placeholders `{{PO}} {{SKU}} {{TITLE}} {{LINKS}}`).
- Item page shows a **Contact Vendor** helper that opens your mail client or sends via Zapier (set `OUTGOING_WEBHOOK_URL`).

### CSV Import/Export
- **Import**: `/import` supports items and credits CSV (see samples in `static/`).
- **Export**: `/export/items.csv` and `/export/credits.csv`.

### Bulk Apply Credits
- From the dashboard, select items and apply a chosen credit **evenly** by a total amount.

### Audit Log
- Internal `ChangeLog` table records role, action, and details for imports and credit applications.


### Multi-User Accounts
- Admin can create users at **Users** (email, role, password). First-run bootstrap is on the login page.

### SLA Alerts
- Set `SLA days` per vendor. Items show **SLA Overdue / Due Soon** badges and can be filtered by SLA on the dashboard.

### Printable / PDF Claim Packet
- Per item: **/item/<id>/print** (clean print page) and **/item/<id>/pdf** (downloads a PDF).

### Vendor CSV Import
- On **Vendors**, import a CSV with columns: `name,email,phone,sla_days,notes,email_template`.



### OCR & Quick Capture (PWA-ready)
- Visit **/item/new-upload** on mobile to snap a photo or upload a PDF.
- The server will attempt OCR using **Tesseract** if available (pytesseract). If Tesseract isn't installed, we fall back to PDF text extraction via **pypdf** (no OCR on images in that case).
- Parsed hints: **PO**, **SKU**, **Credit $amount**. You can confirm and create the item from the OCR result.
- App is a basic **PWA**: add to home screen; service worker caches core shell for quick loads.
- To enable full OCR on Render/Fly, install the system package `tesseract-ocr` (or run a worker/cron that uses Zapier + Google Drive OCR as an alternative).



### Daily SLA Digest (Zapier-friendly)
- View the digest at **/reports/sla?format=html** (admin/accountant) or JSON at **/reports/sla**.
- To send automatically each morning with Zapier:
  1) **Trigger:** Schedule by Zapier (e.g., every weekday 8am).
  2) **Action:** Webhooks by Zapier — POST to **/zap/sla-digest** with header `Authorization: Bearer <ZAPIER_SECRET>`.
  3) **Action:** Gmail or Slack — format message using the `html` field from the webhook body.

### Email Claim Packet (PDF via Zapier/Gmail)
- On an item page, click **Email Claim Packet** to POST a JSON payload to `OUTGOING_WEBHOOK_URL` containing:
  - `to`, `subject`, `body`
  - `attachments[0].content_base64` (PDF encoded), filename and content_type
- In your Zap:
  - **Trigger:** Catch Hook (Zapier).
  - **Action:** Gmail — Send Email (map `to`, `subject`, `body` and add the PDF attachment using `content_base64`).



### Reports page
- Visit **/reports** for three live charts (Chart.js):
  - **Credits by Vendor** (used vs remaining)
  - **Items by Month**
  - **Average Days to Credit (by Vendor)**

### Direct Upload to Drive via Zap
Add a Zap to handle uploads directly to Google Drive from the item page:
1) **Trigger:** Catch Hook (Zapier) — this listens for `file.upload_request` events.
2) **Action:** Code by Zapier (optional) — decode `content_base64` into a file buffer.
3) **Action:** Google Drive — Upload File (use filename, set parent folder).
4) **Action:** Webhooks by Zapier — POST back to `https://YOUR-APP/zap/attach` with header `Authorization: Bearer <ZAPIER_SECRET>` and body:
```json
{
  "item_id": 123,
  "drive_file_id": "###",
  "webview_link": "https://drive.google.com/file/d/###/view",
  "name": "photo.jpg",
  "mime_type": "image/jpeg"
}
```
When this callback arrives, the app automatically attaches the Drive link to the item.
