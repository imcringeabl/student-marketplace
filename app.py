import hmac
import os
import re
import secrets
import sqlite3
import uuid
from functools import wraps

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "marketplace.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")

# ---------- photo upload settings ----------
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")   # photos are saved here, the DB keeps only the path
MAX_PHOTO_MB = 5
app.config["MAX_CONTENT_LENGTH"] = MAX_PHOTO_MB * 1024 * 1024

# ---------- security settings ----------
ALLOWED_EMAIL_DOMAIN = "kbtu.kz"                      # only university accounts
STUDENT_ID_RE = re.compile(r"^\d{2}[A-Z]\d{6}$")      # e.g. 24B031936
PASSWORD_MIN_LEN = 8
MAX_LOGIN_FAILS = 5            # failed logins allowed ...
LOGIN_WINDOW_MIN = 15          # ... within this many minutes, then the account is locked for that time
MAX_MESSAGES = 5               # messages a user may send ...
MESSAGE_WINDOW_SEC = 60        # ... within this many seconds
MAX_MESSAGE_LEN = 1000
MAX_REVIEW_LEN = 500          # feedback text under a rating
MAX_COURSE_LEN = 12
MAX_PICKUP_LEN = 40
PICKUP_SUGGESTIONS = ["Library", "Main hall", "Canteen", "Dorm 1", "Dorm 2", "Sports hall"]
MAX_TITLE_LEN = 100           # BUG-03: very long titles broke the listing page on phones
app.config["CSRF_ENABLED"] = True   # tests switch it off; test_tc39 checks it


# ---------- CSRF protection ----------

def csrf_token():
    """One random token per session; every POST form must send it back."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def csrf_field():
    return Markup(f'<input type="hidden" name="csrf_token" value="{csrf_token()}">')


app.jinja_env.globals.update(csrf_token=csrf_token, csrf_field=csrf_field)

 
@app.before_request
def check_csrf():
    if request.method == "POST" and app.config["CSRF_ENABLED"]:
        sent = request.form.get("csrf_token", "")
        if not sent or not hmac.compare_digest(sent, session.get("csrf_token", "")):
            abort(400, "CSRF token missing or invalid.")


# ---------- database helpers ----------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create tables and test data. Seed users get the password 'password123'."""
    db = sqlite3.connect(DB_PATH)
    db.execute("PRAGMA foreign_keys = ON")
    with open(os.path.join(BASE_DIR, "schema.sql"), encoding="utf-8") as f:
        db.executescript(f.read())
    with open(os.path.join(BASE_DIR, "seed.sql"), encoding="utf-8") as f:
        db.executescript(f.read())
    db.execute("UPDATE users SET password_hash = ?", (generate_password_hash("password123"),))
    db.commit()
    db.close()


def migrate_db():
    """Upgrade an old marketplace.db: add listings.image_path and messages.is_read if they are missing."""
    db = sqlite3.connect(DB_PATH)
    try:
        listing_cols = {r[1] for r in db.execute("PRAGMA table_info(listings)")}
        message_cols = {r[1] for r in db.execute("PRAGMA table_info(messages)")}
        if listing_cols and "image_path" not in listing_cols:
            db.execute("ALTER TABLE listings ADD COLUMN image_path TEXT")
        if message_cols and "is_read" not in message_cols:
            db.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0 CHECK (is_read IN (0, 1))")
            db.execute("UPDATE messages SET is_read = 1")      # messages that already exist count as read
        for col in ("course", "pickup_place"):
            if listing_cols and col not in listing_cols:
                db.execute(f"ALTER TABLE listings ADD COLUMN {col} TEXT")
        if message_cols:
            db.execute("CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(receiver_id, is_read)")
        db.commit()
    finally:
        db.close()


def update_schema():
    """Add missing tables and indexes WITHOUT deleting any users or listings.
    Takes schema.sql, removes the DROP TABLE lines and makes every CREATE safe (IF NOT EXISTS)."""
    with open(os.path.join(BASE_DIR, "schema.sql"), encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if not ln.strip().upper().startswith("DROP TABLE")]
    sql = "\n".join(lines)
    for word in ("CREATE TABLE ", "CREATE UNIQUE INDEX ", "CREATE INDEX "):
        sql = sql.replace(word, word + "IF NOT EXISTS ")
    db = sqlite3.connect(DB_PATH)
    try:
        db.executescript(sql)
        db.commit()
    finally:
        db.close()


if os.path.exists(DB_PATH):
    migrate_db()        # add missing columns to old tables
    update_schema()     # add missing tables / indexes, keep all data


# ---------- photo helpers ----------

def detect_image_ext(head):
    """Look at the first bytes of the file (not at its name) to see what kind of image it really is."""
    if head.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    return None


def save_photo(file):
    """Save an uploaded photo. Returns (path, None) on success, (None, error) if invalid, (None, None) if no file."""
    if file is None or not file.filename:
        return None, None
    ext = detect_image_ext(file.stream.read(12))
    file.stream.seek(0)
    if ext is None:
        return None, "Photo must be a JPG, PNG, WEBP or GIF image."
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    name = f"{uuid.uuid4().hex}.{ext}"                      # random name: no clashes, no unsafe user file names
    file.save(os.path.join(UPLOAD_DIR, name))
    return f"uploads/{name}", None


def delete_photo(rel_path):
    if rel_path:
        try:
            os.remove(os.path.join(UPLOAD_DIR, os.path.basename(rel_path)))
        except OSError:
            pass


@app.errorhandler(413)
def photo_too_big(_e):
    flash(f"File is too large. Maximum size is {MAX_PHOTO_MB} MB.")
    return redirect(request.path if request.method == "POST" else url_for("index"))


def current_user():
    if "user_id" not in session:
        return None
    return get_db().execute("SELECT * FROM users WHERE user_id = ?", (session["user_id"],)).fetchone()


@app.context_processor
def inject_user():
    me = current_user()
    fav_ids = set()
    if me:
        fav_ids = {r[0] for r in get_db().execute(
            "SELECT listing_id FROM favourites WHERE user_id = ?", (me["user_id"],))}
    unread = 0
    if me:
        unread = get_db().execute(
            "SELECT COUNT(*) FROM messages WHERE receiver_id = ? AND is_read = 0", (me["user_id"],)).fetchone()[0]
    return {"me": me, "fav_ids": fav_ids, "unread": unread}


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


# ---------- ratings ----------
# SQL fragments: average rating and number of reviews of the seller of listing `l`
SELLER_AVG_SQL = "(SELECT ROUND(AVG(r.rating), 1) FROM reviews r WHERE r.seller_id = l.seller_id) AS seller_avg"
SELLER_N_SQL = "(SELECT COUNT(*) FROM reviews r WHERE r.seller_id = l.seller_id) AS seller_n"


def clean_course(text):
    """'math 101' -> 'MATH101'. Returns (value, error)."""
    text = (text or "").strip().upper().replace(" ", "")
    if not text:
        return None, None
    if len(text) > MAX_COURSE_LEN or not re.fullmatch(r"[A-Z0-9-]+", text):
        return None, "Course code: letters and digits only, e.g. MATH101."
    return text, None


def clean_pickup(text):
    text = (text or "").strip()
    if len(text) > MAX_PICKUP_LEN:
        return None, f"Pickup place must be at most {MAX_PICKUP_LEN} characters."
    return (text or None), None


def can_review(db, item, uid):
    """A student may review the seller only for a SOLD listing, only if they talked to the seller about it,
    and only once per listing. Returns (True, '') or (False, reason)."""
    if not uid or uid == item["seller_id"]:
        return False, "Only buyers can review."
    if item["status"] != "sold":
        return False, "You can review the seller after the item is sold."
    talked = db.execute("SELECT 1 FROM messages WHERE listing_id = ? AND sender_id = ? LIMIT 1",
                        (item["listing_id"], uid)).fetchone()
    if not talked:
        return False, "Only students who messaged the seller about this item can review."
    if db.execute("SELECT 1 FROM reviews WHERE listing_id = ? AND reviewer_id = ?",
                  (item["listing_id"], uid)).fetchone():
        return False, "You already reviewed this deal."
    return True, ""


# ---------- US-4: search ----------

@app.route("/")
def index():
    db = get_db()
    q = request.args.get("q", "").strip()
    category = request.args.get("category", "")
    max_price = request.args.get("max_price", "").strip()
    condition = request.args.get("condition", "")
    sort = request.args.get("sort", "price_asc")

    course = request.args.get("course", "").strip().upper().replace(" ", "")
    sql = f"""SELECT l.*, c.name AS category, u.full_name AS seller, {SELLER_AVG_SQL}, {SELLER_N_SQL}
             FROM listings l
             JOIN categories c ON c.category_id = l.category_id
             JOIN users u ON u.user_id = l.seller_id
             WHERE l.status = 'active'"""
    params = []
    if q:
        sql += " AND (l.title LIKE ? OR l.description LIKE ?)"
        params += [f"%{q}%", f"%{q}%"]
    if category:
        sql += " AND l.category_id = ?"
        params.append(category)
    if max_price.isdigit():
        sql += " AND l.price <= ?"
        params.append(int(max_price))
    if condition in ("new", "used"):
        sql += " AND l.condition = ?"
        params.append(condition)
    if course:
        sql += " AND l.course = ?"
        params.append(course)
    # only these fixed values can go into ORDER BY (user text is never put into the SQL)
    order = {"price_asc": "l.price ASC", "price_desc": "l.price DESC",
             "newest": "l.created_at DESC, l.listing_id DESC",
             "rating": "seller_avg IS NULL, seller_avg DESC, l.price ASC"}
    if sort not in order:
        sort = "price_asc"
    sql += " ORDER BY " + order[sort]

    listings = db.execute(sql, params).fetchall()
    # categories with the number of active listings (shown on the filter chips)
    categories = db.execute(
        """SELECT c.*, COUNT(l.listing_id) AS n FROM categories c
           LEFT JOIN listings l ON l.category_id = c.category_id AND l.status = 'active'
           GROUP BY c.category_id ORDER BY c.name""").fetchall()
    courses = [r[0] for r in db.execute(
        "SELECT DISTINCT course FROM listings WHERE status = 'active' AND course IS NOT NULL ORDER BY course")]
    grouped = not (q or category or max_price or condition or course or sort != "price_asc")   # home page = sections by category
    return render_template("index.html", listings=listings, categories=categories,
                           q=q, category=category, max_price=max_price, grouped=grouped,
                           condition=condition, sort=sort, course=course, courses=courses)


# ---------- validation helpers ----------

def is_kbtu_email(email):
    return re.fullmatch(r"[a-z0-9._%+-]+@" + re.escape(ALLOWED_EMAIL_DOMAIN), email) is not None


def password_problem(password):
    """Return an error text, or None if the password is strong enough."""
    if len(password) < PASSWORD_MIN_LEN:
        return f"Password must be at least {PASSWORD_MIN_LEN} characters."
    if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        return "Password must contain at least one letter and one digit."
    return None


def recent_login_fails(email):
    return get_db().execute(
        """SELECT COUNT(*) FROM login_attempts
           WHERE email = ? AND attempted_at > datetime('now', ?)""",
        (email, f"-{LOGIN_WINDOW_MIN} minutes")).fetchone()[0]


# ---------- US-1, US-2: register / login / logout ----------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        student_id, name = f["student_id"].strip(), f["full_name"].strip()
        email, password = f["email"].strip().lower(), f["password"]
        student_id = student_id.upper()
        if not (student_id and name and email and password):
            flash("Fill in all fields.")
            return render_template("register.html")
        if not STUDENT_ID_RE.match(student_id):
            flash("Student ID must look like 24B031936.")
            return render_template("register.html")
        if not is_kbtu_email(email):
            flash(f"Only university emails (@{ALLOWED_EMAIL_DOMAIN}) can register.")
            return render_template("register.html")
        problem = password_problem(password)
        if problem:
            flash(problem)
            return render_template("register.html")
        try:
            db = get_db()
            cur = db.execute(
                "INSERT INTO users (student_id, full_name, email, password_hash) VALUES (?, ?, ?, ?)",
                (student_id, name, email, generate_password_hash(password)))
            db.commit()
        except sqlite3.IntegrityError:
            flash("This student ID or email is already registered.")
            return render_template("register.html")
        session.clear()
        session["user_id"] = cur.lastrowid
        csrf_token()
        flash("Welcome! Your account was created.")
        return redirect(url_for("index"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = get_db()
        email = request.form["email"].strip().lower()
        if recent_login_fails(email) >= MAX_LOGIN_FAILS:
            flash(f"Too many failed attempts. Try again in {LOGIN_WINDOW_MIN} minutes.")
            return render_template("login.html"), 429
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], request.form["password"]):
            db.execute("DELETE FROM login_attempts WHERE email = ?", (email,))
            db.commit()
            session.clear()
            session["user_id"] = user["user_id"]
            csrf_token()
            return redirect(safe_next(request.args.get("next")))
        db.execute("INSERT INTO login_attempts (email, ip) VALUES (?, ?)", (email, request.remote_addr))
        db.commit()
        left = MAX_LOGIN_FAILS - recent_login_fails(email)
        if left > 0:
            flash(f"Wrong email or password. Attempts left: {left}.")
        else:
            flash(f"Wrong email or password. Login locked for {LOGIN_WINDOW_MIN} minutes.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------- US-3: post a listing ----------

@app.route("/listing/new", methods=["GET", "POST"])
@login_required
def new_listing():
    db = get_db()
    categories = db.execute("SELECT * FROM categories ORDER BY name").fetchall()
    if request.method == "POST":
        f = request.form
        title, price = f["title"].strip(), f["price"].strip()
        if not title or not price.isdigit():
            flash("Title is required and price must be a whole number of tenge, 0 or more.")
            return render_template("new_listing.html", categories=categories, suggestions=PICKUP_SUGGESTIONS)
        if len(title) > MAX_TITLE_LEN:  # BUG-03
            flash(f"Title must be at most {MAX_TITLE_LEN} characters.")
            return render_template("new_listing.html", categories=categories, suggestions=PICKUP_SUGGESTIONS)
        course, err = clean_course(f.get("course"))
        pickup, err2 = clean_pickup(f.get("pickup_place"))
        if err or err2:
            flash(err or err2)
            return render_template("new_listing.html", categories=categories, suggestions=PICKUP_SUGGESTIONS)
        photo_path, photo_error = save_photo(request.files.get("photo"))
        if photo_error:
            flash(photo_error)
            return render_template("new_listing.html", categories=categories, suggestions=PICKUP_SUGGESTIONS)
        try:
            cur = db.execute(
                """INSERT INTO listings (seller_id, category_id, title, description, price, condition, image_path,
                                         course, pickup_place)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session["user_id"], f["category_id"], title, f["description"].strip(),
                 int(price), f["condition"], photo_path, course, pickup))
            db.commit()
        except sqlite3.IntegrityError:
            delete_photo(photo_path)
            flash("Invalid category or condition.")
            return render_template("new_listing.html", categories=categories, suggestions=PICKUP_SUGGESTIONS)
        flash("Listing published.")
        return redirect(url_for("listing", listing_id=cur.lastrowid))
    return render_template("new_listing.html", categories=categories, suggestions=PICKUP_SUGGESTIONS)


# ---------- listing page + US-5 messages ----------

def get_listing(listing_id):
    row = get_db().execute(
        f"""SELECT l.*, c.name AS category, u.full_name AS seller, u.email AS seller_email,
                  {SELLER_AVG_SQL}, {SELLER_N_SQL}
           FROM listings l JOIN categories c ON c.category_id = l.category_id
           JOIN users u ON u.user_id = l.seller_id WHERE l.listing_id = ?""",
        (listing_id,)).fetchone()
    if row is None:
        abort(404)
    return row


@app.route("/listing/<int:listing_id>", methods=["GET", "POST"])
def listing(listing_id):
    db = get_db()
    item = get_listing(listing_id)
    uid = session.get("user_id")

    if request.method == "POST":
        if not uid:
            return redirect(url_for("login", next=request.path))
        text = request.form.get("text", "").strip()
        # buyer writes to the seller; seller replies to the chosen buyer
        if uid != item["seller_id"]:
            receiver = item["seller_id"]
        else:
            receiver = request.form.get("receiver_id", type=int)
            # the seller may only reply to someone who already wrote about this listing
            wrote = db.execute("SELECT 1 FROM messages WHERE listing_id = ? AND sender_id = ? LIMIT 1",
                               (listing_id, receiver)).fetchone()
            if not wrote:
                abort(403)
        if not text or receiver == uid:
            return redirect(url_for("listing", listing_id=listing_id))
        if len(text) > MAX_MESSAGE_LEN:
            flash(f"Message is too long (max {MAX_MESSAGE_LEN} characters).")
            return redirect(url_for("listing", listing_id=listing_id))
        sent = db.execute(
            "SELECT COUNT(*) FROM messages WHERE sender_id = ? AND sent_at > datetime('now', ?)",
            (uid, f"-{MESSAGE_WINDOW_SEC} seconds")).fetchone()[0]
        if sent >= MAX_MESSAGES:
            flash("You are sending messages too fast. Wait a minute and try again.")
            return redirect(url_for("listing", listing_id=listing_id))
        db.execute("INSERT INTO messages (listing_id, sender_id, receiver_id, text) VALUES (?, ?, ?, ?)",
                   (listing_id, uid, receiver, text))
        db.commit()
        return redirect(url_for("listing", listing_id=listing_id))

    messages, buyers = [], []
    if uid:
        # each user sees only conversations they take part in
        messages = db.execute(
            """SELECT m.*, s.full_name AS sender FROM messages m JOIN users s ON s.user_id = m.sender_id
               WHERE m.listing_id = ? AND (m.sender_id = ? OR m.receiver_id = ?)
               ORDER BY m.sent_at, m.message_id""", (listing_id, uid, uid)).fetchall()
        if uid == item["seller_id"]:
            buyers = db.execute(
                """SELECT DISTINCT u.user_id, u.full_name FROM messages m JOIN users u ON u.user_id = m.sender_id
                   WHERE m.listing_id = ? AND m.sender_id <> ?""", (listing_id, uid)).fetchall()
        # the person opened the conversation -> messages sent to them become read
        # (`messages` above still holds the old values, so the page can mark them "New")
        db.execute("UPDATE messages SET is_read = 1 WHERE listing_id = ? AND receiver_id = ? AND is_read = 0",
                   (listing_id, uid))
        db.commit()
    # how many students saved this listing
    saved_by = db.execute("SELECT COUNT(*) FROM favourites WHERE listing_id = ?", (listing_id,)).fetchone()[0]
    may_review, review_note = can_review(db, item, uid)
    reviews = db.execute(
        """SELECT r.*, u.full_name AS reviewer FROM reviews r JOIN users u ON u.user_id = r.reviewer_id
           WHERE r.listing_id = ? ORDER BY r.review_id DESC""", (listing_id,)).fetchall()
    return render_template("listing.html", item=item, messages=messages, buyers=buyers, saved_by=saved_by,
                           buyer_id=request.args.get("buyer", type=int),
                           may_review=may_review, review_note=review_note, reviews=reviews)


# ---------- inbox: all my conversations ----------

@app.route("/inbox")
@login_required
def inbox():
    uid = session["user_id"]
    rows = get_db().execute(
        """SELECT m.*, l.title, l.image_path,
                  CASE WHEN m.sender_id = :u THEN m.receiver_id ELSE m.sender_id END AS other_id,
                  o.full_name AS other_name
           FROM messages m
           JOIN listings l ON l.listing_id = m.listing_id
           JOIN users o ON o.user_id = CASE WHEN m.sender_id = :u THEN m.receiver_id ELSE m.sender_id END
           WHERE m.sender_id = :u OR m.receiver_id = :u
           ORDER BY m.sent_at DESC, m.message_id DESC""", {"u": uid}).fetchall()
    chats = {}   # one conversation = one listing + one other person; newest message comes first
    for m in rows:
        key = (m["listing_id"], m["other_id"])
        if key not in chats:
            chats[key] = {"title": m["title"], "image_path": m["image_path"], "other_name": m["other_name"],
                          "last_text": m["text"], "last_at": m["sent_at"], "last_mine": m["sender_id"] == uid,
                          "unread": 0,
                          "url": url_for("listing", listing_id=m["listing_id"], buyer=m["other_id"]) + "#messages"}
        if m["receiver_id"] == uid and not m["is_read"]:
            chats[key]["unread"] += 1
    return render_template("inbox.html", chats=list(chats.values()))


# ---------- US-6: mark as sold (owner only) ----------

@app.route("/listing/<int:listing_id>/sold", methods=["POST"])
@login_required
def mark_sold(listing_id):
    item = get_listing(listing_id)
    if item["seller_id"] != session["user_id"]:
        abort(403)  # only the owner may change the listing
    db = get_db()
    db.execute("UPDATE listings SET status = 'sold' WHERE listing_id = ?", (listing_id,))
    db.commit()
    flash("Marked as sold. It no longer appears in search.")
    return redirect(url_for("listing", listing_id=listing_id))


# ---------- edit / delete listing (owner only) ----------

@app.route("/listing/<int:listing_id>/edit", methods=["GET", "POST"])
@login_required
def edit_listing(listing_id):
    item = get_listing(listing_id)
    if item["seller_id"] != session["user_id"]:
        abort(403)
    db = get_db()
    categories = db.execute("SELECT * FROM categories ORDER BY name").fetchall()
    if request.method == "POST":
        f = request.form
        title, price = f["title"].strip(), f["price"].strip()
        if not title or not price.isdigit():
            flash("Title is required and price must be a whole number of tenge, 0 or more.")
            return render_template("new_listing.html", categories=categories, item=item, suggestions=PICKUP_SUGGESTIONS)
        if len(title) > MAX_TITLE_LEN:  # BUG-03
            flash(f"Title must be at most {MAX_TITLE_LEN} characters.")
            return render_template("new_listing.html", categories=categories, item=item, suggestions=PICKUP_SUGGESTIONS)
        course, err = clean_course(f.get("course"))
        pickup, err2 = clean_pickup(f.get("pickup_place"))
        if err or err2:
            flash(err or err2)
            return render_template("new_listing.html", categories=categories, item=item, suggestions=PICKUP_SUGGESTIONS)
        photo_path, photo_error = save_photo(request.files.get("photo"))
        if photo_error:
            flash(photo_error)
            return render_template("new_listing.html", categories=categories, item=item, suggestions=PICKUP_SUGGESTIONS)
        new_path = item["image_path"]
        if photo_path:                       # a new photo replaces the old one
            new_path = photo_path
        elif f.get("remove_photo"):          # "Remove photo" checkbox
            new_path = None
        try:
            db.execute(
                """UPDATE listings SET category_id = ?, title = ?, description = ?, price = ?, condition = ?,
                          image_path = ?, course = ?, pickup_place = ?
                   WHERE listing_id = ?""",
                (f["category_id"], title, f["description"].strip(), int(price), f["condition"],
                 new_path, course, pickup, listing_id))
            db.commit()
        except sqlite3.IntegrityError:
            delete_photo(photo_path)
            flash("Invalid category or condition.")
            return render_template("new_listing.html", categories=categories, item=item, suggestions=PICKUP_SUGGESTIONS)
        if new_path != item["image_path"]:
            delete_photo(item["image_path"])   # old file is no longer used
        flash("Listing updated.")
        return redirect(url_for("listing", listing_id=listing_id))
    return render_template("new_listing.html", categories=categories, item=item, suggestions=PICKUP_SUGGESTIONS)


@app.route("/listing/<int:listing_id>/delete", methods=["POST"])
@login_required
def delete_listing(listing_id):
    item = get_listing(listing_id)
    if item["seller_id"] != session["user_id"]:
        abort(403)
    db = get_db()
    db.execute("DELETE FROM listings WHERE listing_id = ?", (listing_id,))  # messages/favourites cascade
    db.commit()
    delete_photo(item["image_path"])
    flash("Listing deleted.")
    return redirect(url_for("my_listings"))


# ---------- US-7: my listings ----------

@app.route("/my")
@login_required
def my_listings():
    rows = get_db().execute(
        """SELECT l.*, c.name AS category FROM listings l JOIN categories c ON c.category_id = l.category_id
           WHERE l.seller_id = ? ORDER BY l.created_at DESC""", (session["user_id"],)).fetchall()
    return render_template("my_listings.html", listings=rows)


# ---------- ratings and feedback ----------

@app.route("/listing/<int:listing_id>/review", methods=["POST"])
@login_required
def add_review(listing_id):
    db = get_db()
    item = get_listing(listing_id)
    uid = session["user_id"]
    ok, reason = can_review(db, item, uid)
    if not ok:
        flash(reason)
        return redirect(url_for("listing", listing_id=listing_id))
    rating = request.form.get("rating", type=int)
    comment = request.form.get("comment", "").strip()
    if rating is None or not 1 <= rating <= 5:
        flash("Choose a rating from 1 to 5 stars.")
        return redirect(url_for("listing", listing_id=listing_id) + "#reviews")
    if len(comment) > MAX_REVIEW_LEN:
        flash(f"Feedback is too long (max {MAX_REVIEW_LEN} characters).")
        return redirect(url_for("listing", listing_id=listing_id) + "#reviews")
    db.execute("INSERT INTO reviews (listing_id, seller_id, reviewer_id, rating, comment) VALUES (?, ?, ?, ?, ?)",
               (listing_id, item["seller_id"], uid, rating, comment or None))
    db.commit()
    flash("Thank you! Your review was saved.")
    return redirect(url_for("listing", listing_id=listing_id) + "#reviews")


@app.route("/seller/<int:user_id>")
def seller_profile(user_id):
    db = get_db()
    seller = db.execute("SELECT user_id, full_name, created_at FROM users WHERE user_id = ?", (user_id,)).fetchone()
    if seller is None:
        abort(404)
    summary = db.execute("SELECT ROUND(AVG(rating), 1) AS avg, COUNT(*) AS n FROM reviews WHERE seller_id = ?",
                         (user_id,)).fetchone()
    # how many reviews for each star count (5 -> 1)
    dist = {r["rating"]: r["n"] for r in db.execute(
        "SELECT rating, COUNT(*) AS n FROM reviews WHERE seller_id = ? GROUP BY rating", (user_id,))}
    reviews = db.execute(
        """SELECT r.*, u.full_name AS reviewer, l.title FROM reviews r
           JOIN users u ON u.user_id = r.reviewer_id JOIN listings l ON l.listing_id = r.listing_id
           WHERE r.seller_id = ? ORDER BY r.review_id DESC""", (user_id,)).fetchall()
    sold = db.execute("SELECT COUNT(*) FROM listings WHERE seller_id = ? AND status = 'sold'", (user_id,)).fetchone()[0]
    active = db.execute(
        """SELECT l.*, c.name AS category FROM listings l JOIN categories c ON c.category_id = l.category_id
           WHERE l.seller_id = ? AND l.status = 'active' ORDER BY l.created_at DESC""", (user_id,)).fetchall()
    return render_template("seller.html", seller=seller, summary=summary, dist=dist, reviews=reviews,
                           sold=sold, active=active)


# ---------- favourites ----------

def safe_next(url):
    """Only allow redirects to local paths."""
    return url if url and url.startswith("/") and not url.startswith("//") else url_for("index")


@app.route("/listing/<int:listing_id>/favourite", methods=["POST"])
def toggle_favourite(listing_id):
    back = safe_next(request.form.get("next"))
    if "user_id" not in session:
        flash("Please log in to save listings.")
        return redirect(url_for("login", next=back))
    get_listing(listing_id)  # 404 if it does not exist
    db = get_db()
    removed = db.execute("DELETE FROM favourites WHERE user_id = ? AND listing_id = ?",
                         (session["user_id"], listing_id)).rowcount
    if not removed:
        db.execute("INSERT INTO favourites (user_id, listing_id) VALUES (?, ?)",
                   (session["user_id"], listing_id))
    db.commit()
    return redirect(back)



@app.route("/favourites")
@login_required
def favourites():
    rows = get_db().execute(
        f"""SELECT l.*, c.name AS category, u.full_name AS seller, {SELLER_AVG_SQL}, {SELLER_N_SQL}
           FROM favourites f JOIN listings l ON l.listing_id = f.listing_id
           JOIN categories c ON c.category_id = l.category_id
           JOIN users u ON u.user_id = l.seller_id
           WHERE f.user_id = ? AND l.status = 'active'
           ORDER BY f.favourite_id DESC""", (session["user_id"],)).fetchall()
    return render_template("favourites.html", listings=rows)


# ---------- Analytics: marketplace statistics ----------

def get_stats(db):
    """Collect the numbers for the /stats page with SQL (COUNT, AVG, MIN, MAX, GROUP BY)."""
    # 1. how many listings have each status: active / sold / hidden
    by_status = {r["status"]: r["n"] for r in db.execute(
        "SELECT status, COUNT(*) AS n FROM listings GROUP BY status")}

    # 2. per category: number of active listings and their average, lowest and highest price
    by_category = db.execute(
        """SELECT c.name,
                  COUNT(l.listing_id)        AS active,
                  CAST(ROUND(AVG(l.price)) AS INTEGER) AS avg_price,
                  MIN(l.price)               AS min_price,
                  MAX(l.price)               AS max_price
           FROM categories c
           LEFT JOIN listings l ON l.category_id = c.category_id AND l.status = 'active'
           GROUP BY c.category_id
           ORDER BY active DESC, c.name""").fetchall()

    # 3. top 3 listings saved to favourites most often
    top_favourites = db.execute(
        """SELECT l.listing_id, l.title, COUNT(f.favourite_id) AS saves
           FROM favourites f JOIN listings l ON l.listing_id = f.listing_id
           GROUP BY l.listing_id
           ORDER BY saves DESC, l.listing_id
           LIMIT 3""").fetchall()

    # 4. overall totals
    totals = {
        "users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "listings": db.execute("SELECT COUNT(*) FROM listings").fetchone()[0],
        "messages": db.execute("SELECT COUNT(*) FROM messages").fetchone()[0],
    }
    return {"by_status": by_status, "by_category": by_category,
            "top_favourites": top_favourites, "totals": totals}


@app.route("/stats")
def stats():
    return render_template("stats.html", s=get_stats(get_db()))



if __name__ == "__main__":
    if not os.path.exists(DB_PATH):
        init_db()
    app.run(debug=True)
