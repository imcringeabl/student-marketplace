"""Automated tests for the main user process.  Run:  python -m pytest -v
Each test = one test case (TC) from the Status Check Pack. 77 test cases: TC-01 ... TC-77."""
import os
import sqlite3
import tempfile

import pytest

import app as marketplace

 
@pytest.fixture
def client():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    marketplace.DB_PATH = path
    marketplace.UPLOAD_DIR = tempfile.mkdtemp()      # test photos never touch static/uploads
    marketplace.init_db()
    marketplace.app.config["TESTING"] = True
    marketplace.app.config["CSRF_ENABLED"] = False   # the CSRF test turns it on itself
    with marketplace.app.test_client() as c:
        yield c
    os.remove(path)


def register(c, sid="24B999001", email="new@kbtu.kz", password="secret123"):
    return c.post("/register", data={"student_id": sid, "full_name": "New Student",
                                     "email": email, "password": password}, follow_redirects=True)


def login(c, email="aruzhan@kbtu.kz", password="password123"):
    return c.post("/login", data={"email": email, "password": password}, follow_redirects=True)


def test_tc01_register_success(client):
    r = register(client)
    assert b"Your account was created" in r.data


def test_tc02_register_duplicate_student_id(client):
    r = register(client, sid="24B000101", email="other@kbtu.kz")  # 24B000101 already exists
    assert b"already registered" in r.data


def test_tc03_password_is_hashed(client):
    register(client, password="secret123")
    import sqlite3
    db = sqlite3.connect(marketplace.DB_PATH)
    stored = db.execute("SELECT password_hash FROM users WHERE email='new@kbtu.kz'").fetchone()[0]
    db.close()
    assert stored != "secret123" and stored.startswith(("scrypt:", "pbkdf2:"))


def test_tc04_login_wrong_password(client):
    r = login(client, password="wrong")
    assert b"Wrong email or password" in r.data


def test_tc05_post_listing(client):
    login(client)
    r = client.post("/listing/new", data={"title": "Algorithms book", "category_id": "1", "price": "3000",
                                          "condition": "used", "description": "CLRS"}, follow_redirects=True)
    assert b"Listing published" in r.data and b"Algorithms book" in r.data


def test_tc06_negative_price_rejected(client):
    login(client)
    r = client.post("/listing/new", data={"title": "Bad", "category_id": "1", "price": "-5",
                                          "condition": "used", "description": ""}, follow_redirects=True)
    assert b"price must be" in r.data


def test_tc07_search_category_and_price(client):
    r = client.get("/?category=1&max_price=4000")  # Books up to 4000
    assert b"Discrete Math lecture notes" in r.data    # 2000
    assert b"Calculus textbook" not in r.data           # 4500, too expensive
    assert b"Mechanical keyboard" not in r.data         # other category


def test_tc08_send_message(client):
    login(client, email="madina@kbtu.kz")
    client.post("/listing/1", data={"text": "Can I see it today?"})
    r = client.get("/listing/1")
    assert b"Can I see it today?" in r.data


def test_tc09_mark_sold_hides_from_search(client):
    login(client)  # aruzhan owns listing 1
    client.post("/listing/1/sold")
    r = client.get("/?q=Calculus")
    assert b"Calculus textbook" not in r.data


def test_tc10_cannot_mark_others_listing(client):
    login(client, email="dias@kbtu.kz")  # listing 1 belongs to aruzhan
    r = client.post("/listing/1/sold")
    assert r.status_code == 403


def test_tc11_post_requires_login(client):
    r = client.get("/listing/new")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_tc12_favourite_toggle(client):
    login(client)  # aruzhan has listings 3 and 5 saved in seed data
    client.post("/listing/8/favourite", data={"next": "/"})
    r = client.get("/favourites")
    assert b"Mechanical keyboard" in r.data and b"Logitech wireless mouse" in r.data
    client.post("/listing/8/favourite", data={"next": "/"})        # second click removes it
    assert b"Mechanical keyboard" not in client.get("/favourites").data


def test_tc13_favourite_requires_login(client):
    r = client.post("/listing/8/favourite", data={"next": "/"})
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert client.get("/favourites").status_code == 302


def test_tc14_home_grouped_by_category(client):
    r = client.get("/")
    assert b"cat-head" in r.data and b"Dorm items" in r.data and b"Services" in r.data


def test_tc15_favourite_redirect_is_local_only(client):
    login(client)
    r = client.post("/listing/8/favourite", data={"next": "//evil.example.com"})
    assert r.status_code == 302 and "evil.example.com" not in r.headers["Location"]


def test_tc16_favourites_are_private_per_user(client):
    login(client, email="dias@kbtu.kz")  # seed: dias saved only listing 3 (mouse); aruzhan also saved 5 (hoodie)
    r = client.get("/favourites")
    assert b"Logitech wireless mouse" in r.data and b"University hoodie" not in r.data


# ---------- security improvements ----------

def test_tc17_only_kbtu_email_can_register(client):
    r = register(client, email="someone@gmail.com")
    assert b"Only university emails" in r.data
    r = register(client, email="fake@kbtu.kz.evil.com")
    assert b"Only university emails" in r.data


def test_tc18_weak_password_rejected(client):
    assert b"at least 8 characters" in register(client, password="abc12").data
    assert b"one letter and one digit" in register(client, password="onlyletters").data


def test_tc19_bad_student_id_rejected(client):
    assert b"Student ID must look like" in register(client, sid="hello").data


def test_tc20_login_locked_after_5_fails(client):
    for _ in range(5):
        login(client, password="wrong")
    r = client.post("/login", data={"email": "aruzhan@kbtu.kz", "password": "password123"})
    assert r.status_code == 429 and b"Too many failed attempts" in r.data   # even the right password is blocked


def test_tc21_message_rate_limit(client):
    import sqlite3
    db = sqlite3.connect(marketplace.DB_PATH)   # make seed messages "old" so they don't count
    db.execute("UPDATE messages SET sent_at = datetime('now', '-1 day')")
    db.commit()
    db.close()
    login(client, email="madina@kbtu.kz")
    for i in range(6):
        client.post("/listing/1", data={"text": f"msg {i}"})
    r = client.get("/listing/1")
    assert b"msg 4" in r.data and b"msg 5" not in r.data and b"too fast" in r.data


def test_tc22_message_too_long_and_seller_reply_restricted(client):
    login(client, email="madina@kbtu.kz")
    client.post("/listing/1", data={"text": "x" * 1001})
    assert b"too long" in client.get("/listing/1").data
    client.get("/logout")
    login(client)  # aruzhan, seller of listing 1; dias never wrote about it
    r = client.post("/listing/1", data={"text": "spam", "receiver_id": "2"})
    assert r.status_code == 403


def test_tc23_sold_listing_not_in_favourites(client):
    login(client)  # aruzhan saved listings 3 (mouse) and 5 (hoodie)
    import sqlite3
    db = sqlite3.connect(marketplace.DB_PATH)
    db.execute("UPDATE listings SET status = 'sold' WHERE listing_id = 3")
    db.commit(); db.close()
    r = client.get("/favourites")
    assert b"Logitech wireless mouse" not in r.data and b"University hoodie" in r.data


def test_tc24_saved_by_counter(client):
    r = client.get("/listing/3")  # saved by aruzhan and dias in seed data
    assert b"Saved by 2" in r.data


# ---------- Week 14: TC-25 ... TC-38 (Altyngul: testing, analytics, integration) ----------

def count_rows(sql, params=()):
    """Read one number from the test database and close the connection (BUG-02)."""
    db = sqlite3.connect(marketplace.DB_PATH)
    try:
        return db.execute(sql, params).fetchone()[0]
    finally:
        db.close()


def stats_now():
    """Run the analytics function on the test database."""
    db = sqlite3.connect(marketplace.DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        return marketplace.get_stats(db)
    finally:
        db.close()


def listing_form(**changes):
    data = {"title": "Algorithms book", "category_id": "1", "price": "3000", "condition": "used", "description": ""}
    data.update(changes)
    return data


def test_tc25_logout_ends_session(client):
    # US-2: after logout the user can no longer open "My listings"
    login(client)
    assert client.get("/my").status_code == 200
    client.get("/logout")
    r = client.get("/my")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_tc26_listing_without_title_rejected(client):
    # US-3: an empty title is rejected and nothing is saved
    login(client)
    before = count_rows("SELECT COUNT(*) FROM listings")
    r = client.post("/listing/new", data=listing_form(title="   "), follow_redirects=True)
    assert b"Title is required" in r.data
    assert count_rows("SELECT COUNT(*) FROM listings") == before


def test_tc27_keyword_search(client):
    # US-4: keyword search finds matching titles only
    r = client.get("/?q=textbook")
    assert b"Calculus textbook" in r.data and b"Statistics textbook" in r.data
    assert b"Logitech wireless mouse" not in r.data


def test_tc28_sold_and_hidden_not_in_search(client):
    # US-4 / US-6: only active listings are shown in search
    r = client.get("/?q=e")  # matches almost every title
    assert b"USB-C charger 65W" not in r.data          # sold
    assert b"Physics 1 problem book" not in r.data     # hidden
    assert b"Mechanical keyboard" in r.data            # active


def test_tc29_seller_cannot_message_self(client):
    # US-5: a seller cannot send a message to themselves
    before = count_rows("SELECT COUNT(*) FROM messages WHERE listing_id = 1")
    login(client)  # aruzhan is the seller of listing 1
    client.post("/listing/1", data={"text": "Message to myself", "receiver_id": "1"})  # 1 = aruzhan herself
    assert count_rows("SELECT COUNT(*) FROM messages WHERE listing_id = 1") == before


def test_tc30_users_see_only_their_conversations(client):
    # Security / US-5: Dias must not see the Madina-Aruzhan conversation about listing 1
    login(client, email="madina@kbtu.kz")   # Madina is in this conversation and sees it
    assert b"Is the Calculus book still available?" in client.get("/listing/1").data
    client.get("/logout")
    login(client, email="dias@kbtu.kz")     # Dias is not in it and must not see it
    assert b"Is the Calculus book still available?" not in client.get("/listing/1").data


def test_tc31_unknown_listing_404(client):
    # Reliability: a listing that does not exist gives "404 Not Found", not a crash
    assert client.get("/listing/9999").status_code == 404


def test_tc32_stats_numbers_are_correct(client):
    # Analytics: /stats shows correct numbers from the seed data
    s = stats_now()
    assert s["by_status"] == {"active": 17, "sold": 2, "hidden": 1}
    books = next(c for c in s["by_category"] if c["name"] == "Books")
    assert books["active"] == 5 and books["avg_price"] == 4100   # (4500+2000+7000+3000+4000) / 5
    assert s["top_favourites"][0]["title"] == "Logitech wireless mouse"   # saved 2 times
    r = client.get("/stats")
    assert r.status_code == 200 and b"4,100" in r.data


def test_tc33_stats_update_after_sale(client):
    # Analytics + integration: marking a listing as sold changes the statistics
    login(client)  # aruzhan owns listing 1 (Books, 4500)
    client.post("/listing/1/sold")
    s = stats_now()
    assert s["by_status"]["sold"] == 3 and s["by_status"]["active"] == 16
    books = next(c for c in s["by_category"] if c["name"] == "Books")
    assert books["active"] == 4 and books["avg_price"] == 4000   # (2000+7000+3000+4000) / 4


def test_tc34_title_longer_than_100_rejected(client):
    # BUG-03 fix: a title longer than 100 characters is rejected, when posting and when editing
    login(client)
    before = count_rows("SELECT COUNT(*) FROM listings")
    r = client.post("/listing/new", data=listing_form(title="Test " + "h" * 200), follow_redirects=True)
    assert b"at most 100 characters" in r.data
    assert count_rows("SELECT COUNT(*) FROM listings") == before
    r = client.post("/listing/1/edit", data=listing_form(title="Test " + "h" * 200), follow_redirects=True)
    assert b"at most 100 characters" in r.data
    assert count_rows("SELECT length(title) FROM listings WHERE listing_id = 1") <= 100


def test_tc35_owner_can_edit_price(client):
    # Edit: the owner changes the price of her listing
    login(client)  # aruzhan owns listing 1 (4500)
    r = client.post("/listing/1/edit", data=listing_form(title="Calculus textbook, Stewart 8th ed", price="3999"),
                    follow_redirects=True)
    assert b"Listing updated" in r.data and b"3,999" in r.data
    assert count_rows("SELECT price FROM listings WHERE listing_id = 1") == 3999


def test_tc36_other_user_cannot_edit(client):
    # Edit security: another user gets 403 and the price does not change
    login(client, email="dias@kbtu.kz")
    r = client.post("/listing/1/edit", data=listing_form(price="1"))
    assert r.status_code == 403
    assert count_rows("SELECT price FROM listings WHERE listing_id = 1") == 4500


def test_tc37_owner_can_delete_listing_in_favourites(client):
    # Delete: dias deletes listing 3, which two users saved; its favourites are removed too (no error)
    login(client, email="dias@kbtu.kz")
    r = client.post("/listing/3/delete", follow_redirects=True)
    assert b"Listing deleted" in r.data
    assert client.get("/listing/3").status_code == 404
    assert count_rows("SELECT COUNT(*) FROM favourites WHERE listing_id = 3") == 0


def test_tc38_other_user_cannot_delete(client):
    # Delete security: another user gets 403 and the listing stays
    login(client, email="dias@kbtu.kz")   # listing 1 belongs to aruzhan
    assert client.post("/listing/1/delete").status_code == 403
    assert count_rows("SELECT COUNT(*) FROM listings WHERE listing_id = 1") == 1


def test_tc39_csrf_token_required(client):
    marketplace.app.config["CSRF_ENABLED"] = True
    try:
        r = client.post("/login", data={"email": "aruzhan@kbtu.kz", "password": "password123"})
        assert r.status_code == 400                       # no token -> rejected
        page = client.get("/login").data.decode()
        token = page.split('name="csrf_token" value="')[1].split('"')[0]
        r = client.post("/login", data={"email": "aruzhan@kbtu.kz", "password": "password123",
                                        "csrf_token": token})
        assert r.status_code == 302                       # valid token -> logged in
        r = client.post("/listing/1/delete", data={"csrf_token": "fake"})
        assert r.status_code == 400                       # forged token -> rejected
    finally:
        marketplace.app.config["CSRF_ENABLED"] = False


# ---------- photos ----------
import base64
import io

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")


def new_listing_with_photo(c, content=PNG, filename="book.png", title="Book with photo"):
    return c.post("/listing/new", data={"title": title, "category_id": "1", "price": "1000", "condition": "used",
                                        "description": "", "photo": (io.BytesIO(content), filename)},
                  content_type="multipart/form-data")


def test_tc40_upload_photo(client):
    # a real image is saved to disk, its path is stored in listings.image_path and it is shown on the page
    login(client)
    r = new_listing_with_photo(client)
    assert r.status_code == 302
    path = count_rows("SELECT 1 FROM listings WHERE title = 'Book with photo' AND image_path LIKE 'uploads/%.png'")
    assert path == 1
    stored = sqlite3.connect(marketplace.DB_PATH).execute(
        "SELECT image_path FROM listings WHERE title = 'Book with photo'").fetchone()[0]
    assert os.path.exists(os.path.join(marketplace.UPLOAD_DIR, os.path.basename(stored)))
    assert stored.encode() in client.get(r.headers["Location"]).data     # <img src=".../uploads/xxx.png">


def test_tc41_fake_image_rejected(client):
    # a text file renamed to .png is not an image: nothing is saved, no listing is created
    login(client)
    r = new_listing_with_photo(client, content=b"this is not an image", filename="evil.png", title="Fake photo")
    assert b"JPG, PNG, WEBP or GIF" in r.data
    assert count_rows("SELECT COUNT(*) FROM listings WHERE title = 'Fake photo'") == 0
    assert os.listdir(marketplace.UPLOAD_DIR) == []


def test_tc42_listing_without_photo_still_works(client):
    login(client)
    r = client.post("/listing/new", data={"title": "No photo", "category_id": "1", "price": "1", "condition": "new",
                                          "description": ""})
    assert r.status_code == 302
    assert count_rows("SELECT COUNT(*) FROM listings WHERE title = 'No photo' AND image_path IS NULL") == 1


def test_tc43_edit_replace_and_remove_photo(client):
    login(client)
    r = new_listing_with_photo(client)
    lid = int(r.headers["Location"].rsplit("/", 1)[1])
    old = os.listdir(marketplace.UPLOAD_DIR)
    assert len(old) == 1
    client.post(f"/listing/{lid}/edit", data={"title": "Book with photo", "category_id": "1", "price": "1000",
                "condition": "used", "description": "", "photo": (io.BytesIO(PNG), "new.png")},
                content_type="multipart/form-data")
    new = os.listdir(marketplace.UPLOAD_DIR)
    assert len(new) == 1 and new != old                      # replaced, the old file is deleted
    client.post(f"/listing/{lid}/edit", data={"title": "Book with photo", "category_id": "1", "price": "1000",
                "condition": "used", "description": "", "remove_photo": "1"})
    assert os.listdir(marketplace.UPLOAD_DIR) == []
    assert count_rows(f"SELECT COUNT(*) FROM listings WHERE listing_id = {lid} AND image_path IS NULL") == 1


def test_tc44_delete_listing_removes_photo_file(client):
    login(client)
    r = new_listing_with_photo(client)
    lid = int(r.headers["Location"].rsplit("/", 1)[1])
    assert len(os.listdir(marketplace.UPLOAD_DIR)) == 1
    client.post(f"/listing/{lid}/delete")
    assert os.listdir(marketplace.UPLOAD_DIR) == []


# ---------- messages: unread counter and inbox ----------

def test_tc45_new_message_is_unread_and_shown_to_receiver(client):
    # dias writes about aruzhan's listing 1 -> aruzhan sees "You have 1 new message" and the badge on the button
    login(client, email="dias@kbtu.kz")
    client.post("/listing/1", data={"text": "Is it still available?"})
    assert count_rows("SELECT COUNT(*) FROM messages WHERE text = 'Is it still available?' AND is_read = 0") == 1
    client.get("/logout")
    page = login(client, email="aruzhan@kbtu.kz").data       # seed also has 1 unread message from madina
    assert b"new message" in page and b"fab-badge" in page


def test_tc46_opening_conversation_marks_messages_read(client):
    login(client, email="aruzhan@kbtu.kz")
    before = count_rows("SELECT COUNT(*) FROM messages WHERE receiver_id = 1 AND is_read = 0")
    assert before >= 1
    page = client.get("/listing/1").data
    assert b"tag new" in page                                # shown as New on this visit
    assert count_rows("SELECT COUNT(*) FROM messages WHERE receiver_id = 1 AND listing_id = 1 AND is_read = 0") == 0


def test_tc47_inbox_lists_my_conversations_only(client):
    login(client, email="aruzhan@kbtu.kz")
    page = client.get("/inbox").data.decode()
    assert "Calculus textbook" in page                       # her conversation with madina
    assert "Logitech" not in page and "keyboard" not in page.lower()   # other people's chats are not shown


def test_tc48_inbox_requires_login(client):
    r = client.get("/inbox")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_tc49_sort_most_expensive_first(client):
    db = sqlite3.connect(marketplace.DB_PATH)
    expected = [r[0] for r in db.execute(
        "SELECT title FROM listings WHERE status = 'active' ORDER BY price DESC LIMIT 3")]
    db.close()
    html = client.get("/?sort=price_desc").data.decode("utf-8")
    positions = [html.index(t) for t in expected]
    assert positions == sorted(positions)       # the most expensive listing comes first


def test_tc50_filter_used_only(client):
    db = sqlite3.connect(marketplace.DB_PATH)
    used = [r[0] for r in db.execute("SELECT title FROM listings WHERE condition='used' AND status='active'")]
    new = [r[0] for r in db.execute("SELECT title FROM listings WHERE condition='new' AND status='active'")]
    db.close()
    html = client.get("/?condition=used").data.decode("utf-8")
    assert used and all(t in html for t in used)      # every used item is shown
    assert new and all(t not in html for t in new)    # no new items


def test_tc51_update_schema_keeps_users(client):
    register(client)                                   # a new user is saved in the database
    db = sqlite3.connect(marketplace.DB_PATH)
    db.execute("DROP TABLE favourites")                # pretend an old database misses this table
    db.commit()
    marketplace.update_schema()                        # what the site does on start-up
    users = db.execute("SELECT COUNT(*) FROM users WHERE email='new@kbtu.kz'").fetchone()[0]
    tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    db.close()
    assert users == 1 and "favourites" in tables       # the user is still there, the table is back



# ---------- ratings, feedback, campus fields (TC-52 ... TC-62) ----------

def review_form(rating="5", comment="Great seller"):
    return {"rating": rating, "comment": comment}


def test_tc52_buyer_can_review_sold_listing(client):
    # listing 1 is sold; madina wrote about it, so she may review aruzhan
    login(client)
    client.post("/listing/1/sold")
    client.get("/logout")
    login(client, email="madina@kbtu.kz")
    assert b"Rate the seller" in client.get("/listing/1").data
    r = client.post("/listing/1/review", data=review_form("4", "Pickup was easy"), follow_redirects=True)
    assert b"review was saved" in r.data and b"Pickup was easy" in r.data
    assert count_rows("SELECT rating FROM reviews WHERE listing_id = 1 AND reviewer_id = 3") == 4


def test_tc53_cannot_review_unsold_listing(client):
    login(client, email="madina@kbtu.kz")            # listing 1 is still active
    r = client.post("/listing/1/review", data=review_form(), follow_redirects=True)
    assert b"after the item is sold" in r.data
    assert count_rows("SELECT COUNT(*) FROM reviews WHERE listing_id = 1") == 0


def test_tc54_seller_cannot_review_self(client):
    login(client, email="dias@kbtu.kz")              # dias sold listing 4
    r = client.post("/listing/4/review", data=review_form(), follow_redirects=True)
    assert b"Only buyers can review" in r.data
    assert count_rows("SELECT COUNT(*) FROM reviews WHERE reviewer_id = 2") == 0


def test_tc55_stranger_cannot_review(client):
    login(client, email="timur@kbtu.kz")             # never wrote about sold listing 4
    r = client.post("/listing/4/review", data=review_form(), follow_redirects=True)
    assert b"messaged the seller" in r.data


def test_tc56_one_review_per_deal(client):
    login(client)                                    # seed: aruzhan already reviewed listing 4
    db = sqlite3.connect(marketplace.DB_PATH)
    db.execute("INSERT INTO messages (listing_id, sender_id, receiver_id, text) VALUES (4, 1, 2, 'hi')")
    db.commit(); db.close()
    r = client.post("/listing/4/review", data=review_form("1"), follow_redirects=True)
    assert b"already reviewed" in r.data
    assert count_rows("SELECT COUNT(*) FROM reviews WHERE listing_id = 4 AND reviewer_id = 1") == 1


def test_tc57_rating_must_be_1_to_5(client):
    login(client)
    client.post("/listing/1/sold")
    client.get("/logout")
    login(client, email="madina@kbtu.kz")
    for bad in ("0", "6", "abc", ""):
        r = client.post("/listing/1/review", data=review_form(bad), follow_redirects=True)
        assert b"1 to 5" in r.data
    assert count_rows("SELECT COUNT(*) FROM reviews WHERE listing_id = 1") == 0


def test_tc58_review_requires_login_and_csrf(client):
    r = client.post("/listing/4/review", data=review_form())
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    marketplace.app.config["CSRF_ENABLED"] = True
    try:
        login_page = client.get("/login")
        r = client.post("/listing/4/review", data=review_form())
        assert r.status_code == 400
    finally:
        marketplace.app.config["CSRF_ENABLED"] = False


def test_tc59_average_rating_shown(client):
    # seed: dias has one review (5 stars) -> shown on his seller page and on his listing card
    page = client.get("/seller/2").data
    assert b"Great" not in page and b"5.0" in page and b"Charger was exactly as described" in page
    assert b"5.0" in client.get("/?q=mouse").data
    assert client.get("/seller/9999").status_code == 404


def test_tc60_course_and_pickup_saved_and_filtered(client):
    login(client)
    client.post("/listing/new", data=listing_form(title="Linear algebra notes", course="math 201",
                                                  pickup_place="Library"))
    assert count_rows("SELECT COUNT(*) FROM listings WHERE title='Linear algebra notes' AND course='MATH201' "
                      "AND pickup_place='Library'") == 1
    r = client.get("/?course=MATH201").data
    assert b"Linear algebra notes" in r and b"Calculus textbook" not in r and b"Library" in r


def test_tc61_bad_course_rejected(client):
    login(client)
    r = client.post("/listing/new", data=listing_form(title="Bad course", course="<script>"), follow_redirects=True)
    assert b"letters and digits only" in r.data
    assert count_rows("SELECT COUNT(*) FROM listings WHERE title = 'Bad course'") == 0


def test_tc62_sort_best_rated_sellers(client):
    html = client.get("/?sort=rating").data.decode("utf-8")
    assert html.index("Python tutoring") < html.index("Calculus textbook")   # aigerim has a review, aruzhan none


# ---------- Week 13 (Altyngul): TC-63 ... TC-77 (incl. TC-73 end-to-end) ----------
# Altyngul: these tests cover the branches that were not tested yet (coverage 92% -> 95%+).

def test_tc63_old_database_is_upgraded(client):
    # Reliability: an old marketplace.db without image_path / is_read is upgraded and old messages count as read
    fd, old = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = sqlite3.connect(old)
    db.executescript("""CREATE TABLE listings (listing_id INTEGER PRIMARY KEY, title TEXT);
                        CREATE TABLE messages (message_id INTEGER PRIMARY KEY, receiver_id INTEGER, text TEXT);
                        INSERT INTO messages (receiver_id, text) VALUES (1, 'old message');""")
    db.commit(); db.close()
    saved = marketplace.DB_PATH
    marketplace.DB_PATH = old
    try:
        marketplace.migrate_db()
        marketplace.migrate_db()                              # running twice must not fail
        db = sqlite3.connect(old)
        listing_cols = {r[1] for r in db.execute("PRAGMA table_info(listings)")}
        message_cols = {r[1] for r in db.execute("PRAGMA table_info(messages)")}
        is_read = db.execute("SELECT is_read FROM messages").fetchone()[0]
        db.close()
    finally:
        marketplace.DB_PATH = saved
        os.remove(old)
    assert "image_path" in listing_cols and "is_read" in message_cols
    assert is_read == 1


def test_tc64_image_type_is_detected_by_first_bytes(client):
    # Security: the file type comes from the content, not from the file name
    assert marketplace.detect_image_ext(b"\xff\xd8\xff\xe0" + b"0" * 8) == "jpg"
    assert marketplace.detect_image_ext(PNG[:12]) == "png"
    assert marketplace.detect_image_ext(b"GIF89a" + b"0" * 6) == "gif"
    assert marketplace.detect_image_ext(b"RIFF1234WEBP") == "webp"
    assert marketplace.detect_image_ext(b"%PDF-1.4 text") is None
    assert marketplace.detect_image_ext(b"") is None


def test_tc65_too_big_photo_rejected(client):
    # Photos: a file above the size limit is rejected with a message, no listing and no file are created
    login(client)
    limit = marketplace.app.config["MAX_CONTENT_LENGTH"]
    marketplace.app.config["MAX_CONTENT_LENGTH"] = 200       # make the limit tiny for this test
    try:
        r = new_listing_with_photo(client, content=PNG + b"0" * 1000, title="Huge photo")
        assert r.status_code == 302
        assert b"too large" in client.get("/listing/new").data
    finally:
        marketplace.app.config["MAX_CONTENT_LENGTH"] = limit
    assert count_rows("SELECT COUNT(*) FROM listings WHERE title = 'Huge photo'") == 0
    assert os.listdir(marketplace.UPLOAD_DIR) == []


def test_tc66_register_validation_and_duplicate_email(client):
    # US-1: empty fields are rejected; the same email cannot be used twice; nothing extra is saved
    before = count_rows("SELECT COUNT(*) FROM users")
    r = client.post("/register", data={"student_id": "", "full_name": "", "email": "", "password": ""})
    assert b"Fill in all fields" in r.data
    r = register(client, sid="24B999777", email="aruzhan@kbtu.kz")     # email already taken
    assert b"already registered" in r.data
    assert count_rows("SELECT COUNT(*) FROM users") == before


def test_tc67_login_redirects_only_to_local_pages(client):
    # Security: after login the user goes to `next` only if it is a local path (no open redirect)
    r = client.post("/login?next=/inbox", data={"email": "aruzhan@kbtu.kz", "password": "password123"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/inbox")
    client.get("/logout")
    r = client.post("/login?next=//evil.example.com", data={"email": "aruzhan@kbtu.kz", "password": "password123"})
    assert r.status_code == 302 and "evil.example.com" not in r.headers["Location"]
    assert marketplace.safe_next("https://evil.example.com") == "/"
    assert marketplace.safe_next(None) == "/"


def test_tc68_message_edge_cases(client):
    # US-5: anonymous user -> login; empty text is not saved; the seller can reply to a buyer who wrote
    before = count_rows("SELECT COUNT(*) FROM messages")
    r = client.post("/listing/1", data={"text": "hello"})                  # not logged in
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    login(client, email="madina@kbtu.kz")
    client.post("/listing/1", data={"text": "    "})                       # only spaces
    assert count_rows("SELECT COUNT(*) FROM messages") == before
    client.get("/logout")
    login(client)                                                          # aruzhan, seller; madina wrote in seed data
    r = client.post("/listing/1", data={"text": "See you at 5pm", "receiver_id": "3"})
    assert r.status_code == 302
    assert count_rows("SELECT COUNT(*) FROM messages WHERE text = 'See you at 5pm' AND receiver_id = 3 AND is_read = 0") == 1


def test_tc69_invalid_category_rejected_and_photo_cleaned(client):
    # US-3 + photos: a wrong category gives an error, no listing is saved and the uploaded file is removed
    login(client)
    r = client.post("/listing/new", data={"title": "Wrong category", "category_id": "999", "price": "100",
                                          "condition": "used", "description": "",
                                          "photo": (io.BytesIO(PNG), "a.png")},
                    content_type="multipart/form-data")
    assert b"Invalid category or condition" in r.data
    assert count_rows("SELECT COUNT(*) FROM listings WHERE title = 'Wrong category'") == 0
    assert os.listdir(marketplace.UPLOAD_DIR) == []


def test_tc70_edit_validation_keeps_old_data(client):
    # Edit: empty title, bad photo and wrong condition are rejected; the listing stays unchanged
    login(client)  # aruzhan owns listing 1
    r = client.post("/listing/1/edit", data=listing_form(title="  "))
    assert b"Title is required" in r.data
    r = client.post("/listing/1/edit", data=listing_form(title="Changed", photo=(io.BytesIO(b"not an image"), "x.png")),
                    content_type="multipart/form-data")
    assert b"JPG, PNG, WEBP or GIF" in r.data
    r = client.post("/listing/1/edit", data=listing_form(title="Changed", condition="broken"))
    assert b"Invalid category or condition" in r.data
    assert count_rows("SELECT title FROM listings WHERE listing_id = 1") == "Calculus textbook, Stewart 8th ed"
    assert client.get("/listing/1/edit").status_code == 200


def test_tc71_unknown_listing_gives_404_everywhere(client):
    # Reliability: every action on a listing that does not exist returns 404, never a crash
    login(client)
    assert client.post("/listing/9999/sold").status_code == 404
    assert client.post("/listing/9999/delete").status_code == 404
    assert client.get("/listing/9999/edit").status_code == 404
    assert client.post("/listing/9999/favourite", data={"next": "/"}).status_code == 404
    marketplace.delete_photo("uploads/this-file-does-not-exist.png")     # deleting a missing file must not crash
    marketplace.delete_photo(None)


def test_tc72_inbox_groups_chats_and_counts_unread(client):
    # Messages: one chat = one listing + one other person; the inbox counts only unread messages sent to me
    login(client, email="madina@kbtu.kz")
    client.post("/listing/1", data={"text": "Second question"})
    client.get("/logout")
    login(client, email="aruzhan@kbtu.kz")
    assert count_rows("SELECT COUNT(*) FROM messages WHERE receiver_id = 1 AND is_read = 0") == 2
    page = client.get("/inbox").data.decode()
    assert page.count("Calculus textbook") == 1                  # 3 messages, but one conversation
    assert client.get("/listing/1").status_code == 200           # opening the listing marks them as read
    assert count_rows("SELECT COUNT(*) FROM messages WHERE receiver_id = 1 AND is_read = 0") == 0


def test_tc73_end_to_end_full_process(client):
    # End-to-end: register -> log in -> post listing -> search -> message seller -> reply -> mark as sold -> Stats
    # seller registers and posts a listing (with a photo)
    assert b"Your account was created" in register(client, sid="24B111111", email="seller@kbtu.kz").data
    r = new_listing_with_photo(client, title="E2E Laptop stand")
    assert r.status_code == 302
    lid = int(r.headers["Location"].rsplit("/", 1)[1])
    client.get("/logout")
    # buyer registers, finds the listing by search and writes to the seller
    register(client, sid="24B222222", email="buyer@kbtu.kz")
    assert b"E2E Laptop stand" in client.get("/?q=Laptop stand").data
    client.post(f"/listing/{lid}", data={"text": "Is the stand still available?"})
    assert count_rows("SELECT COUNT(*) FROM messages WHERE listing_id = ? AND is_read = 0", (lid,)) == 1
    client.get("/logout")
    # seller sees the new message, replies, then marks the item as sold
    page = login(client, email="seller@kbtu.kz", password="secret123").data
    assert b"new message" in page
    assert b"E2E Laptop stand" in client.get("/inbox").data            # the conversation is in the seller's inbox
    buyer_id = count_rows("SELECT user_id FROM users WHERE email = 'buyer@kbtu.kz'")
    client.post(f"/listing/{lid}", data={"text": "Yes, come today", "receiver_id": str(buyer_id)})
    before_sold = stats_now()["by_status"]["sold"]
    client.post(f"/listing/{lid}/sold")
    # the item disappears from search and the statistics change
    assert b"E2E Laptop stand" not in client.get("/?q=Laptop stand").data
    assert count_rows("SELECT status FROM listings WHERE listing_id = ?", (lid,)) == "sold"
    s = stats_now()
    assert s["by_status"]["sold"] == before_sold + 1
    assert s["totals"]["messages"] == 6 + 2 and s["totals"]["users"] == 10 + 2
    assert client.get("/stats").status_code == 200


def test_tc74_sort_and_filter_ignore_bad_values(client):
    # Search: an unknown sort value or condition is ignored (never put into the SQL) and the page still works
    r = client.get("/?sort=price%3B%20DROP%20TABLE%20users&condition=broken")
    assert r.status_code == 200
    assert count_rows("SELECT COUNT(*) FROM users") == 10
    html = client.get("/?sort=newest&condition=new").data.decode("utf-8")
    assert "Python tutoring" in html and "Calculus textbook" not in html


def test_tc75_review_text_too_long_rejected(client):
    # Reviews: feedback above 500 characters is rejected and no review is saved
    login(client)
    client.post("/listing/1/sold")
    client.get("/logout")
    login(client, email="madina@kbtu.kz")
    r = client.post("/listing/1/review", data=review_form("5", "x" * 501), follow_redirects=True)
    assert b"too long" in r.data
    assert count_rows("SELECT COUNT(*) FROM reviews WHERE listing_id = 1") == 0


def test_tc76_campus_fields_validated_on_create_and_edit(client):
    # Campus fields: a too long pickup place and a bad course code are rejected; the old data stays
    login(client)
    r = client.post("/listing/new", data=listing_form(title="Long pickup", pickup_place="P" * 41), follow_redirects=True)
    assert b"at most 40" in r.data
    assert count_rows("SELECT COUNT(*) FROM listings WHERE title = 'Long pickup'") == 0
    r = client.post("/listing/1/edit", data=listing_form(title="Calculus textbook, Stewart 8th ed", course="<b>"))
    assert b"letters and digits only" in r.data
    assert count_rows("SELECT course FROM listings WHERE listing_id = 1") == "MATH101"


def test_tc77_register_page_opens(client):
    # US-1: the registration form is available without login
    r = client.get("/register")
    assert r.status_code == 200 and b"Student ID" in r.data
