# Student Marketplace — prototype

Main process: register -> log in -> post listing -> search -> message seller -> mark as sold.

## Run
    pip install -r requirements.txt
    python app.py
Open http://127.0.0.1:5000 . The database `marketplace.db` is created on first start from
`schema.sql` + `seed.sql`. Delete the file to reset the data.

Test accounts: aruzhan@kbtu.kz, dias@kbtu.kz, madina@kbtu.kz ... password `password123`.

## Tests
    python -m pytest -v      # 63 test cases, TC-01 ... TC-63

## Files
- app.py — routes (Flask), one function per user story (US-1 ... US-7)
- schema.sql — tables (users, categories, listings, messages, favourites), keys, constraints;  seed.sql — test data
- templates/ — HTML pages (_ui.html = inline SVG icons, listing card, category sections)
- test_app.py — automated tests

## Favourites (US-8)
Heart button on every card and listing page; `/favourites` shows saved items grouped by category. Heart toggles add/remove (table `favourites`).

## Photos
Add a photo when selling (and replace / remove it on the Edit page). Allowed: JPG, PNG, WEBP, GIF, up to 5 MB.
The file is saved in `static/uploads/` under a random name; the database keeps only the path (`listings.image_path`).
The file type is checked by its first bytes, not by its name, so a renamed text file is rejected.
When a listing is deleted or its photo is replaced, the old file is deleted too.

## Messages (inbox)
- Round message button in the bottom-right corner of every page (when logged in). A red badge shows the number of unread messages.
- If someone wrote to you, a bubble appears above the button: "You have N new messages" (it can be closed; it comes back when a new message arrives).
- `/inbox` lists all conversations (listing + other person, last message, number of new messages). Click one to open the listing chat.
- `messages.is_read`: new message = 0; it becomes 1 when the receiver opens the listing page. New messages are marked "New" on that visit.
- An old `marketplace.db` is upgraded automatically at start (`migrate_db()` adds `image_path` and `is_read`); existing data is kept.

## Security
- Registration only with `@kbtu.kz` email; student ID must match `24B031936` format.
- Password policy: min 8 characters, at least one letter and one digit (stored as hash).
- Login brute-force protection: 5 wrong passwords for an email → locked for 15 minutes (table `login_attempts`, HTTP 429).
- Messages: max 5 per minute per user, max 1000 characters; a seller can reply only to users who wrote about the listing.
- CSRF protection: every POST form carries a secret per-session token (`csrf_token`), requests without it get HTTP 400.
- `next` redirect after login is limited to local paths (no open redirect).

## Analytics (Stats page)
`/stats` (link "Stats" in the menu) shows live numbers from the database: listings by status, active listings with
average / lowest / highest price per category, top 3 listings saved to favourites, totals. The SQL is in `get_stats()` in `app.py`.

## Testing (Altyngul)
- TC-01 ... TC-24 — main process, favourites, security (team).
- TC-25 ... TC-34 — logout, validation, search, messages privacy, 404, analytics, title length (BUG-03).
- TC-35 ... TC-38 — edit / delete listing: owner can, other users get 403.
- TC-39 — CSRF: POST without a valid token is rejected (400).
- TC-40 ... TC-44 — photos: upload, fake image rejected, no photo, replace / remove, file deleted with the listing.
- TC-45 ... TC-48 — messages: unread counter, opening marks as read, inbox shows only my chats, inbox needs login.
- TC-49 ... TC-51 — sorting, new/used filter, safe schema update (team).
- TC-52 ... TC-61 — old DB upgrade, image type by bytes, too big photo, register validation, safe `next` redirect, message edge cases, invalid category, edit validation, 404s, inbox grouping.
- TC-62 — end-to-end: register -> post listing with photo -> search -> message -> reply -> mark as sold -> Stats.
- TC-63 — sort / filter ignore bad values (SQL injection attempt does nothing).

## Continuous integration
GitHub Actions (`.github/workflows/tests.yml`) runs all tests on every push and pull request and fails if coverage is below 95%:
    python -m pytest -v --cov=app --cov-report=term-missing --cov-fail-under=95
