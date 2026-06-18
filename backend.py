from flask import Flask, request, redirect, session, send_from_directory, jsonify, abort
import sqlite3
import hashlib
import secrets
import os

app = Flask(__name__, static_folder='.', static_url_path='')
app.secret_key = secrets.token_hex(32)

DB_PATH = os.path.join(os.path.dirname(__file__), 'remti.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        company TEXT DEFAULT '',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS suppliers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        name TEXT NOT NULL,
        color TEXT DEFAULT '#2B5BD7',
        ytd_total REAL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS invoices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        supplier_id INTEGER,
        invoice_number TEXT,
        description TEXT,
        amount REAL NOT NULL,
        due_date TEXT,
        status TEXT DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
    )''')
    conn.execute('''CREATE TABLE IF NOT EXISTS activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        icon TEXT,
        message TEXT,
        detail TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    demo = conn.execute("SELECT id FROM users WHERE email = 'jordan@harbert.co.uk'").fetchone()
    if not demo:
        seed_demo_data(conn)
    conn.commit()
    conn.close()


def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()


def seed_demo_data(conn):
    pw = hash_pw('demo1234')
    conn.execute("INSERT INTO users (name, email, password_hash, company) VALUES (?, ?, ?, ?)",
                 ('Jordan Morgan', 'jordan@harbert.co.uk', pw, 'Harbert & Co'))
    uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    suppliers = [
        (uid, 'Farrow Materials', '#C23030', 72800),
        (uid, 'Redwood Packaging', '#B04A1D', 68300),
        (uid, 'Meridian Logistics', '#2B5BD7', 54100),
        (uid, 'Avalon Industrial', '#8B4513', 42100),
        (uid, 'Kettle & Hearth', '#6B4C9A', 28600),
        (uid, 'Olive & Oak Linen', '#8B6914', 19400),
        (uid, 'Summit Ingredients', '#2F6E3E', 31200),
        (uid, 'Juniper Cleaning', '#2F6E3E', 12400),
        (uid, 'Blackstone Printing', '#1A1A1A', 8900),
        (uid, 'Northgate Facilities', '#666', 15200),
    ]
    for s in suppliers:
        conn.execute("INSERT INTO suppliers (user_id, name, color, ytd_total) VALUES (?, ?, ?, ?)", s)

    sids = {row['name']: row['id'] for row in conn.execute("SELECT id, name FROM suppliers WHERE user_id = ?", (uid,)).fetchall()}

    invoices = [
        (uid, sids['Farrow Materials'], 'INV-4822', 'Steel restock', 12150.00, '2026-04-05', 'overdue'),
        (uid, sids['Redwood Packaging'], 'INV-4821', 'Crates & pallets', 8420.00, '2026-04-01', 'overdue'),
        (uid, sids['Meridian Logistics'], 'INV-4823', 'Q2 freight', 5280.00, '2026-04-22', 'pending'),
        (uid, sids['Juniper Cleaning'], 'INV-4824', 'March service', 1580.00, '2026-04-25', 'pending'),
        (uid, sids['Kettle & Hearth'], 'INV-4825', 'Coffee supplies', 3420.00, '2026-05-01', 'pending'),
        (uid, sids['Olive & Oak Linen'], 'INV-4826', 'April laundry', 2460.00, '2026-05-02', 'pending'),
        (uid, sids['Blackstone Printing'], 'INV-4827', 'Brochure run', 2340.00, '2026-04-26', 'approval'),
        (uid, sids['Northgate Facilities'], 'INV-4828', 'Q1 maintenance', 2450.00, '2026-04-29', 'approval'),
        (uid, sids['Summit Ingredients'], 'INV-4829', 'Bulk flour order', 7890.00, '2026-04-20', 'approved'),
    ]
    for inv in invoices:
        conn.execute("INSERT INTO invoices (user_id, supplier_id, invoice_number, description, amount, due_date, status) VALUES (?, ?, ?, ?, ?, ?, ?)", inv)

    activities = [
        (uid, 'paid', '<b>Meridian Logistics</b> paid &middot; &pound;5,280', '2 hrs ago &middot; Via Faster Payments'),
        (uid, 'approved', '<b>Elena</b> approved Summit Ingredients', '3 hrs ago &middot; &pound;7,890'),
        (uid, 'import', '4 invoices imported from Xero', 'Yesterday &middot; 16:42'),
    ]
    for a in activities:
        conn.execute("INSERT INTO activity (user_id, icon, message, detail) VALUES (?, ?, ?, ?)", a)


# --- Auth routes ---

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or request.form
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()

    if not user or user['password_hash'] != hash_pw(password):
        return jsonify({'error': 'Invalid email or password'}), 401

    session['user_id'] = user['id']
    session['user_name'] = user['name']
    session['user_email'] = user['email']
    session['company'] = user['company']
    return jsonify({'ok': True, 'name': user['name']})


@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json() or request.form
    name = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not name or not email or not password:
        return jsonify({'error': 'All fields are required'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Password must be at least 6 characters'}), 400

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'error': 'An account with this email already exists'}), 409

    conn.execute("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                 (name, email, hash_pw(password)))
    uid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.commit()
    conn.close()

    session['user_id'] = uid
    session['user_name'] = name
    session['user_email'] = email
    session['company'] = ''
    return jsonify({'ok': True, 'name': name})


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'ok': True})


@app.route('/api/me')
def api_me():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    return jsonify({
        'name': session['user_name'],
        'email': session['user_email'],
        'company': session.get('company', ''),
    })


# --- Data routes ---

@app.route('/api/dashboard')
def api_dashboard():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401

    uid = session['user_id']
    conn = get_db()

    invoices = [dict(row) for row in conn.execute('''
        SELECT i.*, s.name as supplier_name, s.color as supplier_color
        FROM invoices i JOIN suppliers s ON i.supplier_id = s.id
        WHERE i.user_id = ? ORDER BY i.due_date
    ''', (uid,)).fetchall()]

    suppliers = [dict(row) for row in conn.execute(
        "SELECT * FROM suppliers WHERE user_id = ? ORDER BY ytd_total DESC", (uid,)
    ).fetchall()]

    activities = [dict(row) for row in conn.execute(
        "SELECT * FROM activity WHERE user_id = ? ORDER BY id DESC LIMIT 10", (uid,)
    ).fetchall()]

    overdue = [i for i in invoices if i['status'] == 'overdue']
    pending = [i for i in invoices if i['status'] in ('pending', 'overdue')]
    approvals = [i for i in invoices if i['status'] == 'approval']

    payable_total = sum(i['amount'] for i in pending)
    overdue_total = sum(i['amount'] for i in overdue)
    paid_total = 184620

    conn.close()

    return jsonify({
        'user': {'name': session['user_name'], 'company': session.get('company', '')},
        'kpis': {
            'payable_now': payable_total,
            'overdue_count': len(overdue),
            'overdue_total': overdue_total,
            'due_this_week': sum(i['amount'] for i in invoices if i['status'] == 'pending'),
            'due_this_week_count': len([i for i in invoices if i['status'] == 'pending']),
            'paid_this_month': paid_total,
            'avg_days_to_pay': 2.4,
        },
        'invoices': invoices,
        'approvals': approvals,
        'suppliers': suppliers[:6],
        'activities': activities,
        'bank_accounts': [
            {'name': 'Barclays', 'label': 'Operating', 'last4': '4829', 'balance': 248920, 'color': '#00aeef'},
            {'name': 'HSBC', 'label': 'Payroll', 'last4': '1187', 'balance': 62140, 'color': '#e2000f'},
        ],
        'aging': [
            {'label': 'Current', 'amount': 21460, 'pct': 38},
            {'label': '1-15d', 'amount': 14400, 'pct': 26},
            {'label': '16-30d', 'amount': 12150, 'pct': 22, 'severity': 'warn'},
            {'label': '30+ d', 'amount': 8420, 'pct': 14, 'severity': 'danger'},
        ],
    })


@app.route('/api/invoices/<int:invoice_id>/approve', methods=['POST'])
def approve_invoice(invoice_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    conn.execute("UPDATE invoices SET status = 'approved' WHERE id = ? AND user_id = ?",
                 (invoice_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


@app.route('/api/invoices/<int:invoice_id>/pay', methods=['POST'])
def pay_invoice(invoice_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    conn = get_db()
    conn.execute("UPDATE invoices SET status = 'paid' WHERE id = ? AND user_id = ?",
                 (invoice_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'ok': True})


# --- Page routes ---

@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/login')
def login_page():
    if 'user_id' in session:
        return redirect('/dashboard')
    return send_from_directory('.', 'login.html')


@app.route('/dashboard')
def dashboard_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'dashboard.html')


@app.route('/invoices')
def invoices_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'invoices.html')


@app.route('/approvals')
def approvals_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'approvals.html')


@app.route('/approval-detail')
def approval_detail_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'approval-detail.html')


@app.route('/invoice-detail')
def invoice_detail_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'invoice-detail.html')


@app.route('/supplier')
def supplier_detail_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'supplier-detail.html')


@app.route('/reports')
def reports_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'reports.html')


@app.route('/bank-accounts')
def bank_accounts_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'bank-accounts.html')


@app.route('/suppliers')
def suppliers_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'suppliers.html')


@app.route('/payrun')
def payrun_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'payrun.html')


@app.route('/integrations')
def integrations_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'integrations.html')


@app.route('/settings')
def settings_page():
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory('.', 'settings.html')


@app.route('/pricing')
@app.route('/pricing.html')
def pricing_page():
    return send_from_directory('.', 'pricing.html')


@app.route('/product')
@app.route('/product.html')
def product_page():
    return send_from_directory('.', 'product.html')


@app.route('/about')
@app.route('/about.html')
def about_page():
    return send_from_directory('.', 'about.html')


@app.route('/security')
@app.route('/security.html')
def security_page():
    return send_from_directory('.', 'security.html')


@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)


if __name__ == '__main__':
    init_db()
    print("\n  Remti running at http://localhost:5250\n")
    app.run(port=5250, debug=True)
