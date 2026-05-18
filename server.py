import os, re, sqlite3, hashlib, hmac, secrets, shutil
from datetime import date, datetime
from html import escape
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

DB = os.environ.get('WASHDOG_DB', 'washdog.db')
UPLOAD_DIR = os.environ.get('WASHDOG_UPLOAD_DIR', 'uploads')
IMPORT_DIR = os.environ.get('WASHDOG_IMPORT_DIR', 'imports')
SECRET = os.environ.get('WASHDOG_SECRET', 'change-me-secret')

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(IMPORT_DIR, exist_ok=True)

CSS = '''
body{font-family:Arial,sans-serif;margin:0;background:#f5f7fb;color:#14233c}header{background:#0f6fff;color:#fff;padding:1rem}main{max-width:1180px;margin:auto;padding:1rem}.card{background:#fff;padding:1rem;border-radius:10px;margin:1rem 0;border:1px solid #d9e1ef;box-shadow:0 4px 14px rgba(20,35,60,.06)}a{color:#0f6fff}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}input,select,button,textarea{box-sizing:border-box;padding:.55rem;margin:.2rem 0 .7rem;width:100%;border:1px solid #cfd8e7;border-radius:7px}button{background:#0f6fff;color:#fff;border:0;font-weight:700;cursor:pointer}.danger{background:#b42318}.nav a{margin-right:1rem;color:#fff}.tabs{display:flex;flex-wrap:wrap;gap:.5rem}.tab{display:inline-block;padding:.55rem .8rem;background:#e9f0ff;border-radius:7px;text-decoration:none;font-weight:700}.tab.active{background:#0f6fff;color:#fff}small{color:#4a5a78}.logo{display:block;max-width:220px;max-height:180px;margin:1rem auto}.shop-photo{max-width:220px;border-radius:8px}.table{width:100%;border-collapse:collapse}.table th,.table td{border-bottom:1px solid #edf1f7;text-align:left;padding:.5rem;vertical-align:top}label{font-weight:700;display:block}.muted{color:#5b6b84}.inline{display:inline}.inline button{width:auto;padding:.45rem .7rem}.table tbody tr:nth-child(even){background:#f8fbff}.table th{background:#eaf1ff;cursor:pointer}.toolbar{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center}.toolbar input{max-width:320px;margin:0}.toolbar button{width:auto}.hidden{display:none}.tile-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:1rem}.tile{background:#fff;border:1px solid #d9e1ef;border-radius:10px;padding:1rem}.avatar{width:72px;height:72px;border-radius:50%;object-fit:cover;background:#e9f0ff;display:block;margin-bottom:.7rem}.stat{font-size:2rem;font-weight:800;color:#0f6fff}.chart-card{min-height:260px}.bar-row{display:grid;grid-template-columns:minmax(120px,1fr) 3fr 56px;gap:.5rem;align-items:center;margin:.45rem 0}.bar-track{background:#e9f0ff;border-radius:999px;overflow:hidden;height:1rem}.bar-fill{background:#0f6fff;height:100%}.pie{width:180px;height:180px;border-radius:50%;margin:1rem auto;background:#e9f0ff}.legend{display:flex;flex-wrap:wrap;gap:.5rem}.legend span{display:inline-flex;align-items:center;gap:.25rem}.swatch{width:.8rem;height:.8rem;border-radius:3px;display:inline-block}.chart-pie{display:none}.dashboard.pie-mode .chart-bar{display:none}.dashboard.pie-mode .chart-pie{display:block}.kpi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem}.kpi{background:#f8fbff;border:1px solid #d9e1ef;border-radius:10px;padding:1rem}
'''

ADMIN_TABS = [
    ('/admin/dashboard', 'Tableau de bord'),
    ('/admin/templates', 'Templates'),
    ('/admin/shops', 'Boutiques'),
    ('/admin/services', 'Services'),
    ('/admin/clients', 'Clients'),
    ('/admin/managers', 'Managers'),
    ('/admin/dogs', 'Chiens'),
    ('/admin/database', 'Base de données'),
    ('/admin/security', 'Sécurité'),
]


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def hash_pw(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 260000).hex()
    return f'pbkdf2_sha256${salt}${digest}'


def legacy_hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()


def verify_pw(password, stored_hash):
    if not stored_hash:
        return False
    if stored_hash.startswith('pbkdf2_sha256$'):
        try:
            _, salt, digest = stored_hash.split('$', 2)
        except ValueError:
            return False
        candidate = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 260000).hex()
        return hmac.compare_digest(candidate, digest)
    return hmac.compare_digest(legacy_hash_pw(password), stored_hash)


def is_legacy_password_hash(stored_hash):
    return bool(stored_hash and not stored_hash.startswith('pbkdf2_sha256$'))


def sign(value):
    return hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()


def init():
    con = db()
    c = con.cursor()
    c.executescript('''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT,first_name TEXT,email TEXT UNIQUE,password TEXT,role TEXT,shop_id INTEGER,phone TEXT,vcard TEXT,birth_date TEXT,registered_at TEXT,avatar_path TEXT);
CREATE TABLE IF NOT EXISTS templates(id INTEGER PRIMARY KEY,name TEXT,description TEXT);
CREATE TABLE IF NOT EXISTS shops(id INTEGER PRIMARY KEY,name TEXT,address TEXT,email TEXT,phone TEXT,hours TEXT,services TEXT,lat REAL,lng REAL,template_id INTEGER,photo_path TEXT,operation_mode TEXT DEFAULT 'Libre service');
CREATE TABLE IF NOT EXISTS dogs(id INTEGER PRIMARY KEY,client_id INTEGER,name TEXT,breed TEXT,weight REAL,washes INTEGER DEFAULT 0,age INTEGER,registered_at TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS manager_shops(manager_id INTEGER,shop_id INTEGER,PRIMARY KEY(manager_id,shop_id));
CREATE TABLE IF NOT EXISTS stock_items(id INTEGER PRIMARY KEY,shop_id INTEGER,name TEXT,sku TEXT,quantity REAL,unit TEXT,min_quantity REAL,updated_at TEXT);
CREATE TABLE IF NOT EXISTS shop_services(id INTEGER PRIMARY KEY,shop_id INTEGER,name TEXT,category TEXT,description TEXT,price REAL,active INTEGER DEFAULT 1,updated_at TEXT);
''')
    user_columns = [row['name'] for row in c.execute('PRAGMA table_info(users)').fetchall()]
    user_migrations = {'first_name': 'TEXT', 'phone': 'TEXT', 'vcard': 'TEXT', 'birth_date': 'TEXT', 'registered_at': 'TEXT', 'avatar_path': 'TEXT'}
    for column, kind in user_migrations.items():
        if column not in user_columns:
            c.execute(f'ALTER TABLE users ADD COLUMN {column} {kind}')
    dog_columns = [row['name'] for row in c.execute('PRAGMA table_info(dogs)').fetchall()]
    dog_migrations = {'age': 'INTEGER', 'registered_at': 'TEXT'}
    for column, kind in dog_migrations.items():
        if column not in dog_columns:
            c.execute(f'ALTER TABLE dogs ADD COLUMN {column} {kind}')
    columns = [row['name'] for row in c.execute('PRAGMA table_info(shops)').fetchall()]
    if 'email' not in columns:
        c.execute('ALTER TABLE shops ADD COLUMN email TEXT')
    if 'photo_path' not in columns:
        c.execute('ALTER TABLE shops ADD COLUMN photo_path TEXT')
    if 'operation_mode' not in columns:
        c.execute("ALTER TABLE shops ADD COLUMN operation_mode TEXT DEFAULT 'Libre service'")
    admin = c.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
    if not admin:
        c.execute(
            'INSERT INTO users(name,first_name,email,password,role,registered_at) VALUES(?,?,?,?,?,datetime("now"))',
            ('Admin', '', 'admin@washdog.local', hash_pw('admin123'), 'admin'),
        )
    con.commit()
    con.close()


def setting(key, default=''):
    con = db()
    row = con.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    con.close()
    return row['value'] if row else default


def set_setting(key, value):
    con = db()
    con.execute('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, value))
    con.commit()
    con.close()


def cookie_token(environ):
    for part in environ.get('HTTP_COOKIE', '').split(';'):
        part = part.strip()
        if part.startswith('sid='):
            return part[4:]
    return None


def current_user(environ):
    sid = cookie_token(environ)
    if not sid or '.' not in sid:
        return None
    token, sig = sid.split('.', 1)
    if not hmac.compare_digest(sign(token), sig):
        return None
    con = db()
    row = con.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?', (token,)).fetchone()
    con.close()
    return row


def parse_post(environ):
    size = int(environ.get('CONTENT_LENGTH') or 0)
    body = environ['wsgi.input'].read(size)
    parsed = parse_qs(body.decode(errors='ignore'))
    return {key: values[0] for key, values in parsed.items()}


def parse_post_multi(environ):
    size = int(environ.get('CONTENT_LENGTH') or 0)
    body = environ['wsgi.input'].read(size)
    return parse_qs(body.decode(errors='ignore'))


def first_value(parsed, key, default=''):
    values = parsed.get(key) or []
    return values[0] if values else default


def parse_multipart(environ):
    content_type = environ.get('CONTENT_TYPE', '')
    if 'multipart/form-data' not in content_type or 'boundary=' not in content_type:
        return {}, {}
    boundary = content_type.split('boundary=', 1)[1].split(';', 1)[0].strip().strip('\"').encode()
    size = int(environ.get('CONTENT_LENGTH') or 0)
    raw = environ['wsgi.input'].read(size)
    fields = {}
    files = {}
    for part in raw.split(b'--' + boundary):
        if b'Content-Disposition' not in part:
            continue
        head, _, data = part.partition(b'\r\n\r\n')
        disposition = head.decode(errors='ignore')
        if 'name="' not in disposition:
            continue
        name = disposition.split('name="', 1)[1].split('"', 1)[0]
        value = data.rsplit(b'\r\n', 1)[0]
        if 'filename="' in disposition:
            filename = disposition.split('filename="', 1)[1].split('"', 1)[0]
            if filename and value:
                files[name] = {'filename': os.path.basename(filename), 'content': value}
        else:
            fields[name] = value.decode(errors='ignore')
    return fields, files


def safe_filename(filename):
    base = os.path.basename(filename or 'upload')
    cleaned = re.sub(r'[^A-Za-z0-9_.-]+', '_', base).strip('._')
    return cleaned or 'upload'


def save_upload(file_data, directory, prefix):
    os.makedirs(directory, exist_ok=True)
    safe_name = f"{prefix}{secrets.token_hex(6)}_{safe_filename(file_data.get('filename', 'upload'))}"
    path = os.path.normpath(os.path.join(directory, safe_name))
    root = os.path.abspath(directory)
    if os.path.commonpath([root, os.path.abspath(path)]) != root:
        raise ValueError('Chemin de fichier invalide')
    with open(path, 'wb') as output:
        output.write(file_data['content'])
    return path


def uploaded_file_path(request_path):
    prefix = '/uploads/'
    if not request_path.startswith(prefix):
        return None
    relative_name = request_path[len(prefix):]
    normalized = os.path.normpath(os.path.join(UPLOAD_DIR, relative_name))
    root = os.path.abspath(UPLOAD_DIR)
    candidate = os.path.abspath(normalized)
    if os.path.commonpath([root, candidate]) != root:
        return None
    return normalized


def html_page(title, body, user=None):
    nav = '<div class="nav"><a href="/">Accueil</a><a href="/shops">Vitrines</a>'
    if user and user['role'] == 'admin':
        nav += '<a href="/admin/dashboard">Admin</a>'
    if user and user['role'] == 'manager':
        nav += '<a href="/admin/dashboard">Tableau de bord</a><a href="/admin/dogs">Manager</a><a href="/admin/shops?tab=stock">Stock</a><a href="/admin/services">Services</a>'
    if user and user['role'] == 'client':
        nav += '<a href="/client">Client</a><a href="/dogs">Chiens</a>'
    nav += '<a href="/logout">Déconnexion</a>' if user else '<a href="/login">Connexion</a><a href="/register">Inscription</a>'
    nav += '</div>'
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{escape(title)}</title><style>{CSS}</style></head><body><header><h1>WashDog Pro</h1>{nav}</header><main>{body}</main></body></html>".encode()


def redirect(start_response, to, cookie=None):
    headers = [('Location', to)]
    if cookie:
        headers.append(('Set-Cookie', cookie))
    start_response('302 Found', headers)
    return [b'']


def require_admin(user, start_response):
    if not user or user['role'] != 'admin':
        return redirect(start_response, '/login')
    return None


def require_admin_or_manager(user, start_response):
    if not user or user['role'] not in ('admin', 'manager'):
        return redirect(start_response, '/login')
    return None


def admin_tabs(active_path):
    links = []
    for href, label in ADMIN_TABS:
        active = ' active' if href == active_path else ''
        links.append(f"<a class='tab{active}' href='{href}'>{label}</a>")
    return "<div class='card tabs'>" + ''.join(links) + '</div>'


def admin_shell(active_path, title, content):
    return admin_tabs(active_path) + f"<div class='card'><h2>{title}</h2></div>" + content


def db_file_size():
    return os.path.getsize(DB) if os.path.exists(DB) else 0


def handle_db_action(action, files=None):
    files = files or {}
    if action == 'db_backup':
        backup_name = f"washdog_backup_{secrets.token_hex(4)}.db"
        shutil.copyfile(DB, backup_name)
        return f"Sauvegarde créée : {backup_name}"
    if action == 'db_import' and files.get('database_file'):
        uploaded = save_upload(files['database_file'], IMPORT_DIR, 'db_')
        try:
            test_con = sqlite3.connect(uploaded)
            result = test_con.execute('PRAGMA quick_check').fetchone()[0]
            tables = {row[0] for row in test_con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            test_con.close()
        except sqlite3.DatabaseError as exc:
            return f"Import refusé : fichier SQLite invalide ({escape(str(exc))})."
        required = {'users', 'shops', 'dogs', 'settings'}
        if result == 'ok' and required.issubset(tables):
            if os.path.exists(DB):
                shutil.copyfile(DB, f"washdog_before_import_{secrets.token_hex(4)}.db")
            shutil.copyfile(uploaded, DB)
            return 'Base de données importée avec succès.'
        return f"Import refusé : schéma WashDog invalide ou contrôle SQLite invalide ({escape(str(result))})."
    return ''


def export_db(start_response):
    start_response('200 OK', [('Content-Type', 'application/octet-stream'), ('Content-Disposition', 'attachment; filename="washdog.db"')])
    with open(DB, 'rb') as db_file:
        return [db_file.read()]


def render_home(user):
    logo = setting('home_logo_path')
    logo_html = f"<img class='logo' src='/{escape(logo)}' alt='Logo WashDog Pro'>" if logo else ''
    return html_page(
        'Accueil',
        f"<div class='card'><h2 style='text-align:center'>Site dynamique sécurisé</h2>{logo_html}<p style='text-align:center'>Plateforme professionnelle pour gérer les vitrines publiques, les espaces clients et les boutiques d'une station de lavage canine.</p></div>",
        user,
    )


def render_public_shops(user):
    con = db()
    rows = con.execute('SELECT * FROM shops ORDER BY id DESC').fetchall()
    con.close()
    cards = []
    for row in rows:
        image = f"<img class='shop-photo' src='/{escape(row['photo_path'])}' alt='Photo boutique'>" if row['photo_path'] else ''
        cards.append(
            f"<div class='card'><h3>{escape(row['name'] or '')}</h3>{image}<p>{escape(row['address'] or '')}<br>{escape(row['email'] or '')}<br>{escape(row['phone'] or '')}<br>{escape(row['hours'] or '')}<br>{escape(row['services'] or '')}<br>Mode : {escape(row['operation_mode'] or 'Libre service')}</p></div>"
        )
    return html_page('Vitrines', ''.join(cards) or '<div class="card">Aucune boutique.</div>', user)


def options(rows, selected=None, empty=False):
    html = '<option value="">Aucun</option>' if empty else ''
    for row in rows:
        sel = ' selected' if selected is not None and str(row['id']) == str(selected) else ''
        html += f"<option value='{row['id']}'{sel}>{row['id']} - {escape(row['name'] or '')}</option>"
    return html


DASHBOARD_COLORS = ['#0f6fff', '#12b76a', '#f79009', '#b42318', '#7a5af8', '#06aed4', '#db2777', '#64748b']
AGE_BRACKETS = [(0, 20), (21, 40), (41, 60), (61, 80), (81, 100)]


def parse_iso_date(value):
    if not value:
        return None
    text = str(value).strip()[:10]
    for fmt in ('%Y-%m-%d', '%Y/%m/%d', '%Y%m%d'):
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def date_key(value):
    parsed = parse_iso_date(value)
    return parsed.isoformat() if parsed else 'Non daté'


def years_between(value):
    parsed = parse_iso_date(value)
    if not parsed:
        return None
    today = date.today()
    return today.year - parsed.year - ((today.month, today.day) < (parsed.month, parsed.day))


def age_bracket_label(age):
    if age in (None, ''):
        return 'Non renseigné'
    try:
        numeric_age = int(age)
    except (TypeError, ValueError):
        return 'Non renseigné'
    for low, high in AGE_BRACKETS:
        if low <= numeric_age <= high:
            return f'{low}-{high} ans'
    return '100+ ans'


def add_count(counter, key, amount=1):
    counter[key] = counter.get(key, 0) + amount


def sorted_counts(counter):
    return sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))


def average_rates(dates):
    parsed_dates = [parse_iso_date(item) for item in dates]
    parsed_dates = [item for item in parsed_dates if item]
    total = len(parsed_dates)
    if not total:
        return '0 / jour · 0 / semaine · 0 / mois · 0 / année'
    first = min(parsed_dates)
    days = max(1, (date.today() - first).days + 1)
    weeks = max(1, days / 7)
    months = max(1, days / 30.4375)
    years = max(1, days / 365.25)
    return f'{total / days:.2f} / jour · {total / weeks:.2f} / semaine · {total / months:.2f} / mois · {total / years:.2f} / année'


def chart_html(title, counts, empty_label='Aucune donnée'):
    items = sorted_counts(counts)
    if not items:
        return f"<div class='card chart-card'><h4>{escape(title)}</h4><p class='muted'>{empty_label}</p></div>"
    max_value = max(value for _, value in items) or 1
    bars = []
    legends = []
    start = 0
    segments = []
    total = sum(value for _, value in items) or 1
    for index, (label, value) in enumerate(items):
        color = DASHBOARD_COLORS[index % len(DASHBOARD_COLORS)]
        width = max(3, round((value / max_value) * 100, 2))
        safe_label = escape(str(label))
        bars.append(
            f"<div class='bar-row'><span>{safe_label}</span><div class='bar-track'><div class='bar-fill' style='width:{width}%;background:{color}'></div></div><strong>{value}</strong></div>"
        )
        end = start + (value / total) * 100
        segments.append(f'{color} {start:.2f}% {end:.2f}%')
        legends.append(f"<span><i class='swatch' style='background:{color}'></i>{safe_label} ({value})</span>")
        start = end
    pie_style = '; '.join(segments)
    return f"""
<div class='card chart-card'>
  <h4>{escape(title)}</h4>
  <div class='chart-bar'>{''.join(bars)}</div>
  <div class='chart-pie'><div class='pie' style='background:conic-gradient({pie_style})'></div><div class='legend'>{''.join(legends)}</div></div>
</div>
"""


def scoped_shop_ids(con, user):
    if user['role'] == 'admin':
        return [str(row['id']) for row in con.execute('SELECT id FROM shops ORDER BY name').fetchall()]
    return manager_reference_shop_ids(con, user['id'])


def fetch_dashboard_rows(con, shop_ids):
    if not shop_ids:
        return [], [], [], [], []
    placeholders = ','.join(['?'] * len(shop_ids))
    shops = con.execute(f'SELECT * FROM shops WHERE id IN ({placeholders}) ORDER BY name', shop_ids).fetchall()
    managers = con.execute(f'''
        SELECT u.*,ms.shop_id
        FROM manager_shops ms JOIN users u ON u.id=ms.manager_id
        WHERE u.role='manager' AND ms.shop_id IN ({placeholders})
    ''', shop_ids).fetchall()
    clients = con.execute(f'''
        SELECT * FROM users
        WHERE role='client' AND shop_id IN ({placeholders})
    ''', shop_ids).fetchall()
    dogs = con.execute(f'''
        SELECT d.*,u.shop_id
        FROM dogs d JOIN users u ON u.id=d.client_id
        WHERE u.shop_id IN ({placeholders})
    ''', shop_ids).fetchall()
    services = con.execute(f'''
        SELECT * FROM shop_services
        WHERE shop_id IN ({placeholders})
    ''', shop_ids).fetchall()
    return shops, managers, clients, dogs, services


def build_dashboard_stats(shops, managers, clients, dogs, services):
    stats = {}
    for shop in shops:
        sid = str(shop['id'])
        stats[sid] = {
            'shop': shop,
            'managers': [],
            'clients': [],
            'dogs': [],
            'services': [],
            'client_ages': {},
            'dog_breeds': {},
            'dog_ages': {},
            'manager_dates': {},
            'client_dates': {},
            'dog_dates': {},
            'service_types': {},
        }
    for manager in managers:
        bucket = stats.get(str(manager['shop_id']))
        if bucket is not None:
            bucket['managers'].append(manager)
            add_count(bucket['manager_dates'], date_key(manager['registered_at']))
    for client in clients:
        bucket = stats.get(str(client['shop_id']))
        if bucket is not None:
            bucket['clients'].append(client)
            add_count(bucket['client_ages'], age_bracket_label(years_between(client['birth_date'])))
            add_count(bucket['client_dates'], date_key(client['registered_at']))
    for dog in dogs:
        bucket = stats.get(str(dog['shop_id']))
        if bucket is not None:
            bucket['dogs'].append(dog)
            add_count(bucket['dog_breeds'], dog['breed'] or 'Non renseignée')
            add_count(bucket['dog_ages'], age_bracket_label(dog['age']))
            add_count(bucket['dog_dates'], date_key(dog['registered_at']))
    for service in services:
        bucket = stats.get(str(service['shop_id']))
        if bucket is not None:
            bucket['services'].append(service)
            add_count(bucket['service_types'], service['category'] or 'Non renseigné')
    return stats


def render_dashboard_overview(stats):
    manager_counts = {}
    client_counts = {}
    dog_counts = {}
    service_counts = {}
    for bucket in stats.values():
        label = bucket['shop']['name'] or f"Boutique #{bucket['shop']['id']}"
        manager_counts[label] = len(bucket['managers'])
        client_counts[label] = len(bucket['clients'])
        dog_counts[label] = len(bucket['dogs'])
        service_counts[label] = len(bucket['services'])
    return f"""
<div class='grid'>
  {chart_html('Managers par boutique', manager_counts)}
  {chart_html('Clients par boutique', client_counts)}
  {chart_html('Chiens par boutique', dog_counts)}
  {chart_html('Services par boutique', service_counts)}
</div>
"""


def render_shop_dashboard(bucket):
    shop = bucket['shop']
    manager_dates = [row['registered_at'] for row in bucket['managers']]
    client_dates = [row['registered_at'] for row in bucket['clients']]
    dog_dates = [row['registered_at'] for row in bucket['dogs']]
    kpis = f"""
<div class='kpi-grid'>
  <div class='kpi'><div class='stat'>{len(bucket['managers'])}</div><strong>Managers inscrits</strong></div>
  <div class='kpi'><div class='stat'>{len(bucket['clients'])}</div><strong>Clients inscrits</strong></div>
  <div class='kpi'><div class='stat'>{len(bucket['dogs'])}</div><strong>Chiens inscrits</strong></div>
  <div class='kpi'><div class='stat'>{len(bucket['services'])}</div><strong>Services configurés</strong></div>
</div>
"""
    averages = f"""
<div class='card'>
  <h4>Évolutions et moyennes</h4>
  <p><strong>Managers par boutique :</strong> {escape(average_rates(manager_dates))}</p>
  <p><strong>Clients inscrits par date :</strong> {escape(average_rates(client_dates))}</p>
  <p><strong>Chiens inscrits par date :</strong> {escape(average_rates(dog_dates))}</p>
</div>
"""
    return f"""
<section class='card'>
  <h3>{escape(shop['name'] or 'Boutique sans nom')}</h3>
  <p class='muted'>Boutique #{shop['id']} · {escape(shop['address'] or 'Adresse non renseignée')}</p>
  {kpis}
</section>
<div class='grid'>
  {chart_html('Clients par tranche d’âge', bucket['client_ages'])}
  {chart_html('Chiens par race', bucket['dog_breeds'])}
  {chart_html('Chiens par âge', bucket['dog_ages'])}
  {chart_html('Managers inscrits par date', bucket['manager_dates'])}
  {chart_html('Clients inscrits par date', bucket['client_dates'])}
  {chart_html('Chiens par date d’inscription', bucket['dog_dates'])}
  {chart_html('Services par type', bucket['service_types'])}
  {averages}
</div>
"""


def admin_dashboard(environ, start_response, user):
    blocked = require_admin_or_manager(user, start_response)
    if blocked:
        return blocked
    con = db()
    shop_ids = scoped_shop_ids(con, user)
    shops, managers, clients, dogs, services = fetch_dashboard_rows(con, shop_ids)
    stats = build_dashboard_stats(shops, managers, clients, dogs, services)
    con.close()
    scope = 'Admin : accès complet à toutes les boutiques.' if user['role'] == 'admin' else 'Manager : vue filtrée sur vos boutiques de référence.'
    content = f"""
<div id='dashboard' class='dashboard'>
  <div class='card toolbar'>
    <strong>{scope}</strong>
    <button type='button' id='barChartBtn'>Diagrammes à barres</button>
    <button type='button' id='pieChartBtn'>Graphiques camembert</button>
  </div>
  {render_dashboard_overview(stats) if shops else ''}
  {''.join(render_shop_dashboard(stats[str(shop['id'])]) for shop in shops) if shops else "<div class='card'>Aucune boutique dans votre périmètre.</div>"}
</div>
<script>
const dashboard = document.getElementById('dashboard');
document.getElementById('barChartBtn').onclick = () => dashboard.classList.remove('pie-mode');
document.getElementById('pieChartBtn').onclick = () => dashboard.classList.add('pie-mode');
</script>
"""
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Tableau de bord', admin_shell('/admin/dashboard', 'Tableau de bord par boutique', content), user)]

def admin_templates(environ, start_response, user):
    blocked = require_admin(user, start_response)
    if blocked:
        return blocked
    if environ['REQUEST_METHOD'] == 'POST':
        data = parse_post(environ)
        con = db()
        if data.get('type') == 'template_create':
            con.execute('INSERT INTO templates(name,description) VALUES(?,?)', (data.get('name', ''), data.get('description', '')))
        elif data.get('type') == 'template_update':
            con.execute('UPDATE templates SET name=?,description=? WHERE id=?', (data.get('name', ''), data.get('description', ''), data.get('id')))
        elif data.get('type') == 'template_delete':
            con.execute('DELETE FROM templates WHERE id=?', (data.get('id'),))
        con.commit()
        con.close()
        return redirect(start_response, '/admin/templates')
    con = db()
    templates = con.execute('SELECT * FROM templates ORDER BY id DESC').fetchall()
    con.close()
    rows = ''.join([
        f"<tr><td>{tpl['id']}</td><td>{escape(tpl['name'] or '')}</td><td>{escape(tpl['description'] or '')}</td><td><form class='inline' method='post'><input type='hidden' name='type' value='template_delete'><input type='hidden' name='id' value='{tpl['id']}'><button class='danger'>Supprimer</button></form></td></tr>"
        for tpl in templates
    ])
    body = f"""
<div class='card'><h3>Liste des templates</h3><table class='table'><tr><th>id</th><th>name</th><th>description</th><th>action</th></tr>{rows}</table></div>
<div class='grid'>
  <div class='card'><h3>Création template</h3><form method='post'><input type='hidden' name='type' value='template_create'><label>name</label><input name='name' required><label>description</label><textarea name='description' required></textarea><button>Créer</button></form></div>
  <div class='card'><h3>Édition / modification template</h3><form method='post'><input type='hidden' name='type' value='template_update'><label>id</label><input name='id' required><label>name</label><input name='name' required><label>description</label><textarea name='description' required></textarea><button>Modifier</button></form></div>
</div>
"""
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Gestion des templates', admin_shell('/admin/templates', 'Gestion des templates', body), user)]


def shop_admin_subtabs(active):
    return "<div class='card tabs'><a class='tab{}' href='/admin/shops'>Boutiques</a><a class='tab{}' href='/admin/shops?tab=stock'>Stock</a></div>".format(' active' if active == 'shops' else '', ' active' if active == 'stock' else '')


def allowed_stock_shops(con, user):
    if user['role'] == 'admin':
        return con.execute('SELECT * FROM shops ORDER BY name').fetchall()
    return con.execute(
        'SELECT s.* FROM manager_shops ms JOIN shops s ON s.id=ms.shop_id WHERE ms.manager_id=? ORDER BY s.name',
        (user['id'],),
    ).fetchall()


def stock_shop_allowed(shops, shop_id):
    return any(str(shop['id']) == str(shop_id) for shop in shops)


def stock_item_allowed(con, shops, item_id):
    row = con.execute('SELECT shop_id FROM stock_items WHERE id=?', (item_id,)).fetchone()
    return bool(row and stock_shop_allowed(shops, row['shop_id']))


def render_stock_management(environ, start_response, user):
    blocked = require_admin_or_manager(user, start_response)
    if blocked:
        return blocked
    con = db()
    shops = allowed_stock_shops(con, user)
    if environ['REQUEST_METHOD'] == 'POST':
        data = parse_post(environ)
        if stock_shop_allowed(shops, data.get('shop_id')):
            if data.get('type') == 'stock_create':
                con.execute(
                    'INSERT INTO stock_items(shop_id,name,sku,quantity,unit,min_quantity,updated_at) VALUES(?,?,?,?,?,?,datetime("now"))',
                    (data.get('shop_id'), data.get('name', ''), data.get('sku', ''), data.get('quantity') or 0, data.get('unit', ''), data.get('min_quantity') or 0),
                )
            elif data.get('type') == 'stock_update' and (user['role'] == 'admin' or stock_item_allowed(con, shops, data.get('id'))):
                con.execute(
                    'UPDATE stock_items SET shop_id=?,name=?,sku=?,quantity=?,unit=?,min_quantity=?,updated_at=datetime("now") WHERE id=?',
                    (data.get('shop_id'), data.get('name', ''), data.get('sku', ''), data.get('quantity') or 0, data.get('unit', ''), data.get('min_quantity') or 0, data.get('id')),
                )
            elif data.get('type') == 'stock_delete' and (user['role'] == 'admin' or stock_item_allowed(con, shops, data.get('id'))):
                con.execute('DELETE FROM stock_items WHERE id=? AND shop_id=?', (data.get('id'), data.get('shop_id')))
            elif data.get('type') in ('stock_scan_add', 'stock_scan_remove'):
                sku = data.get('barcode', '').strip()
                delta = float(data.get('scan_quantity') or 1)
                existing = con.execute('SELECT * FROM stock_items WHERE shop_id=? AND sku=?', (data.get('shop_id'), sku)).fetchone()
                if data.get('type') == 'stock_scan_add':
                    if existing:
                        con.execute('UPDATE stock_items SET quantity=quantity+?,updated_at=datetime("now") WHERE id=?', (delta, existing['id']))
                    elif sku:
                        con.execute(
                            'INSERT INTO stock_items(shop_id,name,sku,quantity,unit,min_quantity,updated_at) VALUES(?,?,?,?,?,?,datetime("now"))',
                            (data.get('shop_id'), data.get('scan_name') or f'Produit {sku}', sku, delta, data.get('scan_unit', ''), data.get('scan_min_quantity') or 0),
                        )
                elif existing:
                    new_quantity = max(0, float(existing['quantity'] or 0) - delta)
                    con.execute('UPDATE stock_items SET quantity=?,updated_at=datetime("now") WHERE id=?', (new_quantity, existing['id']))
            con.commit()
        con.close()
        return redirect(start_response, '/admin/shops?tab=stock')
    shop_ids = [str(shop['id']) for shop in shops]
    if shop_ids:
        placeholders = ','.join(['?'] * len(shop_ids))
        items = con.execute(f'''
            SELECT si.*,s.name AS shop_name FROM stock_items si JOIN shops s ON s.id=si.shop_id
            WHERE si.shop_id IN ({placeholders}) ORDER BY s.name,si.name
        ''', shop_ids).fetchall()
    else:
        items = []
    shop_options = ''.join([f"<option value='{shop['id']}'>{shop['id']} - {escape(shop['name'] or '')}</option>" for shop in shops])
    rows = ''.join([
        f"<tr><td>{item['id']}</td><td>{escape(item['shop_name'] or '')}</td><td>{escape(item['name'] or '')}</td><td>{escape(item['sku'] or '')}</td><td>{escape(str(item['quantity'] or 0))}</td><td>{escape(item['unit'] or '')}</td><td>{escape(str(item['min_quantity'] or 0))}</td><td>{escape(item['updated_at'] or '')}</td><td><form class='inline' method='post'><input type='hidden' name='type' value='stock_delete'><input type='hidden' name='id' value='{item['id']}'><input type='hidden' name='shop_id' value='{item['shop_id']}'><button class='danger'>Supprimer</button></form></td></tr>"
        for item in items
    ])
    con.close()
    scope = 'Admin : stock de toutes les boutiques.' if user['role'] == 'admin' else 'Manager : stock limité aux boutiques de référence.'
    body = f"""
{shop_admin_subtabs('stock')}
<div class='card'><h3>Gestion du stock</h3><p>{scope}</p></div>
<div class='card'><h3>Scan code-barres</h3><p>Placez le curseur dans <strong>barcode</strong>, scannez le produit, puis ajoutez ou retirez la quantité indiquée. Si le code-barres est déjà connu localement, les champs produit sont pré-remplis automatiquement.</p><form id='barcodeStockForm' method='post'><label>shop_id</label><select id='scanShop' name='shop_id' required>{shop_options}</select><label>barcode</label><input id='barcodeInput' name='barcode' autocomplete='off' inputmode='numeric' required><label>scan_name</label><input id='scanName' name='scan_name' placeholder='Nom du produit'><label>scan_quantity</label><input id='scanQuantity' name='scan_quantity' type='number' step='0.01' value='1'><label>scan_unit</label><input id='scanUnit' name='scan_unit' placeholder='pièce, litre, kg...'><label>scan_min_quantity</label><input id='scanMinQuantity' name='scan_min_quantity' type='number' step='0.01' value='0'><button name='type' value='stock_scan_add'>Ajouter au stock</button><button class='danger' name='type' value='stock_scan_remove'>Supprimer du stock</button></form></div>
<div class='card'><h3>Liste du stock par boutique</h3><table class='table'><tr><th>id</th><th>boutique</th><th>name</th><th>sku</th><th>quantity</th><th>unit</th><th>min_quantity</th><th>updated_at</th><th>action</th></tr>{rows}</table></div>
<div class='grid'>
  <div class='card'><h3>Création stock</h3><form id='stockCreateForm' method='post'><input type='hidden' name='type' value='stock_create'><label>shop_id</label><select name='shop_id' required>{shop_options}</select><label>name</label><input id='createStockName' name='name' required><label>sku</label><input id='createStockSku' name='sku'><label>quantity</label><input name='quantity' type='number' step='0.01' value='0'><label>unit</label><input id='createStockUnit' name='unit' placeholder='pièce, litre, kg...'><label>min_quantity</label><input id='createStockMinQuantity' name='min_quantity' type='number' step='0.01' value='0'><button>Créer</button></form></div>
  <div class='card'><h3>Édition / modification stock</h3><form method='post'><input type='hidden' name='type' value='stock_update'><label>id</label><input name='id' required><label>shop_id</label><select name='shop_id' required>{shop_options}</select><label>name</label><input name='name' required><label>sku</label><input name='sku'><label>quantity</label><input name='quantity' type='number' step='0.01'><label>unit</label><input name='unit'><label>min_quantity</label><input name='min_quantity' type='number' step='0.01'><button>Modifier</button></form></div>
</div>
<script>
const barcodeInput = document.getElementById('barcodeInput');
const scanName = document.getElementById('scanName');
const scanUnit = document.getElementById('scanUnit');
const scanMinQuantity = document.getElementById('scanMinQuantity');
const barcodeCatalog = JSON.parse(localStorage.getItem('washdog_barcode_catalog_v1') || '{{}}');
function fillProductFromBarcode(code) {{
  const product = barcodeCatalog[code];
  if (!product) return;
  scanName.value = product.name || scanName.value;
  scanUnit.value = product.unit || scanUnit.value;
  scanMinQuantity.value = product.min_quantity || scanMinQuantity.value;
  document.getElementById('createStockSku').value = code;
  document.getElementById('createStockName').value = product.name || '';
  document.getElementById('createStockUnit').value = product.unit || '';
  document.getElementById('createStockMinQuantity').value = product.min_quantity || 0;
}}
barcodeInput?.addEventListener('input', event => fillProductFromBarcode(event.target.value.trim()));
document.getElementById('barcodeStockForm')?.addEventListener('submit', () => {{
  const code = barcodeInput.value.trim();
  if (code && scanName.value.trim()) {{
    barcodeCatalog[code] = {{ name: scanName.value.trim(), unit: scanUnit.value.trim(), min_quantity: scanMinQuantity.value || 0 }};
    localStorage.setItem('washdog_barcode_catalog_v1', JSON.stringify(barcodeCatalog));
  }}
}});
barcodeInput?.focus();
</script>
"""
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Gestion du stock', admin_shell('/admin/shops', 'Gestion des boutiques', body), user)]


def service_category_options(selected=''):
    categories = ['Prestations de base', 'Prestations spécialisées', 'Services additionnels bien-être']
    return ''.join([f"<option value='{escape(category)}'{' selected' if category == selected else ''}>{escape(category)}</option>" for category in categories])


def allowed_service_shops(con, user):
    return allowed_stock_shops(con, user)


def service_shop_allowed(shops, shop_id):
    return stock_shop_allowed(shops, shop_id)


def service_item_allowed(con, shops, service_id):
    row = con.execute('SELECT shop_id FROM shop_services WHERE id=?', (service_id,)).fetchone()
    return bool(row and service_shop_allowed(shops, row['shop_id']))


def service_select_options(con):
    rows = con.execute('SELECT ss.*,s.name AS shop_name FROM shop_services ss JOIN shops s ON s.id=ss.shop_id WHERE ss.active=1 ORDER BY s.name,ss.category,ss.name').fetchall()
    if not rows:
        return "<option value='A définir'>Aucun service disponible - à définir après création</option>"
    return ''.join([f"<option value='{escape(row['name'] or '')}'>{escape(row['shop_name'] or '')} · {escape(row['category'] or '')} · {escape(row['name'] or '')}</option>" for row in rows])


def admin_services(environ, start_response, user):
    blocked = require_admin_or_manager(user, start_response)
    if blocked:
        return blocked
    con = db()
    shops = allowed_service_shops(con, user)
    if environ['REQUEST_METHOD'] == 'POST':
        data = parse_post(environ)
        if service_shop_allowed(shops, data.get('shop_id')):
            if data.get('type') == 'service_create':
                con.execute('INSERT INTO shop_services(shop_id,name,category,description,price,active,updated_at) VALUES(?,?,?,?,?,?,datetime("now"))', (data.get('shop_id'), data.get('name', ''), data.get('category', ''), data.get('description', ''), data.get('price') or 0, 1 if data.get('active') == '1' else 0))
            elif data.get('type') == 'service_update' and (user['role'] == 'admin' or service_item_allowed(con, shops, data.get('id'))):
                con.execute('UPDATE shop_services SET shop_id=?,name=?,category=?,description=?,price=?,active=?,updated_at=datetime("now") WHERE id=?', (data.get('shop_id'), data.get('name', ''), data.get('category', ''), data.get('description', ''), data.get('price') or 0, 1 if data.get('active') == '1' else 0, data.get('id')))
            elif data.get('type') == 'service_delete' and (user['role'] == 'admin' or service_item_allowed(con, shops, data.get('id'))):
                con.execute('DELETE FROM shop_services WHERE id=? AND shop_id=?', (data.get('id'), data.get('shop_id')))
            con.commit()
        con.close()
        return redirect(start_response, '/admin/services')
    shop_ids = [str(shop['id']) for shop in shops]
    if shop_ids:
        placeholders = ','.join(['?'] * len(shop_ids))
        items = con.execute(f'SELECT ss.*,s.name AS shop_name FROM shop_services ss JOIN shops s ON s.id=ss.shop_id WHERE ss.shop_id IN ({placeholders}) ORDER BY s.name,ss.category,ss.name', shop_ids).fetchall()
    else:
        items = []
    shop_options = ''.join([f"<option value='{shop['id']}'>{shop['id']} - {escape(shop['name'] or '')}</option>" for shop in shops])
    rows = ''.join([f"<tr><td>{item['id']}</td><td>{escape(item['shop_name'] or '')}</td><td>{escape(item['category'] or '')}</td><td>{escape(item['name'] or '')}</td><td>{escape(item['description'] or '')}</td><td>{escape(str(item['price'] or 0))}</td><td>{'Oui' if item['active'] else 'Non'}</td><td>{escape(item['updated_at'] or '')}</td><td><form class='inline' method='post'><input type='hidden' name='type' value='service_delete'><input type='hidden' name='id' value='{item['id']}'><input type='hidden' name='shop_id' value='{item['shop_id']}'><button class='danger'>Supprimer</button></form></td></tr>" for item in items])
    con.close()
    scope = 'Admin : services de toutes les boutiques.' if user['role'] == 'admin' else 'Manager : services limités aux boutiques de référence.'
    body = f"""
<div class='card'><h3>Gestion des services des boutiques</h3><p>{scope}</p><p>Catégories : Prestations de base, Prestations spécialisées, Services additionnels bien-être.</p></div>
<div class='card'><h3>Liste des services</h3><table class='table'><tr><th>id</th><th>boutique</th><th>category</th><th>name</th><th>description</th><th>price</th><th>active</th><th>updated_at</th><th>action</th></tr>{rows}</table></div>
<div class='grid'>
  <div class='card'><h3>Création service</h3><form method='post'><input type='hidden' name='type' value='service_create'><label>shop_id</label><select name='shop_id' required>{shop_options}</select><label>category</label><select name='category' required>{service_category_options()}</select><label>name</label><input name='name' required><label>description</label><textarea name='description'></textarea><label>price</label><input name='price' type='number' step='0.01' value='0'><label>active</label><select name='active'><option value='1'>Oui</option><option value='0'>Non</option></select><button>Créer</button></form></div>
  <div class='card'><h3>Édition / modification service</h3><form method='post'><input type='hidden' name='type' value='service_update'><label>id</label><input name='id' required><label>shop_id</label><select name='shop_id' required>{shop_options}</select><label>category</label><select name='category' required>{service_category_options()}</select><label>name</label><input name='name' required><label>description</label><textarea name='description'></textarea><label>price</label><input name='price' type='number' step='0.01'><label>active</label><select name='active'><option value='1'>Oui</option><option value='0'>Non</option></select><button>Modifier</button></form></div>
</div>
"""
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Gestion des services', admin_shell('/admin/services', 'Gestion des services des boutiques', body), user)]


def admin_shops(environ, start_response, user):
    query = parse_qs(environ.get('QUERY_STRING', ''))
    if (query.get('tab') or [''])[0] == 'stock':
        return render_stock_management(environ, start_response, user)
    blocked = require_admin_or_manager(user, start_response)
    if blocked:
        return blocked
    if environ['REQUEST_METHOD'] == 'POST' and user['role'] == 'admin':
        multipart = 'multipart/form-data' in environ.get('CONTENT_TYPE', '')
        data, files = parse_multipart(environ) if multipart else (parse_post(environ), {})
        photo = save_upload(files['shop_photo'], UPLOAD_DIR, 'shop_') if files.get('shop_photo') else None
        con = db()
        if data.get('type') == 'shop_create':
            con.execute('INSERT INTO shops(name,address,email,phone,hours,services,lat,lng,template_id,photo_path,operation_mode) VALUES(?,?,?,?,?,?,?,?,?,?,?)', (data.get('name', ''), data.get('address', ''), data.get('email', ''), data.get('phone', ''), data.get('hours', ''), data.get('services', ''), data.get('lat') or None, data.get('lng') or None, data.get('template_id') or None, photo, data.get('operation_mode', 'Libre service')))
        elif data.get('type') == 'shop_update':
            if photo:
                con.execute('UPDATE shops SET name=?,address=?,email=?,phone=?,hours=?,services=?,lat=?,lng=?,template_id=?,photo_path=?,operation_mode=? WHERE id=?', (data.get('name', ''), data.get('address', ''), data.get('email', ''), data.get('phone', ''), data.get('hours', ''), data.get('services', ''), data.get('lat') or None, data.get('lng') or None, data.get('template_id') or None, photo, data.get('operation_mode', 'Libre service'), data.get('id')))
            else:
                con.execute('UPDATE shops SET name=?,address=?,email=?,phone=?,hours=?,services=?,lat=?,lng=?,template_id=?,operation_mode=? WHERE id=?', (data.get('name', ''), data.get('address', ''), data.get('email', ''), data.get('phone', ''), data.get('hours', ''), data.get('services', ''), data.get('lat') or None, data.get('lng') or None, data.get('template_id') or None, data.get('operation_mode', 'Libre service'), data.get('id')))
        elif data.get('type') == 'shop_delete':
            con.execute('DELETE FROM shops WHERE id=?', (data.get('id'),))
        con.commit()
        con.close()
        return redirect(start_response, '/admin/shops')
    con = db()
    if user['role'] == 'admin':
        shops = con.execute('SELECT * FROM shops ORDER BY id DESC').fetchall()
    else:
        shops = allowed_stock_shops(con, user)
    templates = con.execute('SELECT * FROM templates ORDER BY name').fetchall()
    services_dropdown = service_select_options(con)
    con.close()
    tpl_options = options(templates, empty=True)
    rows = ''.join([
        f"<tr><td>{shop['id']}</td><td>{escape(shop['name'] or '')}</td><td>{escape(shop['address'] or '')}</td><td>{escape(shop['email'] or '')}</td><td>{escape(str(shop['template_id'] or ''))}</td><td>{escape(shop['operation_mode'] or 'Libre service')}</td><td>{escape(shop['photo_path'] or '')}</td><td>{f"<form class='inline' method='post'><input type='hidden' name='type' value='shop_delete'><input type='hidden' name='id' value='{shop['id']}'><button class='danger'>Supprimer</button></form>" if user['role'] == 'admin' else 'Lecture seule'}</td></tr>"
        for shop in shops
    ])
    manager_notice = '' if user['role'] == 'admin' else "<div class='card'><p>Vue filtrée manager : boutiques de référence uniquement. La création, la modification et la suppression restent réservées à l’admin.</p></div>"
    admin_style = '' if user['role'] == 'admin' else 'display:none'
    body = f"""
{shop_admin_subtabs('shops')}
<div class='card'><h3>Liste des boutiques</h3><table class='table'><tr><th>id</th><th>name</th><th>address</th><th>email</th><th>template_id</th><th>operation_mode</th><th>photo_path</th><th>action</th></tr>{rows}</table></div>
{manager_notice}
<div class='grid'>
  <div class='card' style='{admin_style}'><h3>Création boutique</h3><form method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='shop_create'><label>name</label><input name='name' required><label>address</label><input name='address' required><label>email</label><input name='email' type='email' required><label>phone</label><input name='phone' required><label>hours</label><input name='hours' required><label>services</label><select name='services' required>{services_dropdown}</select><label>operation_mode</label><select name='operation_mode' required><option value='Libre service'>Libre service</option><option value='Réservation'>Réservation</option></select><label>lat</label><input name='lat' type='number' step='any'><label>lng</label><input name='lng' type='number' step='any'><label>template_id</label><select name='template_id'>{tpl_options}</select><label>shop_photo</label><input type='file' name='shop_photo' accept='image/*'><button>Créer</button></form></div>
  <div class='card' style='{admin_style}'><h3>Édition / modification boutique</h3><form method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='shop_update'><label>id</label><input name='id' required><label>name</label><input name='name' required><label>address</label><input name='address' required><label>email</label><input name='email' type='email' required><label>phone</label><input name='phone' required><label>hours</label><input name='hours' required><label>services</label><select name='services' required>{services_dropdown}</select><label>operation_mode</label><select name='operation_mode' required><option value='Libre service'>Libre service</option><option value='Réservation'>Réservation</option></select><label>lat</label><input name='lat' type='number' step='any'><label>lng</label><input name='lng' type='number' step='any'><label>template_id</label><select name='template_id'>{tpl_options}</select><label>shop_photo</label><input type='file' name='shop_photo' accept='image/*'><button>Modifier</button></form></div>
</div>
"""
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Gestion des boutiques', admin_shell('/admin/shops', 'Gestion des boutiques', body), user)]


def manager_shop_labels(con, manager_id):
    rows = con.execute(
        'SELECT s.id,s.name FROM manager_shops ms JOIN shops s ON s.id=ms.shop_id WHERE ms.manager_id=? ORDER BY s.name',
        (manager_id,),
    ).fetchall()
    return ', '.join([f"{row['id']} - {row['name']}" for row in rows]) or 'Aucune boutique référente'


def sync_manager_shops(con, manager_id, shop_ids):
    con.execute('DELETE FROM manager_shops WHERE manager_id=?', (manager_id,))
    for shop_id in shop_ids:
        if shop_id:
            con.execute('INSERT OR IGNORE INTO manager_shops(manager_id,shop_id) VALUES(?,?)', (manager_id, shop_id))


def admin_managers(environ, start_response, user):
    blocked = require_admin(user, start_response)
    if blocked:
        return blocked
    if environ['REQUEST_METHOD'] == 'POST':
        parsed = parse_post_multi(environ)
        action = first_value(parsed, 'type')
        shop_ids = parsed.get('shop_ids', [])
        con = db()
        if action == 'manager_create':
            cursor = con.execute(
                'INSERT INTO users(name,email,password,role,registered_at) VALUES(?,?,?,?,datetime("now"))',
                (first_value(parsed, 'name'), first_value(parsed, 'email'), hash_pw(first_value(parsed, 'password')), 'manager'),
            )
            sync_manager_shops(con, cursor.lastrowid, shop_ids)
        elif action == 'manager_update':
            manager_id = first_value(parsed, 'id')
            con.execute(
                'UPDATE users SET name=?,email=? WHERE id=? AND role="manager"',
                (first_value(parsed, 'name'), first_value(parsed, 'email'), manager_id),
            )
            if first_value(parsed, 'password'):
                con.execute('UPDATE users SET password=? WHERE id=? AND role="manager"', (hash_pw(first_value(parsed, 'password')), manager_id))
            sync_manager_shops(con, manager_id, shop_ids)
        elif action == 'manager_delete':
            manager_id = first_value(parsed, 'id')
            con.execute('DELETE FROM manager_shops WHERE manager_id=?', (manager_id,))
            con.execute('DELETE FROM users WHERE id=? AND role="manager"', (manager_id,))
        con.commit()
        con.close()
        return redirect(start_response, '/admin/managers')
    con = db()
    managers = con.execute("SELECT * FROM users WHERE role='manager' ORDER BY id DESC").fetchall()
    shops = con.execute('SELECT * FROM shops ORDER BY name').fetchall()
    rows = ''.join([
        f"<tr><td>{manager['id']}</td><td>{escape(manager['name'] or '')}</td><td>{escape(manager['email'] or '')}</td><td>{escape(manager_shop_labels(con, manager['id']))}</td><td><form class='inline' method='post'><input type='hidden' name='type' value='manager_delete'><input type='hidden' name='id' value='{manager['id']}'><button class='danger'>Supprimer</button></form></td></tr>"
        for manager in managers
    ])
    shop_options = ''.join([f"<option value='{shop['id']}'>{shop['id']} - {escape(shop['name'] or '')}</option>" for shop in shops])
    con.close()
    body = f"""
<div class='card'><h3>Références boutiques</h3><p><strong>Admin :</strong> référent sur toutes les boutiques.</p><p><strong>Managers :</strong> référents sur une ou plusieurs boutiques sélectionnées ci-dessous.</p></div>
<div class='card'><h3>Liste des managers</h3><table class='table'><tr><th>id</th><th>name</th><th>email</th><th>boutiques de référence</th><th>action</th></tr>{rows}</table></div>
<div class='grid'>
  <div class='card'><h3>Création manager</h3><form method='post'><input type='hidden' name='type' value='manager_create'><label>name</label><input name='name' required><label>email</label><input name='email' type='email' required><label>password</label><input name='password' type='password' required><label>shop_ids</label><select name='shop_ids' multiple size='6' required>{shop_options}</select><small>Maintenir Ctrl/Cmd pour sélectionner plusieurs boutiques.</small><button>Créer</button></form></div>
  <div class='card'><h3>Édition / modification manager</h3><form method='post'><input type='hidden' name='type' value='manager_update'><label>id</label><input name='id' required><label>name</label><input name='name' required><label>email</label><input name='email' type='email' required><label>password</label><input name='password' type='password' placeholder='laisser vide pour conserver'><label>shop_ids</label><select name='shop_ids' multiple size='6' required>{shop_options}</select><small>La sélection remplace les boutiques de référence actuelles.</small><button>Modifier</button></form></div>
</div>
"""
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Gestion des managers', admin_shell('/admin/managers', 'Gestion des managers', body), user)]


def manager_reference_shop_ids(con, manager_id):
    rows = con.execute('SELECT shop_id FROM manager_shops WHERE manager_id=?', (manager_id,)).fetchall()
    return [str(row['shop_id']) for row in rows]


def dog_allowed(con, user, dog_id):
    if user['role'] == 'admin':
        return True
    row = con.execute('SELECT u.shop_id FROM dogs d JOIN users u ON u.id=d.client_id WHERE d.id=?', (dog_id,)).fetchone()
    return bool(row and str(row['shop_id']) in manager_reference_shop_ids(con, user['id']))


def admin_dogs(environ, start_response, user):
    blocked = require_admin_or_manager(user, start_response)
    if blocked:
        return blocked
    con = db()
    manager_shop_ids = manager_reference_shop_ids(con, user['id']) if user['role'] == 'manager' else []
    if environ['REQUEST_METHOD'] == 'POST':
        data = parse_post(environ)
        action = data.get('type')
        if action == 'dog_create':
            client = con.execute('SELECT id,shop_id FROM users WHERE id=? AND role="client"', (data.get('client_id'),)).fetchone()
            if client and (user['role'] == 'admin' or str(client['shop_id']) in manager_shop_ids):
                con.execute(
                    'INSERT INTO dogs(client_id,name,breed,weight,washes,age,registered_at) VALUES(?,?,?,?,?,?,COALESCE(NULLIF(?,""),datetime("now")))',
                    (data.get('client_id'), data.get('name', ''), data.get('breed', ''), data.get('weight') or None, data.get('washes') or 0, data.get('age') or None, data.get('registered_at', '')),
                )
        elif action == 'dog_update' and dog_allowed(con, user, data.get('id')):
            new_client = con.execute('SELECT id,shop_id FROM users WHERE id=? AND role="client"', (data.get('client_id'),)).fetchone()
            if new_client and (user['role'] == 'admin' or str(new_client['shop_id']) in manager_shop_ids):
                con.execute(
                    'UPDATE dogs SET client_id=?,name=?,breed=?,weight=?,washes=?,age=?,registered_at=COALESCE(NULLIF(?,""),registered_at) WHERE id=?',
                    (data.get('client_id'), data.get('name', ''), data.get('breed', ''), data.get('weight') or None, data.get('washes') or 0, data.get('age') or None, data.get('registered_at', ''), data.get('id')),
                )
        elif action == 'dog_delete' and dog_allowed(con, user, data.get('id')):
            con.execute('DELETE FROM dogs WHERE id=?', (data.get('id'),))
        con.commit()
        con.close()
        return redirect(start_response, '/admin/dogs')
    if user['role'] == 'admin':
        dogs = con.execute("""
            SELECT d.*,u.name AS client_name,u.email AS client_email,s.name AS shop_name,s.id AS shop_id
            FROM dogs d JOIN users u ON u.id=d.client_id LEFT JOIN shops s ON s.id=u.shop_id
            ORDER BY d.id DESC
        """).fetchall()
        clients = con.execute("SELECT u.*,s.name AS shop_name FROM users u LEFT JOIN shops s ON s.id=u.shop_id WHERE u.role='client' ORDER BY u.name").fetchall()
        scope_note = 'Admin : accès à tous les chiens de toutes les boutiques.'
    else:
        if manager_shop_ids:
            placeholders = ','.join(['?'] * len(manager_shop_ids))
            dogs = con.execute(f"""
                SELECT d.*,u.name AS client_name,u.email AS client_email,s.name AS shop_name,s.id AS shop_id
                FROM dogs d JOIN users u ON u.id=d.client_id LEFT JOIN shops s ON s.id=u.shop_id
                WHERE u.shop_id IN ({placeholders})
                ORDER BY d.id DESC
            """, manager_shop_ids).fetchall()
            clients = con.execute(f"SELECT u.*,s.name AS shop_name FROM users u LEFT JOIN shops s ON s.id=u.shop_id WHERE u.role='client' AND u.shop_id IN ({placeholders}) ORDER BY u.name", manager_shop_ids).fetchall()
        else:
            dogs = []
            clients = []
        scope_note = 'Manager : accès limité aux chiens des clients rattachés aux boutiques de référence.'
    client_options = ''.join([f"<option value='{client['id']}'>{client['id']} - {escape(client['name'] or '')} ({escape(client['shop_name'] or 'Sans boutique')})</option>" for client in clients])
    rows = ''.join([
        f"<tr><td>{dog['id']}</td><td>{escape(dog['name'] or '')}</td><td>{escape(dog['breed'] or '')}</td><td>{escape(str(dog['weight'] or ''))}</td><td>{dog['washes']}</td><td>{escape(str(dog['age'] or ''))}</td><td>{escape(dog['registered_at'] or '')}</td><td>{escape(dog['client_name'] or '')}<br><small>{escape(dog['client_email'] or '')}</small></td><td>{escape(str(dog['shop_id'] or ''))} - {escape(dog['shop_name'] or 'Sans boutique')}</td><td><form class='inline' method='post'><input type='hidden' name='type' value='dog_delete'><input type='hidden' name='id' value='{dog['id']}'><button class='danger'>Supprimer</button></form></td></tr>"
        for dog in dogs
    ])
    con.close()
    body = f"""
<div class='card'><h3>Périmètre d’accès</h3><p>{scope_note}</p></div>
<div class='card'><h3>Liste des chiens</h3><table class='table'><tr><th>id</th><th>name</th><th>breed</th><th>weight</th><th>washes</th><th>âge</th><th>inscription</th><th>client</th><th>boutique</th><th>action</th></tr>{rows}</table></div>
<div class='grid'>
  <div class='card'><h3>Création chien</h3><form method='post'><input type='hidden' name='type' value='dog_create'><label>client_id</label><select name='client_id' required>{client_options}</select><label>name</label><input name='name' required><label>breed</label><input name='breed' required><label>weight</label><input name='weight' type='number' step='0.1'><label>washes</label><input name='washes' type='number' min='0' value='0'><label>age</label><input name='age' type='number' min='0'><label>registered_at</label><input name='registered_at' type='date'><button>Créer</button></form></div>
  <div class='card'><h3>Édition / modification chien</h3><form method='post'><input type='hidden' name='type' value='dog_update'><label>id</label><input name='id' required><label>client_id</label><select name='client_id' required>{client_options}</select><label>name</label><input name='name' required><label>breed</label><input name='breed' required><label>weight</label><input name='weight' type='number' step='0.1'><label>washes</label><input name='washes' type='number' min='0' value='0'><label>age</label><input name='age' type='number' min='0'><label>registered_at</label><input name='registered_at' type='date'><button>Modifier</button></form></div>
</div>
"""
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Gestion des chiens', admin_shell('/admin/dogs', 'Gestion des chiens', body), user)]


def admin_clients(environ, start_response, user):
    blocked = require_admin(user, start_response)
    if blocked:
        return blocked
    if environ['REQUEST_METHOD'] == 'POST':
        if 'multipart/form-data' in environ.get('CONTENT_TYPE', ''):
            data, files = parse_multipart(environ)
        else:
            data, files = parse_post(environ), {}
        avatar = save_upload(files['avatar'], UPLOAD_DIR, 'client_') if files.get('avatar') else None
        con = db()
        if data.get('type') == 'client_create':
            con.execute(
                'INSERT INTO users(name,first_name,email,password,role,shop_id,phone,vcard,birth_date,registered_at,avatar_path) VALUES(?,?,?,?,?,?,?,?,?,COALESCE(NULLIF(?,""),datetime("now")),?)',
                (data.get('name', ''), data.get('first_name', ''), data.get('email', ''), hash_pw(data.get('password', '')), 'client', data.get('shop_id') or None, data.get('phone', ''), data.get('vcard', ''), data.get('birth_date', ''), data.get('registered_at', ''), avatar),
            )
        elif data.get('type') == 'client_update':
            if avatar:
                con.execute(
                    'UPDATE users SET name=?,first_name=?,email=?,shop_id=?,phone=?,vcard=?,birth_date=?,registered_at=COALESCE(NULLIF(?,""),registered_at),avatar_path=? WHERE id=? AND role="client"',
                    (data.get('name', ''), data.get('first_name', ''), data.get('email', ''), data.get('shop_id') or None, data.get('phone', ''), data.get('vcard', ''), data.get('birth_date', ''), data.get('registered_at', ''), avatar, data.get('id')),
                )
            else:
                con.execute(
                    'UPDATE users SET name=?,first_name=?,email=?,shop_id=?,phone=?,vcard=?,birth_date=?,registered_at=COALESCE(NULLIF(?,""),registered_at) WHERE id=? AND role="client"',
                    (data.get('name', ''), data.get('first_name', ''), data.get('email', ''), data.get('shop_id') or None, data.get('phone', ''), data.get('vcard', ''), data.get('birth_date', ''), data.get('registered_at', ''), data.get('id')),
                )
            if data.get('password'):
                con.execute('UPDATE users SET password=? WHERE id=? AND role="client"', (hash_pw(data.get('password')), data.get('id')))
        elif data.get('type') == 'client_delete':
            con.execute('DELETE FROM dogs WHERE client_id=?', (data.get('id'),))
            con.execute('DELETE FROM users WHERE id=? AND role="client"', (data.get('id'),))
        con.commit()
        con.close()
        return redirect(start_response, '/admin/clients')
    con = db()
    clients = con.execute("SELECT * FROM users WHERE role='client' ORDER BY name COLLATE NOCASE, first_name COLLATE NOCASE").fetchall()
    shops = con.execute('SELECT * FROM shops ORDER BY name').fetchall()
    con.close()
    shop_options = options(shops, empty=True)
    rows = ''.join([
        f"<tr data-search='{escape((client['id'].__str__() + ' ' + (client['name'] or '') + ' ' + (client['first_name'] or '') + ' ' + (client['email'] or '') + ' ' + (client['phone'] or '') + ' ' + (client['vcard'] or '')).lower())}'><td>{client['id']}</td><td>{escape(client['name'] or '')}</td><td>{escape(client['first_name'] or '')}</td><td>{escape(client['email'] or '')}</td><td>{escape(client['vcard'] or '')}</td><td>{escape(client['birth_date'] or '')}</td><td>{escape(client['registered_at'] or '')}</td><td><form class='inline' method='post'><input type='hidden' name='type' value='client_delete'><input type='hidden' name='id' value='{client['id']}'><button class='danger'>Supprimer</button></form></td></tr>"
        for client in clients
    ])
    cards = ''.join([
        f"<article class='tile client-tile' data-search='{escape(((client['name'] or '') + ' ' + (client['first_name'] or '') + ' ' + (client['email'] or '') + ' ' + (client['phone'] or '') + ' ' + (client['vcard'] or '')).lower())}'><img class='avatar' src='/{escape(client['avatar_path'] or '')}' alt='Avatar' onerror=\"this.style.display='none'\" {'' if client['avatar_path'] else 'style=\"display:none\"'}><h3>{escape(client['name'] or '')} {escape(client['first_name'] or '')}</h3><p><strong>@Mél :</strong> {escape(client['email'] or '')}<br><strong>Téléphone :</strong> {escape(client['phone'] or '')}<br><strong>vcard :</strong> {escape(client['vcard'] or '')}<br><strong>Date de naissance :</strong> {escape(client['birth_date'] or '')}<br><strong>Date d’enregistrement :</strong> {escape(client['registered_at'] or '')}</p></article>"
        for client in sorted(clients, key=lambda item: ((item['name'] or '').lower(), (item['first_name'] or '').lower()))
    ])
    body = f"""
<div class='card toolbar'>
  <button type='button' id='tableViewBtn'>Affichage tableau</button>
  <button type='button' id='cardViewBtn'>Affichage vignettes</button>
  <input id='clientSearch' placeholder='Recherche dynamique client...'>
  <button type='button' id='exportCsvBtn'>Export CSV</button>
  <button type='button' id='exportMdBtn'>Export Markdown</button>
  <button type='button' id='exportPdfBtn'>Export PDF</button>
</div>
<div id='clientsTableView' class='card'><h3>Liste des clients - tableau</h3><table id='clientsTable' class='table'><thead><tr><th data-type='number'>ID</th><th>Nom</th><th>Prénom</th><th>@Mél</th><th>vcard</th><th>Date de naissance</th><th>Date d’enregistrement</th><th>action</th></tr></thead><tbody>{rows}</tbody></table></div>
<div id='clientsCardView' class='card hidden'><h3>Liste des clients - vignettes</h3><div class='tile-grid'>{cards}</div></div>
<div class='grid'>
  <div class='card'><h3>Création client</h3><form id='clientCreateForm' method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='client_create'><label>import_vcard_3</label><input id='vcardImport' type='file' accept='.vcf,text/vcard,text/x-vcard'><small>Importer un fichier vCard version 3.0 pour pré-remplir Nom, Prénom, @Mél, Téléphone, vcard et Date de naissance.</small><label>name</label><input name='name' required><label>first_name</label><input name='first_name'><label>email</label><input name='email' type='email' required><label>phone</label><input name='phone'><label>vcard</label><input name='vcard'><label>birth_date</label><input name='birth_date' type='date'><label>registered_at</label><input name='registered_at' type='date'><label>avatar</label><input name='avatar' type='file' accept='image/*'><label>password</label><input name='password' type='password' required><label>shop_id</label><select name='shop_id'>{shop_options}</select><button>Créer</button></form></div>
  <div class='card'><h3>Édition / modification client</h3><form method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='client_update'><label>id</label><input name='id' required><label>name</label><input name='name' required><label>first_name</label><input name='first_name'><label>email</label><input name='email' type='email' required><label>phone</label><input name='phone'><label>vcard</label><input name='vcard'><label>birth_date</label><input name='birth_date' type='date'><label>registered_at</label><input name='registered_at' type='date'><label>avatar</label><input name='avatar' type='file' accept='image/*'><label>password</label><input name='password' type='password' placeholder='laisser vide pour conserver'><label>shop_id</label><select name='shop_id'>{shop_options}</select><button>Modifier</button></form></div>
</div>
<script>
const tableView = document.getElementById('clientsTableView');
const cardView = document.getElementById('clientsCardView');
const search = document.getElementById('clientSearch');

const vcardImport = document.getElementById('vcardImport');
function unfoldVcard(text) {{
  return text.replace(/\r?\n[ \t]/g, '').split(/\r?\n/).map(line => line.trim()).filter(Boolean);
}}
function vcardValue(lines, key) {{
  const prefix = key.toUpperCase();
  const line = lines.find(item => item.toUpperCase().startsWith(prefix + ':') || item.toUpperCase().startsWith(prefix + ';'));
  return line ? line.slice(line.indexOf(':') + 1).trim() : '';
}}
function normalizeVcardDate(value) {{
  const clean = value.trim();
  if (/^\\d{{8}}$/.test(clean)) return clean.slice(0, 4) + '-' + clean.slice(4, 6) + '-' + clean.slice(6, 8);
  return clean;
}}
function fillCreateClientFromVcard(text) {{
  const lines = unfoldVcard(text);
  const version = vcardValue(lines, 'VERSION');
  if (version && version !== '3.0') alert('Attention : le fichier vCard importé n’est pas en version 3.0.');
  const form = document.getElementById('clientCreateForm');
  const n = vcardValue(lines, 'N').split(';');
  const fullName = vcardValue(lines, 'FN');
  const lastName = n[0] || fullName.split(' ').slice(-1).join(' ');
  const firstName = n[1] || fullName.split(' ').slice(0, -1).join(' ');
  form.elements.name.value = lastName || form.elements.name.value;
  form.elements.first_name.value = firstName || form.elements.first_name.value;
  form.elements.email.value = vcardValue(lines, 'EMAIL') || form.elements.email.value;
  form.elements.phone.value = vcardValue(lines, 'TEL') || form.elements.phone.value;
  form.elements.birth_date.value = normalizeVcardDate(vcardValue(lines, 'BDAY')) || form.elements.birth_date.value;
  form.elements.vcard.value = fullName || 'vCard 3.0 importée';
}}
if (vcardImport) {{
  vcardImport.addEventListener('change', event => {{
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => fillCreateClientFromVcard(String(reader.result || ''));
    reader.readAsText(file);
  }});
}}
document.getElementById('tableViewBtn').onclick = () => {{ tableView.classList.remove('hidden'); cardView.classList.add('hidden'); }};
document.getElementById('cardViewBtn').onclick = () => {{ cardView.classList.remove('hidden'); tableView.classList.add('hidden'); }};
function visibleRows() {{ return Array.from(document.querySelectorAll('#clientsTable tbody tr')).filter(row => row.style.display !== 'none'); }}
function filterClients() {{
  const term = search.value.trim().toLowerCase();
  document.querySelectorAll('#clientsTable tbody tr,.client-tile').forEach(item => {{ item.style.display = item.dataset.search.includes(term) ? '' : 'none'; }});
}}
search.addEventListener('input', filterClients);
document.querySelectorAll('#clientsTable th').forEach((th, index) => {{
  if (index === 7) return;
  th.addEventListener('click', () => {{
    const tbody = document.querySelector('#clientsTable tbody');
    const asc = th.dataset.asc !== 'true';
    th.dataset.asc = asc;
    Array.from(tbody.rows).sort((a, b) => {{
      const av = a.cells[index].innerText.trim();
      const bv = b.cells[index].innerText.trim();
      if (th.dataset.type === 'number') return asc ? Number(av) - Number(bv) : Number(bv) - Number(av);
      return asc ? av.localeCompare(bv, 'fr') : bv.localeCompare(av, 'fr');
    }}).forEach(row => tbody.appendChild(row));
  }});
}});
function tableData() {{
  const headers = Array.from(document.querySelectorAll('#clientsTable thead th')).slice(0, 7).map(th => th.innerText.trim());
  const rows = visibleRows().map(row => Array.from(row.cells).slice(0, 7).map(cell => cell.innerText.trim()));
  return {{ headers, rows }};
}}
function download(name, type, content) {{
  const blob = new Blob([content], {{ type }});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = name; a.click(); URL.revokeObjectURL(a.href);
}}
document.getElementById('exportCsvBtn').onclick = () => {{
  const data = tableData();
  const esc = value => '"' + value.replaceAll('"', '""') + '"';
  download('clients.csv', 'text/csv;charset=utf-8', [data.headers.map(esc).join(','), ...data.rows.map(row => row.map(esc).join(','))].join('\n'));
}};
document.getElementById('exportMdBtn').onclick = () => {{
  const data = tableData();
  const header = '| ' + data.headers.join(' | ') + ' |';
  const sep = '| ' + data.headers.map(() => '---').join(' | ') + ' |';
  const rows = data.rows.map(row => '| ' + row.join(' | ') + ' |');
  download('clients.md', 'text/markdown;charset=utf-8', [header, sep, ...rows].join('\n'));
}};
document.getElementById('exportPdfBtn').onclick = () => {{
  const popup = window.open('', '_blank');
  popup.document.write('<html><head><title>clients.pdf</title><style>body{{font-family:Arial}} table{{width:100%;border-collapse:collapse}} th,td{{border:1px solid #ddd;padding:6px}} tr:nth-child(even){{background:#f8fbff}}</style></head><body><h1>Liste des clients</h1>' + document.getElementById('clientsTable').outerHTML + '</body></html>');
  popup.document.close(); popup.print();
}};
</script>
"""
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Gestion des clients', admin_shell('/admin/clients', 'Gestion des clients', body), user)]

def database_forms(active_path):
    return f"""
<div class='card'><h3>Informations base de données</h3><p><strong>Nom :</strong> {escape(DB)}<br><strong>Taille :</strong> {db_file_size()} octets</p></div>
<div class='grid'>
  <div class='card'><h3>Sauvegarde</h3><form method='post'><input type='hidden' name='type' value='db_backup'><button>Sauvegarde de la base de données</button></form></div>
  <div class='card'><h3>Export</h3><form method='post'><input type='hidden' name='type' value='db_export'><button>Export de la base de données</button></form></div>
  <div class='card'><h3>Import</h3><form method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='db_import'><label>database_file</label><input type='file' name='database_file' accept='.db,.sqlite,.sqlite3' required><button>Import de la base de données</button></form></div>
</div>
"""


def admin_database(environ, start_response, user):
    blocked = require_admin(user, start_response)
    if blocked:
        return blocked
    message = ''
    if environ['REQUEST_METHOD'] == 'POST':
        if 'multipart/form-data' in environ.get('CONTENT_TYPE', ''):
            data, files = parse_multipart(environ)
        else:
            data, files = parse_post(environ), {}
        if data.get('type') == 'db_export':
            return export_db(start_response)
        message = handle_db_action(data.get('type'), files)
    content = (f"<div class='card'><strong>{escape(message)}</strong></div>" if message else '') + database_forms('/admin/database')
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Gestion de la base de données', admin_shell('/admin/database', 'Gestion de la base de données', content), user)]


def admin_security(environ, start_response, user):
    blocked = require_admin(user, start_response)
    if blocked:
        return blocked
    message = ''
    if environ['REQUEST_METHOD'] == 'POST':
        if 'multipart/form-data' in environ.get('CONTENT_TYPE', ''):
            data, files = parse_multipart(environ)
        else:
            data, files = parse_post(environ), {}
        action = data.get('type')
        if action == 'admin_password':
            con = db()
            con.execute('UPDATE users SET password=? WHERE id=?', (hash_pw(data.get('new_password', '')), user['id']))
            con.commit()
            con.close()
            message = 'Mot de passe admin mis à jour.'
        elif action == 'logo_update' and files.get('home_logo'):
            logo_path = save_upload(files['home_logo'], UPLOAD_DIR, 'logo_')
            set_setting('home_logo_path', logo_path)
            message = 'Logo de la page d’accueil mis à jour.'
        elif action == 'db_export':
            return export_db(start_response)
        else:
            message = handle_db_action(action, files)
    current_logo = setting('home_logo_path')
    logo_preview = f"<img class='logo' src='/{escape(current_logo)}' alt='Logo actuel'>" if current_logo else '<p class="muted">Aucun logo personnalisé.</p>'
    content = f"""
{f"<div class='card'><strong>{escape(message)}</strong></div>" if message else ''}
<div class='card'><h3>Gestion de la sécurité</h3><p><strong>Nom de la base :</strong> {escape(DB)}<br><strong>Taille de la base :</strong> {db_file_size()} octets</p></div>
<div class='grid'>
  <div class='card'><h3>Changer le mot de passe admin</h3><form method='post'><input type='hidden' name='type' value='admin_password'><label>new_password</label><input name='new_password' type='password' required><button>Mettre à jour</button></form></div>
  <div class='card'><h3>Changer le logo d’accueil</h3>{logo_preview}<form method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='logo_update'><label>home_logo</label><input type='file' name='home_logo' accept='image/*' required><button>Changer le logo</button></form></div>
</div>
{database_forms('/admin/security')}
"""
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Gestion de la sécurité', admin_shell('/admin/security', 'Gestion de la sécurité', content), user)]


def register(environ, start_response, user):
    if environ['REQUEST_METHOD'] == 'GET':
        con = db()
        shops = con.execute('SELECT id,name FROM shops ORDER BY name').fetchall()
        con.close()
        body = f"<div class='card'><h2>Inscription client</h2><form method='post'><label>name</label><input name='name' required><label>email</label><input name='email' type='email' required><label>password</label><input name='password' type='password' required><label>shop_id</label><select name='shop_id'>{options(shops, empty=True)}</select><button>Créer</button></form></div>"
        start_response('200 OK', [('Content-Type', 'text/html')])
        return [html_page('Inscription', body, user)]
    data = parse_post(environ)
    con = db()
    con.execute('INSERT INTO users(name,first_name,email,password,role,shop_id,registered_at) VALUES(?,?,?,?,?,?,datetime("now"))', (data.get('name', ''), data.get('first_name', ''), data.get('email', ''), hash_pw(data.get('password', '')), 'client', data.get('shop_id') or None))
    con.commit()
    con.close()
    return redirect(start_response, '/login')


def login(environ, start_response, user):
    if environ['REQUEST_METHOD'] == 'GET':
        body = "<div class='card'><h2>Connexion</h2><form method='post'><label>email</label><input name='email' type='email'><label>password</label><input name='password' type='password'><button>Se connecter</button></form></div>"
        start_response('200 OK', [('Content-Type', 'text/html')])
        return [html_page('Connexion', body, user)]
    data = parse_post(environ)
    con = db()
    found = con.execute('SELECT * FROM users WHERE email=?', (data.get('email', ''),)).fetchone()
    if not found or not verify_pw(data.get('password', ''), found['password']):
        con.close()
        return redirect(start_response, '/login')
    if is_legacy_password_hash(found['password']):
        con.execute('UPDATE users SET password=? WHERE id=?', (hash_pw(data.get('password', '')), found['id']))
    token = secrets.token_hex(16)
    con.execute('INSERT INTO sessions(token,user_id) VALUES(?,?)', (token, found['id']))
    con.commit()
    con.close()
    target = '/admin/dashboard' if found['role'] in ('admin', 'manager') else '/client'
    return redirect(start_response, target, f"sid={token}.{sign(token)}; Path=/; HttpOnly; SameSite=Lax")


def logout(environ, start_response):
    sid = cookie_token(environ)
    if sid and '.' in sid:
        con = db()
        con.execute('DELETE FROM sessions WHERE token=?', (sid.split('.')[0],))
        con.commit()
        con.close()
    return redirect(start_response, '/', 'sid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')


def client_home(environ, start_response, user):
    if not user or user['role'] != 'client':
        return redirect(start_response, '/login')
    con = db()
    dogs = con.execute('SELECT * FROM dogs WHERE client_id=?', (user['id'],)).fetchall()
    con.close()
    body = f"<div class='card'><h2>Espace client</h2><p>ID={user['id']} name={escape(user['name'] or '')} email={escape(user['email'] or '')} shop_id={escape(str(user['shop_id'] or ''))}</p></div>" + ''.join([f"<div class='card'>{escape(dog['name'] or '')} | washes={dog['washes']}</div>" for dog in dogs])
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Client', body, user)]


def client_dogs(environ, start_response, user):
    if not user or user['role'] != 'client':
        return redirect(start_response, '/login')
    con = db()
    if environ['REQUEST_METHOD'] == 'POST':
        data = parse_post(environ)
        if data.get('action') == 'create':
            con.execute('INSERT INTO dogs(client_id,name,breed,weight,washes,age,registered_at) VALUES(?,?,?,?,0,?,datetime("now"))', (user['id'], data.get('name', ''), data.get('breed', ''), data.get('weight') or None, data.get('age') or None))
        if data.get('action') == 'wash':
            con.execute('UPDATE dogs SET washes=washes+1 WHERE id=? AND client_id=?', (data.get('dog_id'), user['id']))
        con.commit()
    dogs = con.execute('SELECT * FROM dogs WHERE client_id=? ORDER BY id DESC', (user['id'],)).fetchall()
    con.close()
    rows = ''.join([f"<div class='card'><h4>ID={dog['id']} name={escape(dog['name'] or '')}</h4><p>breed={escape(dog['breed'] or '')} weight={escape(str(dog['weight'] or ''))} age={escape(str(dog['age'] or ''))} registered_at={escape(dog['registered_at'] or '')} washes={dog['washes']}</p><form method='post'><input type='hidden' name='action' value='wash'><input type='hidden' name='dog_id' value='{dog['id']}'><button>Ajouter lavage</button></form></div>" for dog in dogs])
    body = "<div class='card'><h2>Mes chiens</h2><form method='post'><input type='hidden' name='action' value='create'><label>name</label><input name='name'><label>breed</label><input name='breed'><label>weight</label><input type='number' step='0.1' name='weight'><label>age</label><input type='number' min='0' name='age'><button>Ajouter</button></form></div>" + rows
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Chiens', body, user)]


def app(environ, start_response):
    init()
    path = environ['PATH_INFO']
    user = current_user(environ)
    if path.startswith('/uploads/'):
        file_path = uploaded_file_path(path)
        if not file_path or not os.path.isfile(file_path):
            start_response('404 Not Found', [('Content-Type', 'text/plain')])
            return [b'Not found']
        start_response('200 OK', [('Content-Type', 'application/octet-stream')])
        with open(file_path, 'rb') as file:
            return [file.read()]
    if path == '/':
        start_response('200 OK', [('Content-Type', 'text/html')])
        return [render_home(user)]
    if path == '/shops':
        start_response('200 OK', [('Content-Type', 'text/html')])
        return [render_public_shops(user)]
    if path == '/register':
        return register(environ, start_response, user)
    if path == '/login':
        return login(environ, start_response, user)
    if path == '/logout':
        return logout(environ, start_response)
    if path == '/admin':
        return redirect(start_response, '/admin/dashboard')
    if path == '/admin/dashboard':
        return admin_dashboard(environ, start_response, user)
    if path == '/admin/templates':
        return admin_templates(environ, start_response, user)
    if path == '/admin/shops':
        return admin_shops(environ, start_response, user)
    if path == '/admin/services':
        return admin_services(environ, start_response, user)
    if path == '/admin/clients':
        return admin_clients(environ, start_response, user)
    if path == '/admin/managers':
        return admin_managers(environ, start_response, user)
    if path == '/admin/dogs':
        return admin_dogs(environ, start_response, user)
    if path == '/admin/database':
        return admin_database(environ, start_response, user)
    if path == '/admin/security':
        return admin_security(environ, start_response, user)
    if path == '/client':
        return client_home(environ, start_response, user)
    if path == '/dogs':
        return client_dogs(environ, start_response, user)
    start_response('404 Not Found', [('Content-Type', 'text/plain')])
    return [b'Not Found']


if __name__ == '__main__':
    init()
    port = int(os.environ.get('PORT', 8000))
    print(f'Server on http://localhost:{port}')
    make_server('0.0.0.0', port, app).serve_forever()
