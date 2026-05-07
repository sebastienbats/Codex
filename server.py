import os, sqlite3, hashlib, hmac, secrets, shutil
from html import escape
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

DB = 'washdog.db'
UPLOAD_DIR = 'uploads'
IMPORT_DIR = 'imports'
SECRET = 'change-me-secret'

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(IMPORT_DIR, exist_ok=True)

CSS = '''
body{font-family:Arial,sans-serif;margin:0;background:#f5f7fb;color:#14233c}header{background:#0f6fff;color:#fff;padding:1rem}main{max-width:1180px;margin:auto;padding:1rem}.card{background:#fff;padding:1rem;border-radius:10px;margin:1rem 0;border:1px solid #d9e1ef;box-shadow:0 4px 14px rgba(20,35,60,.06)}a{color:#0f6fff}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}input,select,button,textarea{box-sizing:border-box;padding:.55rem;margin:.2rem 0 .7rem;width:100%;border:1px solid #cfd8e7;border-radius:7px}button{background:#0f6fff;color:#fff;border:0;font-weight:700;cursor:pointer}.danger{background:#b42318}.nav a{margin-right:1rem;color:#fff}.tabs{display:flex;flex-wrap:wrap;gap:.5rem}.tab{display:inline-block;padding:.55rem .8rem;background:#e9f0ff;border-radius:7px;text-decoration:none;font-weight:700}.tab.active{background:#0f6fff;color:#fff}small{color:#4a5a78}.logo{display:block;max-width:220px;max-height:180px;margin:1rem auto}.shop-photo{max-width:220px;border-radius:8px}.table{width:100%;border-collapse:collapse}.table th,.table td{border-bottom:1px solid #edf1f7;text-align:left;padding:.5rem;vertical-align:top}label{font-weight:700;display:block}.muted{color:#5b6b84}.inline{display:inline}.inline button{width:auto;padding:.45rem .7rem}
'''

ADMIN_TABS = [
    ('/admin/templates', 'Templates'),
    ('/admin/shops', 'Boutiques'),
    ('/admin/clients', 'Clients'),
    ('/admin/managers', 'Managers'),
    ('/admin/database', 'Base de données'),
    ('/admin/security', 'Sécurité'),
]


def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con


def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()


def sign(value):
    return hmac.new(SECRET.encode(), value.encode(), hashlib.sha256).hexdigest()


def init():
    con = db()
    c = con.cursor()
    c.executescript('''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT,email TEXT UNIQUE,password TEXT,role TEXT,shop_id INTEGER);
CREATE TABLE IF NOT EXISTS templates(id INTEGER PRIMARY KEY,name TEXT,description TEXT);
CREATE TABLE IF NOT EXISTS shops(id INTEGER PRIMARY KEY,name TEXT,address TEXT,email TEXT,phone TEXT,hours TEXT,services TEXT,lat REAL,lng REAL,template_id INTEGER,photo_path TEXT);
CREATE TABLE IF NOT EXISTS dogs(id INTEGER PRIMARY KEY,client_id INTEGER,name TEXT,breed TEXT,weight REAL,washes INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT);
CREATE TABLE IF NOT EXISTS manager_shops(manager_id INTEGER,shop_id INTEGER,PRIMARY KEY(manager_id,shop_id));
''')
    columns = [row['name'] for row in c.execute('PRAGMA table_info(shops)').fetchall()]
    if 'email' not in columns:
        c.execute('ALTER TABLE shops ADD COLUMN email TEXT')
    if 'photo_path' not in columns:
        c.execute('ALTER TABLE shops ADD COLUMN photo_path TEXT')
    admin = c.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
    if not admin:
        c.execute(
            'INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)',
            ('Admin', 'admin@washdog.local', hash_pw('admin123'), 'admin'),
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
    if sign(token) != sig:
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
    boundary = content_type.split('boundary=', 1)[1].encode()
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


def save_upload(file_data, directory, prefix):
    safe_name = secrets.token_hex(6) + '_' + os.path.basename(file_data['filename'])
    path = os.path.join(directory, prefix + safe_name)
    with open(path, 'wb') as output:
        output.write(file_data['content'])
    return path


def html_page(title, body, user=None):
    nav = '<div class="nav"><a href="/">Accueil</a><a href="/shops">Vitrines</a>'
    if user and user['role'] == 'admin':
        nav += '<a href="/admin/templates">Admin</a>'
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
        test_con = sqlite3.connect(uploaded)
        result = test_con.execute('PRAGMA quick_check').fetchone()[0]
        test_con.close()
        if result == 'ok':
            shutil.copyfile(DB, f"washdog_before_import_{secrets.token_hex(4)}.db")
            shutil.copyfile(uploaded, DB)
            return 'Base de données importée avec succès.'
        return f"Import refusé : contrôle SQLite invalide ({escape(str(result))})."
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
            f"<div class='card'><h3>{escape(row['name'] or '')}</h3>{image}<p>{escape(row['address'] or '')}<br>{escape(row['email'] or '')}<br>{escape(row['phone'] or '')}<br>{escape(row['hours'] or '')}<br>{escape(row['services'] or '')}</p></div>"
        )
    return html_page('Vitrines', ''.join(cards) or '<div class="card">Aucune boutique.</div>', user)


def options(rows, selected=None, empty=False):
    html = '<option value="">Aucun</option>' if empty else ''
    for row in rows:
        sel = ' selected' if selected is not None and str(row['id']) == str(selected) else ''
        html += f"<option value='{row['id']}'{sel}>{row['id']} - {escape(row['name'] or '')}</option>"
    return html


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


def admin_shops(environ, start_response, user):
    blocked = require_admin(user, start_response)
    if blocked:
        return blocked
    if environ['REQUEST_METHOD'] == 'POST':
        multipart = 'multipart/form-data' in environ.get('CONTENT_TYPE', '')
        data, files = parse_multipart(environ) if multipart else (parse_post(environ), {})
        photo = save_upload(files['shop_photo'], UPLOAD_DIR, 'shop_') if files.get('shop_photo') else None
        con = db()
        if data.get('type') == 'shop_create':
            con.execute('INSERT INTO shops(name,address,email,phone,hours,services,lat,lng,template_id,photo_path) VALUES(?,?,?,?,?,?,?,?,?,?)', (data.get('name', ''), data.get('address', ''), data.get('email', ''), data.get('phone', ''), data.get('hours', ''), data.get('services', ''), data.get('lat') or None, data.get('lng') or None, data.get('template_id') or None, photo))
        elif data.get('type') == 'shop_update':
            if photo:
                con.execute('UPDATE shops SET name=?,address=?,email=?,phone=?,hours=?,services=?,lat=?,lng=?,template_id=?,photo_path=? WHERE id=?', (data.get('name', ''), data.get('address', ''), data.get('email', ''), data.get('phone', ''), data.get('hours', ''), data.get('services', ''), data.get('lat') or None, data.get('lng') or None, data.get('template_id') or None, photo, data.get('id')))
            else:
                con.execute('UPDATE shops SET name=?,address=?,email=?,phone=?,hours=?,services=?,lat=?,lng=?,template_id=? WHERE id=?', (data.get('name', ''), data.get('address', ''), data.get('email', ''), data.get('phone', ''), data.get('hours', ''), data.get('services', ''), data.get('lat') or None, data.get('lng') or None, data.get('template_id') or None, data.get('id')))
        elif data.get('type') == 'shop_delete':
            con.execute('DELETE FROM shops WHERE id=?', (data.get('id'),))
        con.commit()
        con.close()
        return redirect(start_response, '/admin/shops')
    con = db()
    shops = con.execute('SELECT * FROM shops ORDER BY id DESC').fetchall()
    templates = con.execute('SELECT * FROM templates ORDER BY name').fetchall()
    con.close()
    tpl_options = options(templates, empty=True)
    rows = ''.join([
        f"<tr><td>{shop['id']}</td><td>{escape(shop['name'] or '')}</td><td>{escape(shop['address'] or '')}</td><td>{escape(shop['email'] or '')}</td><td>{escape(str(shop['template_id'] or ''))}</td><td>{escape(shop['photo_path'] or '')}</td><td><form class='inline' method='post'><input type='hidden' name='type' value='shop_delete'><input type='hidden' name='id' value='{shop['id']}'><button class='danger'>Supprimer</button></form></td></tr>"
        for shop in shops
    ])
    body = f"""
<div class='card'><h3>Liste des boutiques</h3><table class='table'><tr><th>id</th><th>name</th><th>address</th><th>email</th><th>template_id</th><th>photo_path</th><th>action</th></tr>{rows}</table></div>
<div class='grid'>
  <div class='card'><h3>Création boutique</h3><form method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='shop_create'><label>name</label><input name='name' required><label>address</label><input name='address' required><label>email</label><input name='email' type='email' required><label>phone</label><input name='phone' required><label>hours</label><input name='hours' required><label>services</label><input name='services' required><label>lat</label><input name='lat' type='number' step='any'><label>lng</label><input name='lng' type='number' step='any'><label>template_id</label><select name='template_id'>{tpl_options}</select><label>shop_photo</label><input type='file' name='shop_photo' accept='image/*'><button>Créer</button></form></div>
  <div class='card'><h3>Édition / modification boutique</h3><form method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='shop_update'><label>id</label><input name='id' required><label>name</label><input name='name' required><label>address</label><input name='address' required><label>email</label><input name='email' type='email' required><label>phone</label><input name='phone' required><label>hours</label><input name='hours' required><label>services</label><input name='services' required><label>lat</label><input name='lat' type='number' step='any'><label>lng</label><input name='lng' type='number' step='any'><label>template_id</label><select name='template_id'>{tpl_options}</select><label>shop_photo</label><input type='file' name='shop_photo' accept='image/*'><button>Modifier</button></form></div>
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
                'INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)',
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


def admin_clients(environ, start_response, user):
    blocked = require_admin(user, start_response)
    if blocked:
        return blocked
    if environ['REQUEST_METHOD'] == 'POST':
        data = parse_post(environ)
        con = db()
        if data.get('type') == 'client_create':
            con.execute('INSERT INTO users(name,email,password,role,shop_id) VALUES(?,?,?,?,?)', (data.get('name', ''), data.get('email', ''), hash_pw(data.get('password', '')), 'client', data.get('shop_id') or None))
        elif data.get('type') == 'client_update':
            con.execute('UPDATE users SET name=?,email=?,shop_id=? WHERE id=? AND role="client"', (data.get('name', ''), data.get('email', ''), data.get('shop_id') or None, data.get('id')))
            if data.get('password'):
                con.execute('UPDATE users SET password=? WHERE id=? AND role="client"', (hash_pw(data.get('password')), data.get('id')))
        elif data.get('type') == 'client_delete':
            con.execute('DELETE FROM dogs WHERE client_id=?', (data.get('id'),))
            con.execute('DELETE FROM users WHERE id=? AND role="client"', (data.get('id'),))
        con.commit()
        con.close()
        return redirect(start_response, '/admin/clients')
    con = db()
    clients = con.execute("SELECT * FROM users WHERE role='client' ORDER BY id DESC").fetchall()
    shops = con.execute('SELECT * FROM shops ORDER BY name').fetchall()
    con.close()
    shop_options = options(shops, empty=True)
    rows = ''.join([
        f"<tr><td>{client['id']}</td><td>{escape(client['name'] or '')}</td><td>{escape(client['email'] or '')}</td><td>{escape(str(client['shop_id'] or ''))}</td><td><form class='inline' method='post'><input type='hidden' name='type' value='client_delete'><input type='hidden' name='id' value='{client['id']}'><button class='danger'>Supprimer</button></form></td></tr>"
        for client in clients
    ])
    body = f"""
<div class='card'><h3>Liste des clients</h3><table class='table'><tr><th>id</th><th>name</th><th>email</th><th>shop_id</th><th>action</th></tr>{rows}</table></div>
<div class='grid'>
  <div class='card'><h3>Création client</h3><form method='post'><input type='hidden' name='type' value='client_create'><label>name</label><input name='name' required><label>email</label><input name='email' type='email' required><label>password</label><input name='password' type='password' required><label>shop_id</label><select name='shop_id'>{shop_options}</select><button>Créer</button></form></div>
  <div class='card'><h3>Édition / modification client</h3><form method='post'><input type='hidden' name='type' value='client_update'><label>id</label><input name='id' required><label>name</label><input name='name' required><label>email</label><input name='email' type='email' required><label>password</label><input name='password' type='password' placeholder='laisser vide pour conserver'><label>shop_id</label><select name='shop_id'>{shop_options}</select><button>Modifier</button></form></div>
</div>
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
    con.execute('INSERT INTO users(name,email,password,role,shop_id) VALUES(?,?,?,?,?)', (data.get('name', ''), data.get('email', ''), hash_pw(data.get('password', '')), 'client', data.get('shop_id') or None))
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
    found = con.execute('SELECT * FROM users WHERE email=? AND password=?', (data.get('email', ''), hash_pw(data.get('password', '')))).fetchone()
    con.close()
    if not found:
        return redirect(start_response, '/login')
    token = secrets.token_hex(16)
    con = db()
    con.execute('INSERT INTO sessions(token,user_id) VALUES(?,?)', (token, found['id']))
    con.commit()
    con.close()
    return redirect(start_response, '/admin/templates' if found['role'] == 'admin' else '/client', f"sid={token}.{sign(token)}; Path=/; HttpOnly")


def logout(environ, start_response):
    sid = cookie_token(environ)
    if sid and '.' in sid:
        con = db()
        con.execute('DELETE FROM sessions WHERE token=?', (sid.split('.')[0],))
        con.commit()
        con.close()
    return redirect(start_response, '/', 'sid=;Path=/;Max-Age=0')


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
            con.execute('INSERT INTO dogs(client_id,name,breed,weight,washes) VALUES(?,?,?,?,0)', (user['id'], data.get('name', ''), data.get('breed', ''), data.get('weight') or None))
        if data.get('action') == 'wash':
            con.execute('UPDATE dogs SET washes=washes+1 WHERE id=? AND client_id=?', (data.get('dog_id'), user['id']))
        con.commit()
    dogs = con.execute('SELECT * FROM dogs WHERE client_id=? ORDER BY id DESC', (user['id'],)).fetchall()
    con.close()
    rows = ''.join([f"<div class='card'><h4>ID={dog['id']} name={escape(dog['name'] or '')}</h4><p>breed={escape(dog['breed'] or '')} weight={escape(str(dog['weight'] or ''))} washes={dog['washes']}</p><form method='post'><input type='hidden' name='action' value='wash'><input type='hidden' name='dog_id' value='{dog['id']}'><button>Ajouter lavage</button></form></div>" for dog in dogs])
    body = "<div class='card'><h2>Mes chiens</h2><form method='post'><input type='hidden' name='action' value='create'><label>name</label><input name='name'><label>breed</label><input name='breed'><label>weight</label><input type='number' step='0.1' name='weight'><button>Ajouter</button></form></div>" + rows
    start_response('200 OK', [('Content-Type', 'text/html')])
    return [html_page('Chiens', body, user)]


def app(environ, start_response):
    init()
    path = environ['PATH_INFO']
    user = current_user(environ)
    if path.startswith('/uploads/'):
        file_path = path.lstrip('/')
        if not os.path.isfile(file_path):
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
        return redirect(start_response, '/admin/templates')
    if path == '/admin/templates':
        return admin_templates(environ, start_response, user)
    if path == '/admin/shops':
        return admin_shops(environ, start_response, user)
    if path == '/admin/clients':
        return admin_clients(environ, start_response, user)
    if path == '/admin/managers':
        return admin_managers(environ, start_response, user)
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
