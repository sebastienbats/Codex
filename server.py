import os, sqlite3, hashlib, hmac, secrets
from html import escape
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

DB='washdog.db'
SECRET='change-me-secret'

CSS='''body{font-family:Arial,sans-serif;margin:0;background:#f5f7fb}header{background:#0f6fff;color:#fff;padding:1rem}main{max-width:1000px;margin:auto;padding:1rem}.card{background:#fff;padding:1rem;border-radius:10px;margin:1rem 0;border:1px solid #d9e1ef}a{color:#0f6fff}input,select,button{padding:.5rem;margin:.2rem 0;width:100%}.row{display:grid;grid-template-columns:1fr 1fr;gap:1rem}.nav a{margin-right:1rem}'''

def db():
    con=sqlite3.connect(DB)
    con.row_factory=sqlite3.Row
    return con

def init():
    con=db();c=con.cursor()
    c.executescript('''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT,email TEXT UNIQUE,password TEXT,role TEXT,shop_id INTEGER);
CREATE TABLE IF NOT EXISTS templates(id INTEGER PRIMARY KEY,name TEXT,description TEXT);
CREATE TABLE IF NOT EXISTS shops(id INTEGER PRIMARY KEY,name TEXT,address TEXT,phone TEXT,hours TEXT,services TEXT,lat REAL,lng REAL,template_id INTEGER);
CREATE TABLE IF NOT EXISTS dogs(id INTEGER PRIMARY KEY,client_id INTEGER,name TEXT,breed TEXT,weight REAL,washes INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER);
''')
    admin = c.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
    if not admin:
        pwd=hashlib.sha256('admin123'.encode()).hexdigest()
        c.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",('Admin','admin@washdog.local',pwd,'admin'))
    con.commit();con.close()

def hash_pw(p): return hashlib.sha256(p.encode()).hexdigest()

def sign(v): return hmac.new(SECRET.encode(),v.encode(),hashlib.sha256).hexdigest()

def cookie_token(environ):
    ck=environ.get('HTTP_COOKIE','')
    for part in ck.split(';'):
        part=part.strip()
        if part.startswith('sid='):
            return part[4:]
    return None

def current_user(environ):
    sid=cookie_token(environ)
    if not sid or '.' not in sid: return None
    token,sig=sid.split('.',1)
    if sign(token)!=sig: return None
    con=db(); row=con.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?',(token,)).fetchone(); con.close(); return row

def parse_post(environ):
    size=int(environ.get('CONTENT_LENGTH') or 0)
    data=environ['wsgi.input'].read(size).decode()
    q=parse_qs(data)
    return {k:v[0] for k,v in q.items()}

def esc(value):
    if value is None:
        return ''
    return escape(str(value), quote=True)

def html(title,body,user=None):
    nav='<div class="nav"><a href="/">Accueil</a><a href="/shops">Vitrines</a>'
    if user and user['role']=='admin': nav+='<a href="/admin">Admin boutiques</a>'
    if user and user['role']=='client': nav+='<a href="/client">Espace client</a><a href="/dogs">Mes chiens</a>'
    if user: nav+='<a href="/logout">Déconnexion</a>'
    else: nav+='<a href="/login">Connexion</a><a href="/register">Inscription client</a>'
    nav+='</div>'
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{esc(title)}</title><style>{CSS}</style></head><body><header><h1>WashDog Pro</h1>{nav}</header><main>{body}</main></body></html>".encode()

def redirect(start_response,to,cookie=None):
    headers=[('Location',to)]
    if cookie: headers.append(('Set-Cookie',cookie))
    start_response('302 Found',headers); return [b'']

def app(environ,start_response):
    path=environ['PATH_INFO']; method=environ['REQUEST_METHOD']; user=current_user(environ)
    if path=='/':
        start_response('200 OK',[('Content-Type','text/html')]);return [html('Accueil','<div class="card"><h2>Plateforme dynamique multi-pages</h2><p>Vitrines publiques, accès admin et client sécurisés.</p></div>',user)]
    if path=='/shops':
        con=db(); rows=con.execute('SELECT * FROM shops').fetchall(); con.close()
        cards=''.join([f"<div class='card'><h3>{esc(r['name'])}</h3><p>{esc(r['address'])}<br>{esc(r['phone'])}<br>{esc(r['hours'])}<br>{esc(r['services'])}</p></div>" for r in rows]) or '<div class="card">Aucune boutique.</div>'
        start_response('200 OK',[('Content-Type','text/html')]); return [html('Vitrines',cards,user)]
    if path=='/register':
        if method=='GET':
            con=db();shops=con.execute('SELECT id,name FROM shops').fetchall();con.close()
            opts=''.join([f"<option value='{esc(s['id'])}'>{esc(s['name'])}</option>" for s in shops])
            body=f"<div class='card'><h2>Inscription client</h2><form method='post'><input name='name' placeholder='Nom' required><input name='email' type='email' required><input name='password' type='password' required><select name='shop_id' required>{opts}</select><button>Créer compte</button></form></div>"
            start_response('200 OK',[('Content-Type','text/html')]);return [html('Inscription',body,user)]
        d=parse_post(environ); con=db()
        try:
            con.execute('INSERT INTO users(name,email,password,role,shop_id) VALUES(?,?,?,?,?)',(d['name'],d['email'],hash_pw(d['password']),'client',d['shop_id']))
            con.commit()
        except Exception:
            pass
        con.close(); return redirect(start_response,'/login')
    if path=='/login':
        if method=='GET':
            body="<div class='card'><h2>Connexion</h2><form method='post'><input name='email' type='email' required><input name='password' type='password' required><button>Se connecter</button></form></div>"
            start_response('200 OK',[('Content-Type','text/html')]);return [html('Connexion',body,user)]
        d=parse_post(environ); con=db(); u=con.execute('SELECT * FROM users WHERE email=? AND password=?',(d['email'],hash_pw(d['password']))).fetchone(); con.close()
        if not u: return redirect(start_response,'/login')
        token=secrets.token_hex(16); con=db(); con.execute('INSERT INTO sessions(token,user_id) VALUES(?,?)',(token,u['id'])); con.commit(); con.close()
        return redirect(start_response,'/admin' if u['role']=='admin' else '/client',f"sid={token}.{sign(token)}; Path=/; HttpOnly")
    if path=='/logout':
        sid=cookie_token(environ)
        if sid and '.' in sid:
            token=sid.split('.')[0]; con=db(); con.execute('DELETE FROM sessions WHERE token=?',(token,)); con.commit(); con.close()
        return redirect(start_response,'/','sid=;Path=/;Max-Age=0')

    if path=='/admin':
        if not user or user['role']!='admin': return redirect(start_response,'/login')
        con=db()
        if method=='POST':
            d=parse_post(environ)
            if d.get('type')=='template': con.execute('INSERT INTO templates(name,description) VALUES(?,?)',(d['name'],d['description']))
            if d.get('type')=='shop': con.execute('INSERT INTO shops(name,address,phone,hours,services,lat,lng,template_id) VALUES(?,?,?,?,?,?,?,?)',(d['name'],d['address'],d['phone'],d['hours'],d['services'],d['lat'],d['lng'],d['template_id']))
            con.commit()
        tpls=con.execute('SELECT * FROM templates').fetchall(); shops=con.execute('SELECT * FROM shops').fetchall(); con.close()
        trows=''.join([f"<li>{esc(t['name'])} - {esc(t['description'])}</li>" for t in tpls])
        srows=''.join([f"<li>{esc(s['name'])} ({esc(s['address'])})</li>" for s in shops])
        opts=''.join([f"<option value='{esc(t['id'])}'>{esc(t['name'])}</option>" for t in tpls])
        body=f"""
<div class='card'><h2>Admin - Templates</h2><form method='post'><input type='hidden' name='type' value='template'><input name='name' required><input name='description' required><button>Ajouter template</button></form><ul>{trows}</ul></div>
<div class='card'><h2>Admin - Boutiques</h2><form method='post'>
<input type='hidden' name='type' value='shop'><input name='name' placeholder='Nom' required><input name='address' placeholder='Adresse' required><input name='phone' required><input name='hours' required><input name='services' required><div class='row'><input name='lat' type='number' step='any' required><input name='lng' type='number' step='any' required></div><select name='template_id'>{opts}</select><button>Ajouter boutique</button></form><ul>{srows}</ul></div>"""
        start_response('200 OK',[('Content-Type','text/html')]); return [html('Admin',body,user)]

    if path=='/client':
        if not user or user['role']!='client': return redirect(start_response,'/login')
        con=db(); dogs=con.execute('SELECT * FROM dogs WHERE client_id=?',(user['id'],)).fetchall(); con.close()
        body=f"<div class='card'><h2>Espace client</h2><p>Bienvenue {esc(user['name'])} ({esc(user['email'])})</p><p>Boutique ID: {esc(user['shop_id'])}</p></div>" + ''.join([f"<div class='card'><strong>{esc(d['name'])}</strong> - lavages: {esc(d['washes'])}</div>" for d in dogs])
        start_response('200 OK',[('Content-Type','text/html')]); return [html('Client',body,user)]

    if path=='/dogs':
        if not user or user['role']!='client': return redirect(start_response,'/login')
        con=db()
        if method=='POST':
            d=parse_post(environ)
            if d.get('action')=='create': con.execute('INSERT INTO dogs(client_id,name,breed,weight,washes) VALUES(?,?,?,?,0)',(user['id'],d['name'],d['breed'],d['weight']))
            if d.get('action')=='wash': con.execute('UPDATE dogs SET washes=washes+1 WHERE id=? AND client_id=?',(d['dog_id'],user['id']))
            con.commit()
        dogs=con.execute('SELECT * FROM dogs WHERE client_id=?',(user['id'],)).fetchall(); con.close()
        rows=''.join([f"<div class='card'><h4>{esc(d['name'])} ({esc(d['breed'])}, {esc(d['weight'])}kg)</h4><p>Lavages: {esc(d['washes'])}</p><form method='post'><input type='hidden' name='action' value='wash'><input type='hidden' name='dog_id' value='{esc(d['id'])}'><button>Ajouter lavage (QR logique)</button></form></div>" for d in dogs])
        body="<div class='card'><h2>Mes chiens</h2><form method='post'><input type='hidden' name='action' value='create'><input name='name' required placeholder='Nom'><input name='breed' required placeholder='Race'><input name='weight' type='number' step='0.1' required placeholder='Poids'><button>Ajouter chien</button></form></div>"+rows
        start_response('200 OK',[('Content-Type','text/html')]); return [html('Chiens',body,user)]

    start_response('404 Not Found',[('Content-Type','text/plain')]); return [b'Not Found']

if __name__=='__main__':
    init()
    port=int(os.environ.get('PORT',8000))
    print(f'Server on http://localhost:{port}')
    make_server('0.0.0.0',port,app).serve_forever()
