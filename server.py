import os, sqlite3, hashlib, hmac, secrets, shutil
from urllib.parse import parse_qs
from wsgiref.simple_server import make_server

DB='washdog.db'
UPLOAD_DIR='uploads'
SECRET='change-me-secret'
os.makedirs(UPLOAD_DIR, exist_ok=True)

CSS='''body{font-family:Arial,sans-serif;margin:0;background:#f5f7fb}header{background:#0f6fff;color:#fff;padding:1rem}main{max-width:1100px;margin:auto;padding:1rem}.card{background:#fff;padding:1rem;border-radius:10px;margin:1rem 0;border:1px solid #d9e1ef}a{color:#0f6fff}.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}input,select,button,textarea{padding:.5rem;margin:.2rem 0;width:100%}.nav a{margin-right:1rem}.tab{display:inline-block;padding:.4rem .7rem;background:#e9f0ff;border-radius:7px;margin-right:.4rem}small{color:#4a5a78}img{max-width:220px;border-radius:8px}label{font-weight:700}''' 

def db():
    con=sqlite3.connect(DB); con.row_factory=sqlite3.Row; return con

def init():
    con=db();c=con.cursor()
    c.executescript('''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT,email TEXT UNIQUE,password TEXT,role TEXT,shop_id INTEGER);
CREATE TABLE IF NOT EXISTS templates(id INTEGER PRIMARY KEY,name TEXT,description TEXT);
CREATE TABLE IF NOT EXISTS shops(id INTEGER PRIMARY KEY,name TEXT,address TEXT,phone TEXT,hours TEXT,services TEXT,lat REAL,lng REAL,template_id INTEGER,photo_path TEXT);
CREATE TABLE IF NOT EXISTS dogs(id INTEGER PRIMARY KEY,client_id INTEGER,name TEXT,breed TEXT,weight REAL,washes INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user_id INTEGER);
''')
    admin = c.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
    if not admin:
        c.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",('Admin','admin@washdog.local',hash_pw('admin123'),'admin'))
    con.commit(); con.close()

def hash_pw(p): return hashlib.sha256(p.encode()).hexdigest()
def sign(v): return hmac.new(SECRET.encode(),v.encode(),hashlib.sha256).hexdigest()

def cookie_token(environ):
    for part in environ.get('HTTP_COOKIE','').split(';'):
        part=part.strip()
        if part.startswith('sid='): return part[4:]
    return None

def current_user(environ):
    sid=cookie_token(environ)
    if not sid or '.' not in sid: return None
    token,sig=sid.split('.',1)
    if sign(token)!=sig: return None
    con=db(); row=con.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?',(token,)).fetchone(); con.close(); return row

def parse_post(environ):
    size=int(environ.get('CONTENT_LENGTH') or 0)
    body=environ['wsgi.input'].read(size)
    q=parse_qs(body.decode(errors='ignore'))
    return {k:v[0] for k,v in q.items()}

def html(title,body,user=None):
    nav='<div class="nav"><a href="/">Accueil</a><a href="/shops">Vitrines</a>'
    if user and user['role']=='admin': nav+='<a href="/admin">Admin</a>'
    if user and user['role']=='client': nav+='<a href="/client">Client</a><a href="/dogs">Chiens</a>'
    nav += '<a href="/logout">Déconnexion</a>' if user else '<a href="/login">Connexion</a><a href="/register">Inscription</a>'
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title><style>{CSS}</style></head><body><header><h1>WashDog Pro</h1>{nav}</header><main>{body}</main></body></html>".encode()

def redirect(start_response,to,cookie=None):
    h=[('Location',to)]
    if cookie: h.append(('Set-Cookie',cookie))
    start_response('302 Found',h); return [b'']

def save_shop_photo(environ):
    # minimal multipart parser for single file field shop_photo
    ct=environ.get('CONTENT_TYPE','')
    if 'multipart/form-data' not in ct: return {}, None
    boundary=ct.split('boundary=')[-1].encode()
    size=int(environ.get('CONTENT_LENGTH') or 0)
    raw=environ['wsgi.input'].read(size)
    fields={}; photo_path=None
    for part in raw.split(b'--'+boundary):
        if b'Content-Disposition' not in part: continue
        head,_,data=part.partition(b'\r\n\r\n')
        dispo=head.decode(errors='ignore')
        if 'name="' not in dispo: continue
        name=dispo.split('name="')[1].split('"')[0]
        val=data.rsplit(b'\r\n',1)[0]
        if 'filename="' in dispo and name=='shop_photo' and val:
            filename=dispo.split('filename="')[1].split('"')[0] or 'shop.jpg'
            safe=secrets.token_hex(6)+'_'+os.path.basename(filename)
            path=os.path.join(UPLOAD_DIR,safe)
            with open(path,'wb') as f: f.write(val)
            photo_path=path
        elif 'filename="' not in dispo:
            fields[name]=val.decode(errors='ignore')
    return fields, photo_path

def app(environ,start_response):
    path=environ['PATH_INFO']; method=environ['REQUEST_METHOD']; user=current_user(environ)
    if path.startswith('/uploads/'):
        fp=path.lstrip('/')
        if not os.path.isfile(fp): start_response('404 Not Found',[('Content-Type','text/plain')]); return [b'Not found']
        start_response('200 OK',[('Content-Type','application/octet-stream')]); return [open(fp,'rb').read()]
    if path=='/':
        start_response('200 OK',[('Content-Type','text/html')]); return [html('Accueil','<div class="card"><h2>Site dynamique sécurisé</h2></div>',user)]
    if path=='/shops':
        con=db(); rows=con.execute('SELECT * FROM shops').fetchall(); con.close()
        cards=''.join([f"<div class='card'><h3>{r['name']}</h3><p>{r['address']}<br>{r['phone']}<br>{r['hours']}<br>{r['services']}</p>{('<img src=/' + r['photo_path'] + '>') if r['photo_path'] else ''}</div>" for r in rows]) or '<div class="card">Aucune boutique.</div>'
        start_response('200 OK',[('Content-Type','text/html')]); return [html('Vitrines',cards,user)]
    if path=='/register':
        if method=='GET':
            con=db(); shops=con.execute('SELECT id,name FROM shops').fetchall(); con.close()
            opts=''.join([f"<option value='{s['id']}'>{s['id']} - {s['name']}</option>" for s in shops])
            b=f"<div class='card'><h2>Inscription client</h2><form method='post'><label>name</label><input name='name' required><label>email</label><input name='email' type='email' required><label>password</label><input name='password' type='password' required><label>shop_id</label><select name='shop_id'>{opts}</select><button>Créer</button></form></div>"
            start_response('200 OK',[('Content-Type','text/html')]); return [html('Register',b,user)]
        d=parse_post(environ); con=db();
        con.execute('INSERT INTO users(name,email,password,role,shop_id) VALUES(?,?,?,?,?)',(d.get('name',''),d.get('email',''),hash_pw(d.get('password','')),'client',d.get('shop_id') or None)); con.commit(); con.close(); return redirect(start_response,'/login')
    if path=='/login':
        if method=='GET':
            b="<div class='card'><h2>Connexion</h2><form method='post'><label>email</label><input name='email'><label>password</label><input name='password' type='password'><button>Se connecter</button></form></div>"
            start_response('200 OK',[('Content-Type','text/html')]); return [html('Login',b,user)]
        d=parse_post(environ); con=db(); u=con.execute('SELECT * FROM users WHERE email=? AND password=?',(d.get('email',''),hash_pw(d.get('password','')))).fetchone(); con.close()
        if not u: return redirect(start_response,'/login')
        tok=secrets.token_hex(16); con=db(); con.execute('INSERT INTO sessions(token,user_id) VALUES(?,?)',(tok,u['id'])); con.commit(); con.close()
        return redirect(start_response,'/admin' if u['role']=='admin' else '/client',f"sid={tok}.{sign(tok)}; Path=/; HttpOnly")
    if path=='/logout':
        sid=cookie_token(environ)
        if sid and '.' in sid:
            con=db(); con.execute('DELETE FROM sessions WHERE token=?',(sid.split('.')[0],)); con.commit(); con.close()
        return redirect(start_response,'/','sid=;Path=/;Max-Age=0')

    if path=='/admin':
        if not user or user['role']!='admin': return redirect(start_response,'/login')
        con=db()
        if method=='POST':
            action=environ.get('QUERY_STRING','')
            if 'multipart/form-data' in environ.get('CONTENT_TYPE',''):
                d,photo=save_shop_photo(environ)
            else:
                d=parse_post(environ); photo=None
            t=d.get('type','')
            if t=='admin_password':
                con.execute('UPDATE users SET password=? WHERE id=?',(hash_pw(d.get('new_password','')),user['id']))
            elif t=='client_create':
                con.execute('INSERT INTO users(name,email,password,role,shop_id) VALUES(?,?,?,?,?)',(d['name'],d['email'],hash_pw(d['password']),'client',d.get('shop_id') or None))
            elif t=='client_update':
                con.execute('UPDATE users SET name=?,email=?,shop_id=? WHERE id=? AND role="client"',(d['name'],d['email'],d.get('shop_id') or None,d['id']))
            elif t=='template_create':
                con.execute('INSERT INTO templates(name,description) VALUES(?,?)',(d['name'],d['description']))
            elif t=='template_update':
                con.execute('UPDATE templates SET name=?,description=? WHERE id=?',(d['name'],d['description'],d['id']))
            elif t=='shop_create':
                con.execute('INSERT INTO shops(name,address,phone,hours,services,lat,lng,template_id,photo_path) VALUES(?,?,?,?,?,?,?,?,?)',(d['name'],d['address'],d['phone'],d['hours'],d['services'],d['lat'],d['lng'],d.get('template_id') or None,photo))
            elif t=='shop_update':
                if photo:
                    con.execute('UPDATE shops SET name=?,address=?,phone=?,hours=?,services=?,lat=?,lng=?,template_id=?,photo_path=? WHERE id=?',(d['name'],d['address'],d['phone'],d['hours'],d['services'],d['lat'],d['lng'],d.get('template_id') or None,photo,d['id']))
                else:
                    con.execute('UPDATE shops SET name=?,address=?,phone=?,hours=?,services=?,lat=?,lng=?,template_id=? WHERE id=?',(d['name'],d['address'],d['phone'],d['hours'],d['services'],d['lat'],d['lng'],d.get('template_id') or None,d['id']))
            elif t=='db_export':
                start_response('200 OK',[('Content-Type','application/octet-stream'),('Content-Disposition','attachment; filename="washdog.db"')]); con.close(); return [open(DB,'rb').read()]
            elif t=='db_backup':
                bak=f"washdog_backup_{secrets.token_hex(4)}.db"; shutil.copyfile(DB,bak)
            con.commit()
        tpls=con.execute('SELECT * FROM templates').fetchall(); shops=con.execute('SELECT * FROM shops').fetchall(); clients=con.execute("SELECT * FROM users WHERE role='client'").fetchall(); con.close()
        tpl_opts=''.join([f"<option value='{t['id']}'>{t['id']} - {t['name']}</option>" for t in tpls])
        shop_opts=''.join([f"<option value='{s['id']}'>{s['id']} - {s['name']}</option>" for s in shops])
        c_rows=''.join([f"<li>ID={c['id']} | name={c['name']} | email={c['email']} | shop_id={c['shop_id']}</li>" for c in clients])
        s_rows=''.join([f"<li>ID={s['id']} | name={s['name']} | address={s['address']}</li>" for s in shops])
        t_rows=''.join([f"<li>ID={t['id']} | name={t['name']} | description={t['description']}</li>" for t in tpls])
        body=f"""
<div class='card'>
  <span class='tab'>Templates</span><span class='tab'>Boutiques</span><span class='tab'>Clients</span><span class='tab'>Base de données</span><span class='tab'>Sécurité</span>
</div>
<div class='card'><h3>Changer mot de passe admin</h3><form method='post'><input type='hidden' name='type' value='admin_password'><label>new_password</label><input name='new_password' type='password' required><button>Mettre à jour</button></form></div>
<div class='card'><h3>Créer template</h3><form method='post'><input type='hidden' name='type' value='template_create'><label>name</label><input name='name' required><label>description</label><textarea name='description' required></textarea><button>Créer template</button></form><ul>{t_rows}</ul></div>
<div class='card'><h3>Modifier template</h3><form method='post'><input type='hidden' name='type' value='template_update'><label>id</label><input name='id' required><label>name</label><input name='name' required><label>description</label><textarea name='description' required></textarea><button>Modifier template</button></form></div>
<div class='card'><h3>Créer boutique</h3><form method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='shop_create'><label>name</label><input name='name' required><label>address</label><input name='address' required><label>phone</label><input name='phone' required><label>hours</label><input name='hours' required><label>services</label><input name='services' required><label>lat</label><input name='lat' type='number' step='any' required><label>lng</label><input name='lng' type='number' step='any' required><label>template_id</label><select name='template_id'>{tpl_opts}</select><label>shop_photo</label><input type='file' name='shop_photo' accept='image/*'><button>Créer boutique</button></form><ul>{s_rows}</ul></div>
<div class='card'><h3>Modifier boutique</h3><form method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='shop_update'><label>id</label><select name='id'>{shop_opts}</select><label>name</label><input name='name' required><label>address</label><input name='address' required><label>phone</label><input name='phone' required><label>hours</label><input name='hours' required><label>services</label><input name='services' required><label>lat</label><input name='lat' type='number' step='any' required><label>lng</label><input name='lng' type='number' step='any' required><label>template_id</label><select name='template_id'>{tpl_opts}</select><label>shop_photo</label><input type='file' name='shop_photo' accept='image/*'><button>Modifier boutique</button></form></div>
<div class='card'><h3>Créer client</h3><form method='post'><input type='hidden' name='type' value='client_create'><label>name</label><input name='name' required><label>email</label><input name='email' type='email' required><label>password</label><input name='password' required><label>shop_id</label><select name='shop_id'>{shop_opts}</select><button>Créer client</button></form><ul>{c_rows}</ul></div>
<div class='card'><h3>Modifier client</h3><form method='post'><input type='hidden' name='type' value='client_update'><label>id</label><input name='id' required><label>name</label><input name='name' required><label>email</label><input name='email' type='email' required><label>shop_id</label><select name='shop_id'>{shop_opts}</select><button>Modifier client</button></form></div>
<div class='card'><h3>Base de données</h3><form method='post'><input type='hidden' name='type' value='db_backup'><button>Sauvegarde base de données</button></form><form method='post'><input type='hidden' name='type' value='db_export'><button>Export base de données</button></form><form method='post' enctype='multipart/form-data'><input type='hidden' name='type' value='db_import'><label>database_file</label><input type='file' name='database_file' accept='.db'><button>Import base de données</button></form><small>Import: remplacez le fichier washdog.db manuellement après upload (sécurité minimaliste).</small></div>
"""
        start_response('200 OK',[('Content-Type','text/html')]); return [html('Admin',body,user)]

    if path=='/client':
        if not user or user['role']!='client': return redirect(start_response,'/login')
        con=db(); dogs=con.execute('SELECT * FROM dogs WHERE client_id=?',(user['id'],)).fetchall(); con.close()
        b=f"<div class='card'><h2>Espace client</h2><p>ID={user['id']} name={user['name']} email={user['email']} shop_id={user['shop_id']}</p></div>"+''.join([f"<div class='card'>{d['name']} | washes={d['washes']}</div>" for d in dogs])
        start_response('200 OK',[('Content-Type','text/html')]); return [html('Client',b,user)]
    if path=='/dogs':
        if not user or user['role']!='client': return redirect(start_response,'/login')
        con=db()
        if method=='POST':
            d=parse_post(environ)
            if d.get('action')=='create': con.execute('INSERT INTO dogs(client_id,name,breed,weight,washes) VALUES(?,?,?,?,0)',(user['id'],d['name'],d['breed'],d['weight']))
            if d.get('action')=='wash': con.execute('UPDATE dogs SET washes=washes+1 WHERE id=? AND client_id=?',(d['dog_id'],user['id']))
            con.commit()
        dogs=con.execute('SELECT * FROM dogs WHERE client_id=?',(user['id'],)).fetchall(); con.close()
        rows=''.join([f"<div class='card'><h4>ID={d['id']} name={d['name']}</h4><p>breed={d['breed']} weight={d['weight']} washes={d['washes']}</p><form method='post'><input type='hidden' name='action' value='wash'><input type='hidden' name='dog_id' value='{d['id']}'><button>Ajouter lavage</button></form></div>" for d in dogs])
        b="<div class='card'><h2>Mes chiens</h2><form method='post'><input type='hidden' name='action' value='create'><label>name</label><input name='name'><label>breed</label><input name='breed'><label>weight</label><input type='number' step='0.1' name='weight'><button>Ajouter</button></form></div>"+rows
        start_response('200 OK',[('Content-Type','text/html')]); return [html('Chiens',b,user)]
    start_response('404 Not Found',[('Content-Type','text/plain')]); return [b'Not Found']

if __name__=='__main__':
    init(); port=int(os.environ.get('PORT',8000)); print(f'Server on http://localhost:{port}'); make_server('0.0.0.0',port,app).serve_forever()
