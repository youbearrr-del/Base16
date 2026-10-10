"""DulzSystemBase16 versioned local API. Keep it behind HTTPS in production."""
from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, sqlite3, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT=Path(__file__).resolve().parent
for line in ((ROOT.parent/'.env').read_text().splitlines() if (ROOT.parent/'.env').exists() else []):
    if '=' in line and not line.lstrip().startswith('#'):
        k,v=line.split('=',1); os.environ.setdefault(k.strip(),v.strip().strip('"').strip("'"))
DATA=ROOT/'data'; DATA.mkdir(exist_ok=True)
DB=Path(os.getenv('DATABASE_PATH',str(DATA/'dulzsystembase16.db')))
HOST=os.getenv('API_HOST','127.0.0.1'); PORT=int(os.getenv('API_PORT','8788')); SECRET=os.getenv('TOKEN_SECRET','')
if not SECRET: raise RuntimeError('TOKEN_SECRET is required')

def now(): return int(time.time())
def conn():
    db=sqlite3.connect(DB); db.row_factory=sqlite3.Row; db.execute('PRAGMA foreign_keys=ON'); return db
def hash_password(value,salt=None):
    salt=salt or secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac('sha256',value.encode(),salt,310000)
    return 'pbkdf2$310000$'+base64.b64encode(salt).decode()+'$'+base64.b64encode(digest).decode()
def matches(value,stored):
    try:
        _,rounds,salt,digest=stored.split('$'); actual=hashlib.pbkdf2_hmac('sha256',value.encode(),base64.b64decode(salt),int(rounds))
        return hmac.compare_digest(actual,base64.b64decode(digest))
    except (ValueError,TypeError): return False
def encode(payload):
    body=base64.urlsafe_b64encode(json.dumps(payload,separators=(',',':')).encode()).rstrip(b'=')
    sign=hmac.new(SECRET.encode(),body,hashlib.sha256).digest()
    return body.decode()+'.'+base64.urlsafe_b64encode(sign).rstrip(b'=').decode()
def decode(token):
    try:
        body,sig=token.split('.'); expected=hmac.new(SECRET.encode(),body.encode(),hashlib.sha256).digest()
        if not hmac.compare_digest(expected,base64.urlsafe_b64decode(sig+'='*(-len(sig)%4))): return None
        payload=json.loads(base64.urlsafe_b64decode(body+'='*(-len(body)%4))); return payload if payload['exp']>now() else None
    except (ValueError,KeyError,json.JSONDecodeError): return None
def public_user(r): return {'id':r['id'],'username':r['username'],'status':r['status'],'role':r['role']}
def event(db,actor,kind,detail,application_id=None):
    db.execute('INSERT INTO activity_logs(id,actor,kind,detail,application_id,created_at) VALUES(?,?,?,?,?,?)',(str(uuid.uuid4()),actor,kind,detail,application_id,now()))
def init_db():
    with conn() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'active',role TEXT NOT NULL DEFAULT 'USER',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS revoked_tokens(token TEXT PRIMARY KEY,expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS applications(id TEXT PRIMARY KEY,name TEXT NOT NULL,slug TEXT UNIQUE NOT NULL,package_name TEXT,platform TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'DEVELOPMENT',current_version TEXT,minimum_version TEXT,secret_hash TEXT NOT NULL,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS devices(id TEXT PRIMARY KEY,application_id TEXT NOT NULL REFERENCES applications(id),device_identifier TEXT NOT NULL,device_name TEXT,manufacturer TEXT,model TEXT,platform TEXT,os_version TEXT,app_version TEXT,status TEXT NOT NULL DEFAULT 'OFFLINE',last_seen INTEGER,last_heartbeat INTEGER,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,UNIQUE(application_id,device_identifier));
        CREATE TABLE IF NOT EXISTS accounts(id TEXT PRIMARY KEY,application_id TEXT NOT NULL REFERENCES applications(id),external_identifier TEXT NOT NULL,display_name TEXT,status TEXT NOT NULL DEFAULT 'ACTIVE',metadata TEXT NOT NULL DEFAULT '{}',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL,last_seen INTEGER,UNIQUE(application_id,external_identifier));
        CREATE TABLE IF NOT EXISTS configurations(id TEXT PRIMARY KEY,application_id TEXT NOT NULL REFERENCES applications(id),version INTEGER NOT NULL,payload TEXT NOT NULL,created_at INTEGER NOT NULL,created_by TEXT NOT NULL,UNIQUE(application_id,version));
        CREATE TABLE IF NOT EXISTS activity_logs(id TEXT PRIMARY KEY,actor TEXT NOT NULL,kind TEXT NOT NULL,detail TEXT NOT NULL,application_id TEXT,created_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS app_releases(id TEXT PRIMARY KEY,application_id TEXT NOT NULL REFERENCES applications(id),version_name TEXT NOT NULL,version_code INTEGER NOT NULL,channel TEXT NOT NULL DEFAULT 'stable',release_notes TEXT,sha256 TEXT NOT NULL,file_size INTEGER,minimum_sdk INTEGER,mandatory INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'DRAFT',created_at INTEGER NOT NULL,published_at INTEGER,UNIQUE(application_id,version_code));
        ''')
        # Non-destructive migration for the initial local schema.
        existing={r['name'] for r in db.execute('PRAGMA table_info(applications)').fetchall()}
        for column,definition in {'description':'TEXT','app_key':'TEXT','status_label':'TEXT'}.items():
            if column not in existing: db.execute(f'ALTER TABLE applications ADD COLUMN {column} {definition}')
        existing={r['name'] for r in db.execute('PRAGMA table_info(devices)').fetchall()}
        for column,definition in {'ip_address':'TEXT','mac_address':'TEXT','session_state':'TEXT','last_ping':'INTEGER'}.items():
            if column not in existing: db.execute(f'ALTER TABLE devices ADD COLUMN {column} {definition}')
        existing={r['name'] for r in db.execute('PRAGMA table_info(users)').fetchall()}
        if 'email' not in existing: db.execute('ALTER TABLE users ADD COLUMN email TEXT')
        existing={r['name'] for r in db.execute('PRAGMA table_info(activity_logs)').fetchall()}
        for column,definition in {'account_id':'INTEGER','ip_address':'TEXT','user_agent':'TEXT'}.items():
            if column not in existing: db.execute(f'ALTER TABLE activity_logs ADD COLUMN {column} {definition}')
        username,password=os.getenv('BOOTSTRAP_ADMIN_USERNAME'),os.getenv('BOOTSTRAP_ADMIN_PASSWORD')
        if username and password and not db.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone():
            db.execute('INSERT INTO users(username,password_hash,status,role,created_at,updated_at) VALUES(?,?,?,?,?,?)',(username,hash_password(password),'active','SUPER_ADMIN',now(),now()))
        if os.getenv('SEED_DEMO_DATA','false').lower()=='true' and not db.execute('SELECT 1 FROM applications LIMIT 1').fetchone(): seed_demo(db)

def seed_demo(db):
    """Development-only data. Never enabled unless SEED_DEMO_DATA=true."""
    stamp=now(); app_rows=[]
    for name,slug,platform,description in [('Operations Mobile','operations-mobile','ANDROID','Field operations client'),('Support Console','support-console','WEB','Customer support integration'),('Warehouse Agent','warehouse-agent','ANDROID','Warehouse scanning agent')]:
        app_id,key=str(uuid.uuid4()),secrets.token_urlsafe(20); app_rows.append((app_id,name,slug,platform,key))
        db.execute('INSERT INTO applications(id,name,slug,package_name,platform,status,current_version,minimum_version,secret_hash,created_at,updated_at,description,app_key,status_label) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(app_id,name,slug,None,platform,'ACTIVE','1.0.0','1.0.0',hash_password(key),stamp,stamp,description,'app_'+secrets.token_hex(8),'active'))
    for ix in range(9):
        app=app_rows[ix%3]; online=ix%3!=0; device_id=str(uuid.uuid4()); beat=stamp-(ix*45)
        db.execute('INSERT INTO devices(id,application_id,device_identifier,device_name,manufacturer,model,platform,os_version,app_version,status,last_seen,last_heartbeat,created_at,updated_at,ip_address,mac_address,session_state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(device_id,app[0],f'DEV-{100+ix}',f'{app[1]} device {ix+1}','Dulz','Agent One',app[3],'14','1.0.0','ONLINE' if online else 'OFFLINE',beat,beat,stamp,stamp,f'10.0.0.{10+ix}',f'02:00:00:00:00:{10+ix:02x}','connected' if online else 'disconnected'))
    for username,role in [('operations-admin','ADMIN'),('auditor','VIEWER')]:
        if not db.execute('SELECT 1 FROM users WHERE username=?',(username,)).fetchone(): db.execute('INSERT INTO users(username,password_hash,status,role,email,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',(username,hash_password('ChangeThisDemoPassword!'),'active',role,f'{username}@example.test',stamp,stamp))
    for app_id,name,_,_,_ in app_rows: event(db,'system','SEED_APPLICATION',f'Demo application created: {name}',app_id)

class API(BaseHTTPRequestHandler):
    server_version='DulzSystemBase16/1.0'
    def log_message(self,fmt,*args): print(self.address_string(),fmt%args)
    def reply(self,status,data,headers=None):
        raw=json.dumps(data).encode(); self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(raw)))
        self.send_header('Access-Control-Allow-Origin',os.getenv('CORS_ORIGIN','http://localhost:4173')); self.send_header('Access-Control-Allow-Credentials','true'); self.send_header('Vary','Origin')
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(raw)
    def body(self):
        try: return json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))))
        except (ValueError,json.JSONDecodeError): return None
    def token(self):
        auth=self.headers.get('Authorization',''); token=auth[7:] if auth.startswith('Bearer ') else ''
        if not token:
            for item in self.headers.get('Cookie','').split(';'):
                k,_,v=item.strip().partition('=')
                if k=='dulz_session': token=v
        return token
    def admin(self,roles=('SUPER_ADMIN','ADMIN','VIEWER')):
        token=self.token(); payload=decode(token)
        if not payload:return None
        with conn() as db:
            if db.execute('SELECT 1 FROM revoked_tokens WHERE token=?',(token,)).fetchone():return None
            user=db.execute('SELECT * FROM users WHERE id=?',(payload['sub'],)).fetchone()
        return user if user and user['status']=='active' and user['role'] in roles else None
    def identity(self):
        """Any active account; used by the end-user installer API only."""
        token=self.token(); payload=decode(token)
        if not payload:return None
        with conn() as db:
            if db.execute('SELECT 1 FROM revoked_tokens WHERE token=?',(token,)).fetchone():return None
            return db.execute("SELECT * FROM users WHERE id=? AND status='active'",(payload['sub'],)).fetchone()
    def app_key(self):
        key=self.headers.get('X-Application-Key','')
        if not key:return None
        with conn() as db:
            for app in db.execute("SELECT * FROM applications WHERE status='ACTIVE'").fetchall():
                if matches(key,app['secret_hash']):return app
        return None
    def require(self,roles=('SUPER_ADMIN','ADMIN','VIEWER')):
        user=self.admin(roles)
        if not user:self.reply(401,{'success':False,'error':'Unauthorized'}); return None
        return user
    def do_OPTIONS(self):
        self.send_response(204); self.send_header('Access-Control-Allow-Origin',os.getenv('CORS_ORIGIN','http://localhost:4173')); self.send_header('Access-Control-Allow-Credentials','true'); self.send_header('Access-Control-Allow-Headers','Content-Type, Authorization, X-Application-Key'); self.send_header('Access-Control-Allow-Methods','GET, POST, PUT, PATCH, DELETE, OPTIONS'); self.end_headers()
    def do_GET(self):
        parsed=urlparse(self.path); route,q=parsed.path,parse_qs(parsed.query)
        if route in ('/api/v1','/api/v1/health'):return self.reply(200,{'success':True,'service':'DulzSystemBase16 API','version':'v1','health':'ok'})
        if route=='/api/v1/client/session':
            u=self.identity()
            return self.reply(200,{'success':True,'user':public_user(u)}) if u else self.reply(401,{'success':False,'error':'Unauthorized'})
        if route=='/api/v1/client/releases':
            u=self.identity()
            if not u:return self.reply(401,{'success':False,'error':'Unauthorized'})
            with conn() as db:
                rows=db.execute("SELECT r.id,r.version_name,r.version_code,r.channel,r.release_notes,r.sha256,r.file_size,r.minimum_sdk,r.mandatory,a.name AS application_name FROM app_releases r JOIN applications a ON a.id=r.application_id WHERE r.status='PUBLISHED' ORDER BY r.published_at DESC").fetchall()
            return self.reply(200,{'success':True,'releases':[dict(x) for x in rows]})
        if route=='/api/v1/auth/me':
            u=self.require(); return self.reply(200,{'success':True,'user':public_user(u)}) if u else None
        u=self.require()
        if not u:return
        with conn() as db:
            if route=='/api/v1/dashboard':
                threshold=now()-int(q.get('heartbeat_seconds',['120'])[0]); apps=db.execute('SELECT COUNT(*) FROM applications').fetchone()[0]; devices=db.execute('SELECT COUNT(*) FROM devices').fetchone()[0]; online=db.execute('SELECT COUNT(*) FROM devices WHERE last_heartbeat>=?',(threshold,)).fetchone()[0]; accounts=db.execute('SELECT COUNT(*) FROM users').fetchone()[0]; active_accounts=db.execute("SELECT COUNT(*) FROM users WHERE status='active'").fetchone()[0]
                logs=[dict(x) for x in db.execute('SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 8').fetchall()]; return self.reply(200,{'success':True,'metrics':{'applications':apps,'devices':devices,'onlineDevices':online,'accounts':accounts,'activeAccounts':active_accounts},'activity':logs})
            if route=='/api/v1/applications':
                page=max(1,int(q.get('page',['1'])[0])); limit=min(100,max(1,int(q.get('limit',['20'])[0]))); where=[]; args=[]
                if q.get('search'): where.append('(name LIKE ? OR slug LIKE ?)'); args.extend(['%'+q['search'][0]+'%']*2)
                if q.get('status'): where.append('status=?'); args.append(q['status'][0].upper())
                clause=(' WHERE '+' AND '.join(where)) if where else ''; total=db.execute('SELECT COUNT(*) FROM applications'+clause,args).fetchone()[0]
                rows=db.execute('SELECT id,name,slug,package_name,platform,status,current_version,minimum_version,description,app_key,created_at,updated_at FROM applications'+clause+' ORDER BY created_at DESC LIMIT ? OFFSET ?',args+[limit,(page-1)*limit]).fetchall()
                return self.reply(200,{'success':True,'applications':[dict(x) for x in rows],'pagination':{'page':page,'limit':limit,'total':total}})
            if route=='/api/v1/devices':
                sql='SELECT d.*,a.name AS application_name FROM devices d JOIN applications a ON a.id=d.application_id'; args=[]
                if q.get('applicationId'):sql+=' WHERE d.application_id=?';args.append(q['applicationId'][0])
                return self.reply(200,{'success':True,'devices':[dict(x) for x in db.execute(sql+' ORDER BY d.updated_at DESC',args).fetchall()]})
            if route=='/api/v1/accounts':
                if u['role']!='SUPER_ADMIN': return self.reply(403,{'success':False,'error':'SUPER_ADMIN permission required'})
                return self.reply(200,{'success':True,'accounts':[dict(x) for x in db.execute('SELECT id,username,email,status,role,created_at,updated_at FROM users ORDER BY created_at DESC').fetchall()]})
            if route=='/api/v1/application-accounts': return self.reply(200,{'success':True,'accounts':[dict(x) for x in db.execute('SELECT a.*,p.name AS application_name FROM accounts a JOIN applications p ON p.id=a.application_id ORDER BY a.created_at DESC').fetchall()]})
            if route=='/api/v1/releases':
                sql='SELECT r.*,a.name AS application_name FROM app_releases r JOIN applications a ON a.id=r.application_id'; args=[]
                if q.get('applicationId'):sql+=' WHERE r.application_id=?';args.append(q['applicationId'][0])
                return self.reply(200,{'success':True,'releases':[dict(x) for x in db.execute(sql+' ORDER BY r.created_at DESC',args).fetchall()]})
            if route=='/api/v1/activity-logs':
                where=[];args=[]
                if q.get('action'):where.append('kind=?');args.append(q['action'][0])
                if q.get('actor'):where.append('actor=?');args.append(q['actor'][0])
                if q.get('from'):where.append('created_at>=?');args.append(int(q['from'][0]))
                if q.get('to'):where.append('created_at<=?');args.append(int(q['to'][0]))
                clause=(' WHERE '+' AND '.join(where)) if where else ''
                return self.reply(200,{'success':True,'logs':[dict(x) for x in db.execute('SELECT * FROM activity_logs'+clause+' ORDER BY created_at DESC LIMIT 100',args).fetchall()]})
            if route.startswith('/api/v1/applications/') and route.endswith('/config'):
                app_id=route.split('/')[4]; row=db.execute('SELECT * FROM configurations WHERE application_id=? ORDER BY version DESC LIMIT 1',(app_id,)).fetchone(); return self.reply(200,{'success':True,'configuration':dict(row) if row else None})
        self.reply(404,{'success':False,'error':'Not found'})
    def do_PUT(self):
        route=urlparse(self.path).path; data=self.body()
        if not isinstance(data,dict):return self.reply(400,{'success':False,'error':'Invalid JSON payload'})
        u=self.require(('SUPER_ADMIN','ADMIN'))
        if not u:return
        parts=route.split('/')
        with conn() as db:
            if len(parts)==5 and parts[:4]==['','api','v1','applications']:
                app_id=parts[4]; fields={'name':'name','description':'description','platform':'platform','packageName':'package_name','status':'status','currentVersion':'current_version','minimumSupportedVersion':'minimum_version'}; set_parts=[]; values=[]
                for source,column in fields.items():
                    if source in data:set_parts.append(column+'=?');values.append(str(data[source]).upper() if source=='status' else data[source])
                if not set_parts:return self.reply(400,{'success':False,'error':'No editable fields supplied'})
                values.extend([now(),app_id]); cursor=db.execute('UPDATE applications SET '+','.join(set_parts)+',updated_at=? WHERE id=?',values)
                if not cursor.rowcount:return self.reply(404,{'success':False,'error':'Application not found'})
                event(db,u['username'],'UPDATE_APP',app_id,app_id);return self.reply(200,{'success':True})
            if len(parts)==5 and parts[:4]==['','api','v1','devices']:
                device_id=parts[4]; fields={'deviceName':'device_name','ipAddress':'ip_address','macAddress':'mac_address','status':'status','osType':'platform'};sets=[];values=[]
                for source,column in fields.items():
                    if source in data:sets.append(column+'=?');values.append(data[source])
                if not sets:return self.reply(400,{'success':False,'error':'No editable fields supplied'})
                values.extend([now(),device_id]);cursor=db.execute('UPDATE devices SET '+','.join(sets)+',updated_at=? WHERE id=?',values)
                if not cursor.rowcount:return self.reply(404,{'success':False,'error':'Device not found'})
                event(db,u['username'],'UPDATE_DEVICE',device_id);return self.reply(200,{'success':True})
            if len(parts)==5 and parts[:4]==['','api','v1','accounts']:
                if u['role']!='SUPER_ADMIN':return self.reply(403,{'success':False,'error':'SUPER_ADMIN permission required'})
                account_id=parts[4]; fields={'email':'email','role':'role','status':'status'};sets=[];values=[]
                for source,column in fields.items():
                    if source in data:sets.append(column+'=?');values.append(data[source])
                if not sets:return self.reply(400,{'success':False,'error':'No editable fields supplied'})
                values.extend([now(),account_id]);cursor=db.execute('UPDATE users SET '+','.join(sets)+',updated_at=? WHERE id=?',values)
                if not cursor.rowcount:return self.reply(404,{'success':False,'error':'Account not found'})
                event(db,u['username'],'UPDATE_ACCOUNT',account_id);return self.reply(200,{'success':True})
        self.reply(404,{'success':False,'error':'Not found'})
    def do_DELETE(self):
        route=urlparse(self.path).path; u=self.require(('SUPER_ADMIN','ADMIN'))
        if not u:return
        parts=route.split('/')
        with conn() as db:
            if len(parts)==5 and parts[:4]==['','api','v1','applications']:
                cursor=db.execute('DELETE FROM applications WHERE id=?',(parts[4],));
                if not cursor.rowcount:return self.reply(404,{'success':False,'error':'Application not found'})
                event(db,u['username'],'DELETE_APP',parts[4]);return self.reply(200,{'success':True})
            if len(parts)==5 and parts[:4]==['','api','v1','devices']:
                cursor=db.execute('DELETE FROM devices WHERE id=?',(parts[4],));
                if not cursor.rowcount:return self.reply(404,{'success':False,'error':'Device not found'})
                event(db,u['username'],'DELETE_DEVICE',parts[4]);return self.reply(200,{'success':True})
            if len(parts)==5 and parts[:4]==['','api','v1','accounts']:
                if u['role']!='SUPER_ADMIN' or str(u['id'])==parts[4]:return self.reply(403,{'success':False,'error':'SUPER_ADMIN may not delete this account'})
                cursor=db.execute('DELETE FROM users WHERE id=?',(parts[4],));
                if not cursor.rowcount:return self.reply(404,{'success':False,'error':'Account not found'})
                event(db,u['username'],'DELETE_ACCOUNT',parts[4]);return self.reply(200,{'success':True})
        self.reply(404,{'success':False,'error':'Not found'})
    def do_POST(self):
        route=urlparse(self.path).path; data=self.body()
        if not isinstance(data,dict):return self.reply(400,{'success':False,'error':'Invalid JSON payload'})
        if route=='/api/v1/auth/login':
            with conn() as db:
                u=db.execute('SELECT * FROM users WHERE username=?',(str(data.get('username','')).strip(),)).fetchone()
                if not u or u['status']!='active' or not matches(str(data.get('password','')),u['password_hash']):return self.reply(401,{'success':False,'error':'Invalid username or password.'})
                event(db,u['username'],'AUTH_LOGIN','Administrator signed in')
            token=encode({'sub':u['id'],'role':u['role'],'exp':now()+3600}); cookie=f'dulz_session={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=3600'
            return self.reply(200,{'success':True,'token':token,'user':public_user(u)},{'Set-Cookie':cookie})
        if route=='/api/v1/auth/logout':
            token=self.token(); payload=decode(token)
            if payload:
                with conn() as db: db.execute('INSERT OR REPLACE INTO revoked_tokens VALUES(?,?)',(token,payload['exp']))
            return self.reply(200,{'success':True},{'Set-Cookie':'dulz_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0'})
        if route=='/api/v1/devices/register':
            app=self.app_key()
            if not app:return self.reply(401,{'success':False,'error':'Invalid application credential'})
            ident=str(data.get('deviceIdentifier','')).strip()
            if not ident:return self.reply(400,{'success':False,'error':'deviceIdentifier is required'})
            stamp=now(); dev_id=str(uuid.uuid4())
            with conn() as db:
                row=db.execute('SELECT id FROM devices WHERE application_id=? AND device_identifier=?',(app['id'],ident)).fetchone(); dev_id=row['id'] if row else dev_id
                db.execute('INSERT INTO devices(id,application_id,device_identifier,device_name,manufacturer,model,platform,os_version,app_version,status,last_seen,last_heartbeat,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(application_id,device_identifier) DO UPDATE SET device_name=excluded.device_name,manufacturer=excluded.manufacturer,model=excluded.model,platform=excluded.platform,os_version=excluded.os_version,app_version=excluded.app_version,status="ONLINE",last_seen=excluded.last_seen,last_heartbeat=excluded.last_heartbeat,updated_at=excluded.updated_at',(dev_id,app['id'],ident,data.get('deviceName'),data.get('manufacturer'),data.get('model'),data.get('platform'),data.get('osVersion'),data.get('appVersion'),'ONLINE',stamp,stamp,stamp,stamp)); event(db,'device:'+ident,'DEVICE_REGISTERED','Device registered',app['id'])
            return self.reply(200,{'success':True,'device':{'id':dev_id,'applicationId':app['id']}})
        if route=='/api/v1/devices/heartbeat':
            app=self.app_key(); ident=str(data.get('deviceIdentifier','')).strip()
            if not app or not ident:return self.reply(401,{'success':False,'error':'Invalid device authentication'})
            with conn() as db:
                cursor=db.execute('UPDATE devices SET status="ONLINE",last_seen=?,last_heartbeat=?,app_version=COALESCE(?,app_version),updated_at=? WHERE application_id=? AND device_identifier=?',(now(),now(),data.get('appVersion'),now(),app['id'],ident))
            return self.reply(200,{'success':True}) if cursor.rowcount else self.reply(404,{'success':False,'error':'Device not registered'})
        if route=='/api/v1/devices/ping':
            app=self.app_key(); ident=str(data.get('deviceIdentifier','')).strip()
            if not app or not ident:return self.reply(401,{'success':False,'error':'Invalid device authentication'})
            with conn() as db: cursor=db.execute('UPDATE devices SET status="ONLINE",last_ping=?,last_seen=?,last_heartbeat=?,updated_at=? WHERE application_id=? AND device_identifier=?',(now(),now(),now(),now(),app['id'],ident)) if 'last_ping' in {r['name'] for r in db.execute('PRAGMA table_info(devices)')} else db.execute('UPDATE devices SET status="ONLINE",last_seen=?,last_heartbeat=?,updated_at=? WHERE application_id=? AND device_identifier=?',(now(),now(),now(),app['id'],ident))
            return self.reply(200,{'success':True}) if cursor.rowcount else self.reply(404,{'success':False,'error':'Device not registered'})
        u=self.require(('SUPER_ADMIN','ADMIN'))
        if not u:return
        stamp=now()
        if route=='/api/v1/applications':
            name,slug=str(data.get('name','')).strip(),str(data.get('slug','')).strip().lower()
            if not name or not slug:return self.reply(400,{'success':False,'error':'name and slug are required'})
            app_id,secret=str(uuid.uuid4()),secrets.token_urlsafe(32)
            try:
                app_key='app_'+secrets.token_hex(12)
                with conn() as db: db.execute('INSERT INTO applications(id,name,slug,package_name,platform,status,current_version,minimum_version,secret_hash,created_at,updated_at,description,app_key,status_label) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(app_id,name,slug,data.get('packageName'),data.get('platform','ANDROID'),data.get('status','DEVELOPMENT').upper(),data.get('currentVersion'),data.get('minimumSupportedVersion'),hash_password(secret),stamp,stamp,data.get('description'),app_key,'active'));event(db,u['username'],'CREATE_APP',name,app_id)
                return self.reply(201,{'success':True,'application':{'id':app_id,'name':name,'slug':slug,'appKey':app_key,'clientSecret':secret}})
            except sqlite3.IntegrityError:return self.reply(409,{'success':False,'error':'Application slug already exists'})
        if route.startswith('/api/v1/applications/') and route.endswith('/regenerate-secret'):
            app_id=route.split('/')[4]; secret=secrets.token_urlsafe(32)
            with conn() as db:
                cursor=db.execute('UPDATE applications SET secret_hash=?,updated_at=? WHERE id=?',(hash_password(secret),stamp,app_id))
                if not cursor.rowcount:return self.reply(404,{'success':False,'error':'Application not found'})
                event(db,u['username'],'REGENERATE_APP_SECRET',app_id,app_id)
            return self.reply(200,{'success':True,'clientSecret':secret})
        if route.startswith('/api/v1/applications/') and route.endswith('/toggle-status'):
            app_id=route.split('/')[4]
            with conn() as db:
                app=db.execute('SELECT status FROM applications WHERE id=?',(app_id,)).fetchone()
                if not app:return self.reply(404,{'success':False,'error':'Application not found'})
                status='INACTIVE' if app['status']=='ACTIVE' else 'ACTIVE';db.execute('UPDATE applications SET status=?,updated_at=? WHERE id=?',(status,stamp,app_id));event(db,u['username'],'TOGGLE_APP_STATUS',status,app_id)
            return self.reply(200,{'success':True,'status':status})
        if route.startswith('/api/v1/devices/') and route.endswith('/force-disconnect'):
            device_id=route.split('/')[4]
            with conn() as db: cursor=db.execute('UPDATE devices SET status="OFFLINE",session_state="force_disconnected",updated_at=? WHERE id=?',(stamp,device_id));event(db,u['username'],'FORCE_DISCONNECT',device_id)
            return self.reply(200,{'success':True}) if cursor.rowcount else self.reply(404,{'success':False,'error':'Device not found'})
        if route.startswith('/api/v1/devices/') and route.endswith('/restart-session'):
            device_id=route.split('/')[4]
            with conn() as db: cursor=db.execute('UPDATE devices SET session_state="restart_requested",updated_at=? WHERE id=?',(stamp,device_id));event(db,u['username'],'RESTART_SESSION',device_id)
            return self.reply(200,{'success':True}) if cursor.rowcount else self.reply(404,{'success':False,'error':'Device not found'})
        if route.startswith('/api/v1/accounts/') and route.endswith('/reset-password'):
            if u['role']!='SUPER_ADMIN':return self.reply(403,{'success':False,'error':'SUPER_ADMIN permission required'})
            account_id=route.split('/')[4];password=str(data.get('password',''))
            if len(password)<12:return self.reply(400,{'success':False,'error':'A 12-character password is required'})
            with conn() as db: cursor=db.execute('UPDATE users SET password_hash=?,updated_at=? WHERE id=?',(hash_password(password),stamp,account_id));event(db,u['username'],'RESET_PASSWORD',account_id)
            return self.reply(200,{'success':True}) if cursor.rowcount else self.reply(404,{'success':False,'error':'Account not found'})
        if route=='/api/v1/accounts':
            if u['role']!='SUPER_ADMIN': return self.reply(403,{'success':False,'error':'SUPER_ADMIN permission required'})
            username,password=str(data.get('username','')).strip(),str(data.get('password',''))
            if not username or len(password)<12:return self.reply(400,{'success':False,'error':'username and 12-character password are required'})
            try:
                with conn() as db: cursor=db.execute('INSERT INTO users(username,email,password_hash,status,role,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',(username,data.get('email'),hash_password(password),data.get('status','active'),data.get('role','USER'),stamp,stamp));event(db,u['username'],'CREATE_ACCOUNT',username)
                return self.reply(201,{'success':True,'account':{'id':cursor.lastrowid,'username':username}})
            except sqlite3.IntegrityError:return self.reply(409,{'success':False,'error':'Username already exists'})
        if route=='/api/v1/application-accounts':
            app_id,external=str(data.get('applicationId','')),str(data.get('externalIdentifier','')).strip()
            if not app_id or not external:return self.reply(400,{'success':False,'error':'applicationId and externalIdentifier are required'})
            account_id=str(uuid.uuid4())
            try:
                with conn() as db: db.execute('INSERT INTO accounts VALUES(?,?,?,?,?,?,?,?,?)',(account_id,app_id,external,data.get('displayName'),data.get('status','ACTIVE'),json.dumps(data.get('metadata',{})),stamp,stamp,None));event(db,u['username'],'ACCOUNT_CREATED',external,app_id)
                return self.reply(201,{'success':True,'account':{'id':account_id,'externalIdentifier':external}})
            except sqlite3.IntegrityError:return self.reply(409,{'success':False,'error':'Account already exists for this application'})
        if route=='/api/v1/releases':
            application_id=str(data.get('applicationId','')); version_name=str(data.get('versionName','')).strip(); sha256=str(data.get('sha256','')).lower()
            try: version_code=int(data.get('versionCode'))
            except (ValueError,TypeError): return self.reply(400,{'success':False,'error':'versionCode must be an integer'})
            if not application_id or not version_name or len(sha256)!=64 or any(c not in '0123456789abcdef' for c in sha256):return self.reply(400,{'success':False,'error':'applicationId, versionName, and a SHA-256 checksum are required'})
            release_id=str(uuid.uuid4()); status=str(data.get('status','DRAFT')).upper()
            try:
                with conn() as db: db.execute('INSERT INTO app_releases VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(release_id,application_id,version_name,version_code,data.get('channel','stable'),data.get('releaseNotes'),sha256,data.get('fileSize'),data.get('minimumSdk'),1 if data.get('mandatory') else 0,status,stamp,stamp if status=='PUBLISHED' else None));event(db,u['username'],'CREATE_RELEASE',version_name,application_id)
                return self.reply(201,{'success':True,'release':{'id':release_id,'versionName':version_name}})
            except sqlite3.IntegrityError:return self.reply(409,{'success':False,'error':'Release versionCode already exists for this application'})
        if route.startswith('/api/v1/applications/') and route.endswith('/config'):
            app_id=route.split('/')[4]; payload=data.get('configuration')
            if not isinstance(payload,dict):return self.reply(400,{'success':False,'error':'configuration must be an object'})
            with conn() as db:
                version=db.execute('SELECT COALESCE(MAX(version),0)+1 FROM configurations WHERE application_id=?',(app_id,)).fetchone()[0]; cid=str(uuid.uuid4()); db.execute('INSERT INTO configurations VALUES(?,?,?,?,?,?)',(cid,app_id,version,json.dumps(payload),stamp,u['username']));event(db,u['username'],'CONFIGURATION_UPDATED',f'Configuration version {version}',app_id)
            return self.reply(201,{'success':True,'configuration':{'id':cid,'version':version}})
        self.reply(404,{'success':False,'error':'Not found'})

if __name__=='__main__':
    init_db(); print(f'DulzSystemBase16 API listening on http://{HOST}:{PORT}'); ThreadingHTTPServer((HOST,PORT),API).serve_forever()
