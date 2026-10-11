import json, os, time, secrets, hashlib, base64, shutil
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

BASE = os.path.dirname(os.path.abspath(__file__))
# Data lives outside the project folder so editors (e.g. Live Server) don't auto-reload on every save
DB = os.path.join(os.environ.get('DATA_DIR') or os.path.expanduser('~/.parley'), 'parley.json')
try:
    os.makedirs(os.path.dirname(DB), exist_ok=True)
except PermissionError:
    print('WARNING: cannot write to', os.path.dirname(DB), '- is the disk attached? Using temporary storage, data will be lost on restart.')
    DB = '/tmp/parley.json'
if not os.path.exists(DB) and os.path.exists(os.path.join(BASE, 'parley.json')):
    shutil.move(os.path.join(BASE, 'parley.json'), DB)
D = {'users': {}, 'groups': {}, 'msgs': {}, 'posts': []}
if os.path.exists(DB):
    D.update(json.load(open(DB)))

def save():
    json.dump(D, open(DB, 'w'))

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

class Auth(BaseModel):
    username: str
    password: str

def h(p, s):
    return hashlib.sha256((s + p).encode()).hexdigest()

@app.post('/register')
def register(a: Auth):
    u = a.username.strip()
    if not 3 <= len(u) <= 20 or not u.replace('_', '').isalnum():
        raise HTTPException(400, 'Username: 3-20 letters, numbers or underscores')
    if len(a.password) < 6:
        raise HTTPException(400, 'Password needs at least 6 characters')
    if u.lower() in {k.lower() for k in D['users']}:
        raise HTTPException(400, 'That username is taken')
    s = secrets.token_hex(8)
    D['users'][u] = {'salt': s, 'pw': h(a.password, s), 'bio': '', 'games': [], 'tok': '', 'friends': [], 'reqs': [], 'av': '', 'bn': ''}
    save()
    return {'ok': 1}

@app.post('/login')
def login(a: Auth):
    u = D['users'].get(a.username.strip())
    if not u or u['pw'] != h(a.password, u['salt']):
        raise HTTPException(401, 'Wrong username or password')
    u['tok'] = secrets.token_hex(16)
    save()
    return {'token': u['tok']}

conns, calls = {}, {}

def room_users(r):
    if r.startswith('dm:'):
        return r[3:].split('|')
    g = D['groups'].get(r)
    return g['members'] if g else []

def can(u, r):
    p = room_users(r)
    return u in p and all(x in D['users'] for x in p)

async def to(u, m):
    w = conns.get(u)
    if w:
        try:
            await w.send_text(json.dumps(m))
        except Exception:
            pass

def view(u):
    gs = [dict(g, id=i) for i, g in D['groups'].items() if g['public'] or u in g['members']]
    us = [{'n': n, 'bio': x['bio'], 'games': x['games'], 'on': n in conns, 'v': x.get('ver', 0),
           'av': bool(x.get('av')), 'bn': bool(x.get('bn')), 'fr': x.get('friends', [])} for n, x in D['users'].items()]
    out = [n for n, x in D['users'].items() if u in x.get('reqs', [])]
    return {'e': 'state', 'groups': gs, 'users': us, 'reqs': D['users'][u].get('reqs', []), 'out': out}

async def push():
    for u in list(conns):
        await to(u, view(u))

async def leave_call(u, r):
    s = calls.get(r)
    if s and u in s:
        s.discard(u)
        for p in s:
            await to(p, {'e': 'cleft', 'from': u})
        if not s:
            calls.pop(r, None)

async def handle(u, m):
    a, G = m.get('a'), D['groups']
    if a == 'hist':
        r = m.get('room', '')
        if can(u, r):
            await to(u, {'e': 'hist', 'room': r, 'm': D['msgs'].get(r, [])})
    elif a == 'msg':
        r, k, d = m.get('room', ''), m.get('k'), str(m.get('d', ''))
        if not can(u, r) or k not in ('text', 'img', 'voice') or len(d) > 4_000_000 or not d:
            return
        if k == 'text':
            d = d[:2000]
        g = {'id': secrets.token_hex(4), 'from': u, 't': int(time.time() * 1000), 'k': k, 'd': d}
        L = D['msgs'].setdefault(r, [])
        L.append(g)
        del L[:-150]
        save()
        for v in room_users(r):
            await to(v, {'e': 'msg', 'room': r, 'm': g})
    elif a == 'gnew':
        n = str(m.get('name', '')).strip()[:30]
        if n:
            G[secrets.token_hex(3)] = {'name': n, 'desc': str(m.get('desc', ''))[:120], 'public': bool(m.get('public')),
                                       'owner': u, 'admins': [u], 'members': [u]}
            save()
            await push()
    elif a == 'gjoin':
        g = G.get(m.get('id'))
        if g and g['public'] and u not in g['members']:
            g['members'].append(u)
            save()
            await push()
    elif a == 'gleave':
        g = G.get(m.get('id'))
        if g and u in g['members']:
            g['members'].remove(u)
            if u in g['admins']:
                g['admins'].remove(u)
            if not g['members']:
                del G[m['id']]
            elif u == g['owner']:
                g['owner'] = (g['admins'] or g['members'])[0]
                if g['owner'] not in g['admins']:
                    g['admins'].append(g['owner'])
            save()
            await push()
    elif a == 'gmod':
        g, t, op = G.get(m.get('id')), m.get('user'), m.get('op')
        if not g or u not in g['admins'] or t not in D['users']:
            return
        own = u == g['owner']
        if op == 'add' and t not in g['members']:
            g['members'].append(t)
        elif op == 'kick' and t in g['members'] and t != g['owner'] and (own or t not in g['admins']):
            g['members'].remove(t)
            if t in g['admins']:
                g['admins'].remove(t)
        elif op == 'admin' and own and t in g['members'] and t != u:
            if t in g['admins']:
                g['admins'].remove(t)
            else:
                g['admins'].append(t)
        save()
        await push()
    elif a == 'prof':
        x = D['users'][u]
        x['bio'] = str(m.get('bio', ''))[:200]
        x['games'] = [str(s)[:24] for s in m.get('games', [])][:10]
        for k in ('av', 'bn'):
            v = str(m.get(k, ''))
            if v.startswith('data:image/') and len(v) < 1_500_000:
                x[k] = v
                x['ver'] = int(time.time())
        save()
        await push()
    elif a == 'post':
        txt, img = str(m.get('txt', ''))[:280], str(m.get('img', ''))
        if (txt.strip() or img) and len(img) < 4_000_000:
            p = {'id': secrets.token_hex(4), 'by': u, 't': int(time.time() * 1000), 'txt': txt, 'img': img, 'likes': [], 'cm': []}
            D['posts'].insert(0, p)
            del D['posts'][100:]
            save()
            for v in list(conns):
                await to(v, {'e': 'post', 'p': p})
    elif a in ('like', 'cmt'):
        p = next((x for x in D['posts'] if x['id'] == m.get('id')), None)
        if not p:
            return
        if a == 'like' and u not in p['likes']:
            p['likes'].append(u)
        elif a == 'cmt' and str(m.get('txt', '')).strip():
            p['cm'].append({'by': u, 't': int(time.time() * 1000), 'txt': str(m['txt'])[:300]})
        else:
            return
        save()
        for v in list(conns):
            await to(v, {'e': 'pupd', 'p': p})
    elif a in ('freq', 'facc', 'fdec', 'funf'):
        t = m.get('user')
        X, Me = D['users'].get(t), D['users'][u]
        if not X or t == u:
            return
        mf, tf = Me.setdefault('friends', []), X.setdefault('friends', [])
        mr, tr = Me.setdefault('reqs', []), X.setdefault('reqs', [])
        if a == 'freq' and t not in mf and u not in tr:
            if t in mr:
                mr.remove(t); mf.append(t); tf.append(u)
            else:
                tr.append(u)
        elif a == 'facc' and t in mr:
            mr.remove(t); mf.append(t); tf.append(u)
        elif a == 'fdec' and t in mr:
            mr.remove(t)
        elif a == 'funf' and t in mf:
            mf.remove(t)
            if u in tf:
                tf.remove(u)
        save()
        await push()
    elif a == 'pdel':
        D['posts'] = [p for p in D['posts'] if not (p['id'] == m.get('id') and p['by'] == u)]
        save()
        for v in list(conns):
            await to(v, {'e': 'posts', 'p': D['posts']})
    elif a == 'cjoin':
        r = m.get('room', '')
        if not can(u, r):
            return
        s = calls.setdefault(r, set())
        if len(s) >= 6 and u not in s:
            await to(u, {'e': 'cfull'})
            return
        peers = [p for p in s if p != u]
        s.add(u)
        await to(u, {'e': 'cpeers', 'room': r, 'peers': peers})
        if not peers:
            for v in room_users(r):
                if v != u:
                    await to(v, {'e': 'cring', 'room': r, 'by': u})
    elif a == 'sig':
        if m.get('to') in calls.get(m.get('room'), ()) and u in calls.get(m.get('room'), ()):
            await to(m['to'], {'e': 'sig', 'from': u, 'room': m['room'], 'd': m.get('d')})
    elif a == 'cleave':
        await leave_call(u, m.get('room', ''))

@app.websocket('/ws/{user}')
async def ws(w: WebSocket, user: str, t: str = ''):
    await w.accept()
    x = D['users'].get(user)
    if not x or not t or x['tok'] != t:
        await w.close(4001)
        return
    conns[user] = w
    await push()
    await to(user, {'e': 'posts', 'p': D['posts']})
    try:
        while True:
            await handle(user, json.loads(await w.receive_text()))
    except WebSocketDisconnect:
        pass
    except Exception as ex:
        print('ws error', ex)
    finally:
        if conns.get(user) is w:
            conns.pop(user, None)
            for r in list(calls):
                await leave_call(user, r)
            await push()

@app.get('/img/{n}/{k}')
def img(n: str, k: str):
    d = D['users'].get(n, {}).get(k, '') if k in ('av', 'bn') else ''
    if not d.startswith('data:'):
        raise HTTPException(404)
    head, b = d.split(',', 1)
    return Response(base64.b64decode(b), media_type=head[5:].split(';')[0], headers={'Cache-Control': 'public,max-age=31536000'})

@app.get('/')
def home():
    return FileResponse(os.path.join(BASE, 'index.html'))

@app.get('/{page}.html')
def page(page: str):
    if page not in ('index', 'main'):
        raise HTTPException(404)
    return FileResponse(os.path.join(BASE, page + '.html'))
