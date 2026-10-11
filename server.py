import os, time, secrets, hashlib, base64, json
from contextlib import asynccontextmanager
import certifi
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel
from pymongo import AsyncMongoClient

BASE = os.path.dirname(os.path.abspath(__file__))
D = {'users': {}, 'groups': {}, 'posts': []}   # in-memory copy, MongoDB is the source of truth
db = None

@asynccontextmanager
async def lifespan(app):
    global db
    uri = os.environ.get('MONGODB_URI')
    if not uri:
        raise RuntimeError('Set the MONGODB_URI environment variable to your MongoDB connection string')
    kw = {'tlsCAFile': certifi.where()} if uri.startswith('mongodb+srv') else {}
    client = AsyncMongoClient(uri, **kw)
    db = client[os.environ.get('MONGODB_DB', 'parley')]
    await db.msgs.create_index([('room', 1), ('t', -1)])
    async for u in db.users.find():
        D['users'][u.pop('_id')] = u
    async for g in db.groups.find():
        D['groups'][g.pop('_id')] = g
    async for p in db.posts.find().sort('t', -1).limit(100):
        p.pop('_id')
        D['posts'].append(p)
    print(f"Loaded {len(D['users'])} users, {len(D['groups'])} groups, {len(D['posts'])} posts")
    yield
    await client.close()

app = FastAPI(lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

async def put_user(n):
    await db.users.replace_one({'_id': n}, {**D['users'][n], '_id': n}, upsert=True)

async def put_group(i):
    await db.groups.replace_one({'_id': i}, {**D['groups'][i], '_id': i}, upsert=True)

async def put_post(p):
    await db.posts.replace_one({'_id': p['id']}, {**p, '_id': p['id']}, upsert=True)

class Auth(BaseModel):
    username: str
    password: str

def h(p, s):
    return hashlib.sha256((s + p).encode()).hexdigest()

@app.post('/register')
async def register(a: Auth):
    u = a.username.strip()
    if not 3 <= len(u) <= 20 or not u.replace('_', '').isalnum():
        raise HTTPException(400, 'Username: 3-20 letters, numbers or underscores')
    if len(a.password) < 6:
        raise HTTPException(400, 'Password needs at least 6 characters')
    if u.lower() in {k.lower() for k in D['users']}:
        raise HTTPException(400, 'That username is taken')
    s = secrets.token_hex(8)
    D['users'][u] = {'salt': s, 'pw': h(a.password, s), 'bio': '', 'games': [], 'tok': '',
                     'friends': [], 'reqs': [], 'av': '', 'bn': ''}
    await put_user(u)
    return {'ok': 1}

@app.post('/login')
async def login(a: Auth):
    u = D['users'].get(a.username.strip())
    if not u or u['pw'] != h(a.password, u['salt']):
        raise HTTPException(401, 'Wrong username or password')
    u['tok'] = secrets.token_hex(16)
    await put_user(a.username.strip())
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
            L = await db.msgs.find({'room': r}, {'_id': 0, 'room': 0}).sort('t', -1).limit(150).to_list(150)
            L.reverse()
            await to(u, {'e': 'hist', 'room': r, 'm': L})
    elif a == 'msg':
        r, k, d = m.get('room', ''), m.get('k'), str(m.get('d', ''))
        if not can(u, r) or k not in ('text', 'img', 'voice') or len(d) > 4_000_000 or not d:
            return
        if k == 'text':
            d = d[:2000]
        g = {'id': secrets.token_hex(4), 'from': u, 't': int(time.time() * 1000), 'k': k, 'd': d}
        await db.msgs.insert_one({**g, 'room': r})
        old = await db.msgs.find({'room': r}, {'_id': 1}).sort('t', -1).skip(150).to_list(None)
        if old:
            await db.msgs.delete_many({'_id': {'$in': [o['_id'] for o in old]}})
        for v in room_users(r):
            await to(v, {'e': 'msg', 'room': r, 'm': g})
    elif a == 'gnew':
        n = str(m.get('name', '')).strip()[:30]
        if n:
            i = secrets.token_hex(3)
            G[i] = {'name': n, 'desc': str(m.get('desc', ''))[:120], 'public': bool(m.get('public')),
                    'owner': u, 'admins': [u], 'members': [u]}
            await put_group(i)
            await push()
    elif a == 'gjoin':
        g = G.get(m.get('id'))
        if g and g['public'] and u not in g['members']:
            g['members'].append(u)
            await put_group(m['id'])
            await push()
    elif a == 'gleave':
        gid = m.get('id')
        g = G.get(gid)
        if g and u in g['members']:
            g['members'].remove(u)
            if u in g['admins']:
                g['admins'].remove(u)
            if not g['members']:
                del G[gid]
                await db.groups.delete_one({'_id': gid})
                await db.msgs.delete_many({'room': gid})
            else:
                if u == g['owner']:
                    g['owner'] = (g['admins'] or g['members'])[0]
                    if g['owner'] not in g['admins']:
                        g['admins'].append(g['owner'])
                await put_group(gid)
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
        await put_group(m['id'])
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
        await put_user(u)
        await push()
    elif a == 'post':
        txt, img = str(m.get('txt', ''))[:280], str(m.get('img', ''))
        if (txt.strip() or img) and len(img) < 4_000_000:
            p = {'id': secrets.token_hex(4), 'by': u, 't': int(time.time() * 1000), 'txt': txt, 'img': img, 'likes': [], 'cm': []}
            D['posts'].insert(0, p)
            await put_post(p)
            while len(D['posts']) > 100:
                o = D['posts'].pop()
                await db.posts.delete_one({'_id': o['id']})
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
        await put_post(p)
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
        await put_user(u)
        await put_user(t)
        await push()
    elif a == 'pdel':
        pid = m.get('id')
        if any(p['id'] == pid and p['by'] == u for p in D['posts']):
            D['posts'] = [p for p in D['posts'] if p['id'] != pid]
            await db.posts.delete_one({'_id': pid})
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
