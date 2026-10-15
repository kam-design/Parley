import os, time, secrets, hashlib, base64, json, traceback
from contextlib import asynccontextmanager
import certifi
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
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
    uri = (os.environ.get('MONGODB_URI') or '').strip().strip('"\'')
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

RL = {}

def hit(key, n, secs):
    now = time.time()
    L = [t for t in RL.get(key, []) if now - t < secs]
    if len(L) >= n:
        RL[key] = L
        return False
    L.append(now)
    RL[key] = L
    if len(RL) > 20000:
        for k in [k for k, v in RL.items() if not v or now - v[-1] > 3600]:
            RL.pop(k, None)
    return True

def ip(req):
    f = req.headers.get('x-forwarded-for', '')
    return f.split(',')[0].strip() if f else (req.client.host if req.client else '?')

# action -> (max count, per seconds)
LIM = {'msg': (20, 10), 'post': (6, 60), 'cmt': (12, 60), 'gnew': (5, 3600), 'freq': (25, 3600),
       'react': (40, 10), 'medit': (15, 30), 'report': (10, 3600), 'prof': (10, 60)}
RX = ('\U0001F44D', '\u2764\ufe0f', '\U0001F602', '\U0001F525', '\U0001F62E', '\U0001F3AE')
ADMIN = os.environ.get('ADMIN_KEY', '').strip()

def blocked_between(a, b):
    return b in D['users'].get(a, {}).get('blocked', []) or a in D['users'].get(b, {}).get('blocked', [])

@app.post('/register')
async def register(a: Auth, req: Request):
    if not hit('reg:' + ip(req), 5, 3600):
        raise HTTPException(429, 'Too many sign-ups from this network. Try again later.')
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
async def login(a: Auth, req: Request):
    if not hit('lg:' + ip(req), 30, 300) or not hit('lu:' + a.username.strip().lower(), 8, 300):
        raise HTTPException(429, 'Too many sign-in attempts. Wait a few minutes and try again.')
    u = D['users'].get(a.username.strip())
    if u and u.get('banned'):
        raise HTTPException(403, 'This account has been suspended.')
    if not u or u['pw'] != h(a.password, u['salt']):
        raise HTTPException(401, 'Wrong username or password')
    tok = secrets.token_hex(16)
    u['tok'] = tok
    u['toks'] = (u.get('toks', []) + [tok])[-8:]
    await put_user(a.username.strip())
    return {'token': tok}

conns, calls = {}, {}

def good_token(x, t):
    return bool(x) and not x.get('banned') and bool(t) and (t in x.get('toks', []) or t == x.get('tok'))

@app.get('/check/{user}')
def check(user: str, t: str = ''):
    if not good_token(D['users'].get(user), t):
        raise HTTPException(401, 'Session expired')
    return {'ok': 1}

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
    return {'e': 'state', 'groups': gs, 'users': us, 'reqs': D['users'][u].get('reqs', []), 'out': out,
            'blocked': D['users'][u].get('blocked', [])}

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
    if a in LIM and not hit(f'{u}:{a}', *LIM[a]):
        await to(u, {'e': 'err', 'm': 'You are doing that too fast. Wait a moment and try again.'})
        return
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
        if r.startswith('dm:'):
            other = [p for p in room_users(r) if p != u]
            if other and blocked_between(u, other[0]):
                await to(u, {'e': 'err', 'm': 'Message could not be delivered.'})
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
        if not X or t == u or blocked_between(u, t):
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
    elif a in ('block', 'unblock'):
        t, Me = m.get('user'), D['users'][u]
        if t not in D['users'] or t == u:
            return
        b = Me.setdefault('blocked', [])
        if a == 'block' and t not in b:
            b.append(t)
            X = D['users'][t]
            for A, B in ((Me, t), (X, u)):
                for k in ('friends', 'reqs'):
                    if B in A.get(k, []):
                        A[k].remove(B)
            await put_user(t)
        elif a == 'unblock' and t in b:
            b.remove(t)
        await put_user(u)
        await push()
    elif a == 'report':
        kind, tgt = m.get('kind'), m.get('user')
        ref, room, excerpt = str(m.get('ref', ''))[:20], str(m.get('room', ''))[:60], ''
        if kind not in ('user', 'post', 'msg') or tgt not in D['users']:
            return
        if kind == 'post':
            p = next((x for x in D['posts'] if x['id'] == ref), None)
            if not p:
                return
            tgt, excerpt = p['by'], (p['txt'] or '[image]')[:200]
        elif kind == 'msg':
            if not can(u, room):
                return
            x = await db.msgs.find_one({'room': room, 'id': ref})
            if not x:
                return
            tgt, excerpt = x['from'], (x['d'] if x['k'] == 'text' else '[' + x['k'] + ']')[:200]
        if tgt == u:
            return
        await db.reports.insert_one({'_id': secrets.token_hex(6), 'by': u, 'kind': kind, 'user': tgt, 'ref': ref,
                                     'room': room, 'excerpt': excerpt, 'reason': str(m.get('reason', ''))[:300],
                                     't': int(time.time() * 1000), 'status': 'open'})
    elif a in ('medit', 'mdel', 'react'):
        r, i = m.get('room', ''), m.get('id', '')
        if not can(u, r):
            return
        x = await db.msgs.find_one({'room': r, 'id': i}, {'_id': 0, 'room': 0})
        if not x:
            return
        if a == 'medit':
            d = str(m.get('d', '')).strip()[:2000]
            if x['from'] != u or x['k'] != 'text' or not d:
                return
            await db.msgs.update_one({'room': r, 'id': i}, {'$set': {'d': d, 'edited': True}})
            x['d'], x['edited'] = d, True
        elif a == 'mdel':
            g = G.get(r)
            if x['from'] != u and not (g and u in g['admins']):
                return
            await db.msgs.delete_one({'room': r, 'id': i})
            for v in room_users(r):
                await to(v, {'e': 'mdel', 'room': r, 'id': i})
            return
        else:
            e = m.get('emoji')
            if e not in RX:
                return
            rx = x.get('rx', {})
            L = rx.get(e, [])
            if u in L:
                L.remove(u)
            else:
                L.append(u)
            if L:
                rx[e] = L
            else:
                rx.pop(e, None)
            await db.msgs.update_one({'room': r, 'id': i}, {'$set': {'rx': rx}})
            x['rx'] = rx
        for v in room_users(r):
            await to(v, {'e': 'mupd', 'room': r, 'm': x})
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
    if not good_token(x, t):
        await w.close(4001)
        return
    conns[user] = w
    try:
        await push()
        await to(user, {'e': 'posts', 'p': D['posts']})
        while True:
            raw = await w.receive_text()
            try:
                await handle(user, json.loads(raw))
            except WebSocketDisconnect:
                raise
            except Exception as ex:
                traceback.print_exc()
                await to(user, {'e': 'err', 'm': f'{type(ex).__name__}: {ex}'[:200]})
    except WebSocketDisconnect:
        pass
    except Exception:
        traceback.print_exc()
    finally:
        if conns.get(user) is w:
            conns.pop(user, None)
            for r in list(calls):
                await leave_call(user, r)
            await push()

def admin_ok(key):
    return bool(ADMIN) and secrets.compare_digest(key.encode(), ADMIN.encode())

@app.get('/admin/api/reports')
async def admin_reports(key: str = ''):
    if not admin_ok(key):
        raise HTTPException(403, 'Wrong key')
    return await db.reports.find({'status': 'open'}).sort('t', -1).limit(100).to_list(100)

class Act(BaseModel):
    key: str
    id: str
    op: str

@app.post('/admin/api/act')
async def admin_act(a: Act):
    if not admin_ok(a.key):
        raise HTTPException(403, 'Wrong key')
    rp = await db.reports.find_one({'_id': a.id})
    if not rp:
        raise HTTPException(404, 'Report not found')
    if a.op == 'remove':
        if rp['kind'] == 'post':
            D['posts'] = [p for p in D['posts'] if p['id'] != rp['ref']]
            await db.posts.delete_one({'_id': rp['ref']})
            for v in list(conns):
                await to(v, {'e': 'posts', 'p': D['posts']})
        elif rp['kind'] == 'msg':
            await db.msgs.delete_one({'room': rp['room'], 'id': rp['ref']})
            for v in room_users(rp['room']):
                await to(v, {'e': 'mdel', 'room': rp['room'], 'id': rp['ref']})
    elif a.op == 'ban':
        x = D['users'].get(rp['user'])
        if x:
            x['banned'], x['tok'], x['toks'] = True, '', []
            await put_user(rp['user'])
            w = conns.get(rp['user'])
            if w:
                await w.close(4001)
    elif a.op != 'dismiss':
        raise HTTPException(400, 'Unknown action')
    await db.reports.update_one({'_id': a.id}, {'$set': {'status': 'done', 'action': a.op}})
    return {'ok': 1}

@app.api_route('/admin', methods=['GET', 'HEAD'])
def admin_page():
    return FileResponse(os.path.join(BASE, 'admin.html'))

@app.get('/img/{n}/{k}')
def img(n: str, k: str):
    d = D['users'].get(n, {}).get(k, '') if k in ('av', 'bn') else ''
    if not d.startswith('data:'):
        raise HTTPException(404)
    head, b = d.split(',', 1)
    return Response(base64.b64decode(b), media_type=head[5:].split(';')[0], headers={'Cache-Control': 'public,max-age=31536000'})

@app.api_route('/', methods=['GET', 'HEAD'])
def home():
    return FileResponse(os.path.join(BASE, 'index.html'))

@app.api_route('/{page}.html', methods=['GET', 'HEAD'])
def page(page: str):
    if page not in ('index', 'main'):
        raise HTTPException(404)
    return FileResponse(os.path.join(BASE, page + '.html'))
