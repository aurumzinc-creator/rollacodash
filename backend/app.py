from flask import Flask, request, jsonify, g, send_from_directory
from flask_cors import CORS
import sqlite3, bcrypt, jwt, json, os
from datetime import datetime, timedelta
from functools import wraps
from database import get_db, init_db

# Serve frontend (index.html) from same backend folder
FRONTEND_DIR = os.path.dirname(__file__)
app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path='')
CORS(app, resources={r"/api/*": {"origins": "*"}})

@app.route('/')
def serve_frontend():
    return send_from_directory(FRONTEND_DIR, 'index.html')

SECRET = os.environ.get('JWT_SECRET', 'velodash_secret_2024')

# Initialize DB on startup (runs whether via gunicorn or python directly)
init_db()

# ─── Auth helpers ──────────────────────────────────────────────────────────────
def make_token(user_id, role):
    payload = {
        'sub': user_id,
        'role': role,
        'exp': datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET, algorithm='HS256')

def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            payload = jwt.decode(auth[7:], SECRET, algorithms=['HS256'])
            g.user_id = payload['sub']
            g.role = payload['role']
        except Exception:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return wrapper

def require_admin(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized'}), 401
        try:
            payload = jwt.decode(auth[7:], SECRET, algorithms=['HS256'])
            g.user_id = payload['sub']
            g.role = payload['role']
            if g.role != 'admin':
                return jsonify({'error': 'Admin only'}), 403
        except Exception:
            return jsonify({'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return wrapper

def row2dict(row):
    return dict(row) if row else None

# ─── Auth endpoints ─────────────────────────────────────────────────────────────
@app.post('/api/auth/login')
def login():
    data = request.json
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username=?', (data['username'],)).fetchone()
    db.close()
    if not user or not bcrypt.checkpw(data['password'].encode(), user['password'].encode()):
        return jsonify({'error': 'Invalid credentials'}), 401
    token = make_token(user['id'], user['role'])
    return jsonify({'token': token, 'role': user['role'], 'user_id': user['id']})

@app.post('/api/auth/register')
@require_admin
def register():
    data = request.json
    pw_hash = bcrypt.hashpw(data['password'].encode(), bcrypt.gensalt()).decode()
    db = get_db()
    try:
        cur = db.execute(
            'INSERT INTO users (username, password, role) VALUES (?,?,?)',
            (data['username'], pw_hash, data.get('role', 'athlete'))
        )
        user_id = cur.lastrowid
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'error': 'Username already exists'}), 409
    db.close()
    return jsonify({'user_id': user_id}), 201

def list_athletes():
    db = get_db()
    if g.role == 'admin':
        rows = db.execute('''
            SELECT a.*, u.username FROM athletes a
            JOIN users u ON a.user_id = u.id
            ORDER BY a.full_name
        ''').fetchall()
    else:
        rows = db.execute('''
            SELECT a.*, u.username FROM athletes a
            JOIN users u ON a.user_id = u.id
            WHERE a.user_id = ?
        ''', (g.user_id,)).fetchall()
    db.close()
    return jsonify([row2dict(r) for r in rows])

@app.get('/api/athletes/<int:aid>')
@require_auth
def get_athlete(aid):
    db = get_db()
    row = db.execute('SELECT a.*, u.username FROM athletes a JOIN users u ON a.user_id=u.id WHERE a.id=?', (aid,)).fetchone()
    db.close()
    if not row:
        return jsonify({'error': 'Not found'}), 404
    a = row2dict(row)
    # Compute derived fields
    if a.get('birth_date'):
        born = datetime.strptime(a['birth_date'], '%Y-%m-%d')
        a['age'] = (datetime.now() - born).days // 365
    if a.get('max_hr'):
        mhr = a['max_hr']
        a['hr_zones'] = {
            'Z1': [0, int(mhr*0.60)],
            'Z2': [int(mhr*0.60), int(mhr*0.70)],
            'Z3': [int(mhr*0.70), int(mhr*0.80)],
            'Z4': [int(mhr*0.80), int(mhr*0.90)],
            'Z5': [int(mhr*0.90), mhr]
        }
    return jsonify(a)

@app.post('/api/athletes')
@require_auth
def create_athlete():
    data = request.json
    # Athletes create their own profile; admin can create for any user_id
    user_id = data.get('user_id', g.user_id) if g.role == 'admin' else g.user_id
    # Compute max_hr if not provided
    max_hr = data.get('max_hr')
    if not max_hr and data.get('birth_date'):
        age = (datetime.now() - datetime.strptime(data['birth_date'], '%Y-%m-%d')).days // 365
        max_hr = 220 - age
    db = get_db()
    try:
        cur = db.execute('''
            INSERT INTO athletes (user_id, full_name, birth_date, gender, weight_kg,
              height_cm, category, experience_years, health_notes, resting_hr, max_hr)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        ''', (user_id, data['full_name'], data.get('birth_date'), data.get('gender'),
              data.get('weight_kg'), data.get('height_cm'), data.get('category'),
              data.get('experience_years', 0), data.get('health_notes'),
              data.get('resting_hr'), max_hr))
        aid = cur.lastrowid
        db.commit()
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'error': 'Profile already exists'}), 409
    db.close()
    return jsonify({'athlete_id': aid}), 201

@app.put('/api/athletes/<int:aid>')
@require_auth
def update_athlete(aid):
    data = request.json
    allowed = ['full_name','birth_date','gender','weight_kg','height_cm','category',
                'experience_years','health_notes','resting_hr','max_hr','strava_connected']
    sets = ', '.join(f'{k}=?' for k in data if k in allowed)
    vals = [data[k] for k in data if k in allowed] + [aid]
    if not sets:
        return jsonify({'error': 'Nothing to update'}), 400
    db = get_db()
    db.execute(f'UPDATE athletes SET {sets} WHERE id=?', vals)
    db.commit()
    db.close()
    return jsonify({'ok': True})

# ─── Sessions ─────────────────────────────────────────────────────────────────
@app.get('/api/athletes/<int:aid>/sessions')
@require_auth
def list_sessions(aid):
    limit = request.args.get('limit', 50)
    offset = request.args.get('offset', 0)
    db = get_db()
    rows = db.execute('''
        SELECT * FROM sessions WHERE athlete_id=?
        ORDER BY session_date DESC LIMIT ? OFFSET ?
    ''', (aid, limit, offset)).fetchall()
    db.close()
    return jsonify([row2dict(r) for r in rows])

@app.post('/api/athletes/<int:aid>/sessions')
@require_auth
def add_session(aid):
    data = request.json
    data['athlete_id'] = aid
    db = get_db()
    cur = db.execute('''
        INSERT INTO sessions (athlete_id, session_date, session_type, route_type,
          duration_min, distance_km, elevation_m, avg_speed_kmh, max_speed_kmh,
          avg_hr, max_hr, avg_cadence, max_cadence, rpe, calories,
          suffer_score, notes, data_source, strava_id)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (aid, data['session_date'], data['session_type'],
          data.get('route_type'), data.get('duration_min'), data.get('distance_km'),
          data.get('elevation_m'), data.get('avg_speed_kmh'), data.get('max_speed_kmh'),
          data.get('avg_hr'), data.get('max_hr'), data.get('avg_cadence'),
          data.get('max_cadence'), data.get('rpe'), data.get('calories'),
          data.get('suffer_score'), data.get('notes'), data.get('data_source','manual'),
          data.get('strava_id')))
    sid = cur.lastrowid
    # Save HR zones if provided
    hz = data.get('hr_zones')
    if hz:
        db.execute('''INSERT INTO hr_zones (session_id,zone1_min,zone2_min,zone3_min,zone4_min,zone5_min)
                      VALUES (?,?,?,?,?,?)''',
                   (sid, hz.get('z1',0), hz.get('z2',0), hz.get('z3',0), hz.get('z4',0), hz.get('z5',0)))
    db.commit()
    db.close()
    return jsonify({'session_id': sid}), 201

@app.delete('/api/sessions/<int:sid>')
@require_auth
def delete_session(sid):
    db = get_db()
    db.execute('DELETE FROM sessions WHERE id=?', (sid,))
    db.commit()
    db.close()
    return jsonify({'ok': True})

# ─── Stats / Analytics ───────────────────────────────────────────────────────
@app.get('/api/athletes/<int:aid>/stats')
@require_auth
def get_stats(aid):
    db = get_db()

    # Weekly volume (last 8 weeks)
    weekly = db.execute('''
        SELECT
            strftime('%Y-W%W', session_date) AS week,
            COUNT(*) AS sessions,
            ROUND(SUM(distance_km),1) AS total_km,
            SUM(duration_min) AS total_min,
            ROUND(AVG(rpe),1) AS avg_rpe,
            ROUND(AVG(avg_hr),0) AS avg_hr
        FROM sessions
        WHERE athlete_id=?
          AND session_date >= date('now','-56 days')
        GROUP BY week
        ORDER BY week
    ''', (aid,)).fetchall()

    # Session type breakdown
    types = db.execute('''
        SELECT session_type, COUNT(*) AS cnt, ROUND(SUM(distance_km),1) AS km
        FROM sessions WHERE athlete_id=?
        GROUP BY session_type ORDER BY cnt DESC
    ''', (aid,)).fetchall()

    # RPE trend (last 20 sessions)
    rpe_trend = db.execute('''
        SELECT session_date, rpe, session_type, distance_km
        FROM sessions WHERE athlete_id=? AND rpe IS NOT NULL
        ORDER BY session_date DESC LIMIT 20
    ''', (aid,)).fetchall()

    # All-time totals
    totals = db.execute('''
        SELECT
            COUNT(*) AS total_sessions,
            ROUND(SUM(distance_km),1) AS total_km,
            SUM(duration_min) AS total_min,
            ROUND(AVG(avg_speed_kmh),1) AS avg_speed,
            ROUND(AVG(avg_hr),0) AS avg_hr,
            ROUND(AVG(rpe),1) AS avg_rpe,
            MAX(distance_km) AS longest_km,
            MAX(avg_speed_kmh) AS fastest_avg
        FROM sessions WHERE athlete_id=?
    ''', (aid,)).fetchone()

    # Recent 7 days
    recent = db.execute('''
        SELECT COUNT(*) AS sessions, ROUND(SUM(distance_km),1) AS km, SUM(duration_min) AS min
        FROM sessions WHERE athlete_id=? AND session_date >= date('now','-7 days')
    ''', (aid,)).fetchone()

    db.close()
    return jsonify({
        'weekly': [row2dict(r) for r in weekly],
        'session_types': [row2dict(r) for r in types],
        'rpe_trend': [row2dict(r) for r in rpe_trend],
        'totals': row2dict(totals),
        'recent_7d': row2dict(recent)
    })

# ─── Admin: all athletes summary ─────────────────────────────────────────────
@app.get('/api/admin/overview')
@require_admin
def admin_overview():
    db = get_db()
    athletes = db.execute('''
        SELECT a.id, a.full_name, a.category, a.weight_kg, a.height_cm,
               COUNT(s.id) AS total_sessions,
               ROUND(SUM(s.distance_km),1) AS total_km,
               MAX(s.session_date) AS last_session,
               ROUND(AVG(s.rpe),1) AS avg_rpe
        FROM athletes a
        LEFT JOIN sessions s ON s.athlete_id = a.id
        GROUP BY a.id
        ORDER BY a.full_name
    ''').fetchall()

    # Club weekly totals
    club_weekly = db.execute('''
        SELECT strftime('%Y-W%W', s.session_date) AS week,
               COUNT(*) AS total_sessions,
               COUNT(DISTINCT s.athlete_id) AS active_athletes,
               ROUND(SUM(s.distance_km),1) AS total_km
        FROM sessions s
        WHERE s.session_date >= date('now','-56 days')
        GROUP BY week ORDER BY week
    ''').fetchall()

    db.close()
    return jsonify({
        'athletes': [row2dict(r) for r in athletes],
        'club_weekly': [row2dict(r) for r in club_weekly]
    })

# ─── Evaluations / Reports ───────────────────────────────────────────────────
@app.post('/api/athletes/<int:aid>/evaluations')
@require_admin
def save_evaluation(aid):
    data = request.json
    db = get_db()
    cur = db.execute('''
        INSERT INTO evaluations (athlete_id, eval_date, period, coach_notes, ai_report, created_by)
        VALUES (?,?,?,?,?,?)
    ''', (aid, data.get('eval_date', datetime.now().strftime('%Y-%m-%d')),
          data.get('period','weekly'), data.get('coach_notes'),
          json.dumps(data.get('ai_report')), g.user_id))
    db.commit()
    db.close()
    return jsonify({'eval_id': cur.lastrowid}), 201

@app.get('/api/athletes/<int:aid>/evaluations')
@require_auth
def list_evaluations(aid):
    db = get_db()
    rows = db.execute('''
        SELECT * FROM evaluations WHERE athlete_id=?
        ORDER BY created_at DESC LIMIT 10
    ''', (aid,)).fetchall()
    db.close()
    result = []
    for r in rows:
        d = row2dict(r)
        if d.get('ai_report'):
            try: d['ai_report'] = json.loads(d['ai_report'])
            except: pass
        result.append(d)
    return jsonify(result)

# ─── Weekly goals ─────────────────────────────────────────────────────────────
@app.post('/api/athletes/<int:aid>/goals')
@require_admin
def set_goal(aid):
    data = request.json
    db = get_db()
    cur = db.execute('''
        INSERT INTO weekly_goals (athlete_id, week_start, target_sessions,
          target_km, target_duration_min, target_types, notes, created_by)
        VALUES (?,?,?,?,?,?,?,?)
    ''', (aid, data['week_start'], data.get('target_sessions',4),
          data.get('target_km'), data.get('target_duration_min'),
          json.dumps(data.get('target_types',[])), data.get('notes'), g.user_id))
    db.commit()
    db.close()
    return jsonify({'goal_id': cur.lastrowid}), 201

@app.get('/api/athletes/<int:aid>/goals/current')
@require_auth
def current_goal(aid):
    db = get_db()
    row = db.execute('''
        SELECT * FROM weekly_goals WHERE athlete_id=?
        AND week_start <= date('now')
        ORDER BY week_start DESC LIMIT 1
    ''', (aid,)).fetchone()
    db.close()
    if not row:
        return jsonify(None)
    d = row2dict(row)
    if d.get('target_types'):
        try: d['target_types'] = json.loads(d['target_types'])
        except: pass
    return jsonify(d)

# ─── Seed demo data ────────────────────────────────────────────────────────────
@app.post('/api/admin/seed')
@require_admin
def seed_demo():
    import random
    from datetime import date, timedelta

    db = get_db()

    demo_athletes = [
        ('budi', 'Budi Santoso', '2009-03-15', 'L', 42, 148, 'Challenge_13_14', 2, 175, None),
        ('rina', 'Rina Kusuma', '2008-07-22', 'P', 38, 152, 'Challenge_13_14', 3, 182, None),
        ('dani', 'Dani Pratama', '2006-11-08', 'L', 55, 163, 'Youth', 4, 195, None),
        ('sari', 'Sari Wulandari', '2007-05-30', 'P', 48, 158, 'Youth', 3, 188, None),
        ('rizky', 'Rizky Fauzan', '2005-01-12', 'L', 62, 170, 'Junior', 5, 198, None),
    ]

    session_types = ['team_rantai', 'ITT', 'interval', 'hill_repeat', 'rolling', 'endurance', 'recovery']
    route_types   = ['flat', 'hill', 'rolling', 'mixed']

    pw = bcrypt.hashpw(b'atlet123', bcrypt.gensalt()).decode()

    for uname, name, bday, gender, wt, ht, cat, exp, mhr, _ in demo_athletes:
        try:
            cur = db.execute('INSERT INTO users (username,password,role) VALUES (?,?,?)',
                             (uname, pw, 'athlete'))
            uid = cur.lastrowid
        except:
            row = db.execute('SELECT id FROM users WHERE username=?',(uname,)).fetchone()
            uid = row['id']

        try:
            cur = db.execute('''INSERT INTO athletes
                (user_id,full_name,birth_date,gender,weight_kg,height_cm,category,
                 experience_years,resting_hr,max_hr)
                VALUES (?,?,?,?,?,?,?,?,?,?)''',
                (uid, name, bday, gender, wt, ht, cat, exp, 55, mhr))
            aid = cur.lastrowid
        except:
            row = db.execute('SELECT id FROM athletes WHERE user_id=?',(uid,)).fetchone()
            aid = row['id']

        # Generate 30 days of sessions
        today = date.today()
        for i in range(30):
            d = today - timedelta(days=i)
            if random.random() < 0.6:  # 60% chance of training day
                stype = random.choice(session_types)
                rtype = random.choice(route_types)
                dur   = random.randint(45, 180)
                dist  = round(dur * random.uniform(0.25, 0.42), 1)
                speed = round(dist / (dur/60), 1)
                rpe   = random.randint(5, 9)
                ahr   = random.randint(130, 165)
                cad   = random.randint(75, 95)
                try:
                    db.execute('''INSERT INTO sessions
                        (athlete_id,session_date,session_type,route_type,duration_min,
                         distance_km,avg_speed_kmh,avg_hr,max_hr,avg_cadence,rpe,data_source)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (aid, d.isoformat(), stype, rtype, dur, dist, speed,
                         ahr, ahr+20, cad, rpe, 'manual'))
                except: pass

    db.commit()
    db.close()
    return jsonify({'ok': True, 'message': 'Demo data seeded'})

# ─── Health check ─────────────────────────────────────────────────────────────
@app.get('/api/health')
def health():
    return jsonify({'status': 'ok', 'version': '1.0.0'})

if __name__ == '__main__':
    init_db()
    print("🚴 VeloDash API running on http://localhost:5000")
    app.run(debug=True, port=5000)
