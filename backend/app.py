from flask import Flask, request, jsonify, send_from_directory
import sqlite3, csv, json
from pathlib import Path
from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import source_reliability
from backend.services.alert_engine import generate_threat_alert
from backend.services.attack_mapper import map_attack

BASE = Path(__file__).resolve().parent.parent
DB = BASE / 'threat_intelligence.db'
app = Flask(__name__, static_folder=str(BASE / 'frontend/static'))

def db():
    c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c

def init_db():
    c=db(); c.executescript('''
    CREATE TABLE IF NOT EXISTS threats(threat_id TEXT PRIMARY KEY, threat_name TEXT, category TEXT, description TEXT, severity TEXT, risk_score INTEGER, confidence_score INTEGER, status TEXT, first_seen TEXT, last_seen TEXT);
    CREATE TABLE IF NOT EXISTS indicators(indicator_id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT, indicator_type TEXT, indicator_value TEXT, first_seen TEXT, last_seen TEXT);
    CREATE TABLE IF NOT EXISTS sources(source_id INTEGER PRIMARY KEY AUTOINCREMENT, source_name TEXT UNIQUE, reliability INTEGER);
    CREATE TABLE IF NOT EXISTS attack_mappings(mapping_id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT, tactic TEXT, technique TEXT);
    CREATE TABLE IF NOT EXISTS vulnerabilities(vulnerability_id INTEGER PRIMARY KEY AUTOINCREMENT, cve_id TEXT, severity TEXT, cvss_score REAL, patch_available INTEGER, priority_score INTEGER);
    CREATE TABLE IF NOT EXISTS alerts(alert_id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT, severity TEXT, risk_score INTEGER, confidence_score INTEGER, status TEXT, created_at TEXT, alert_type TEXT, description TEXT);
    CREATE TABLE IF NOT EXISTS analyst_notes(note_id INTEGER PRIMARY KEY AUTOINCREMENT, threat_id TEXT, note TEXT, created_at TEXT);
    '''); c.commit(); c.close()

def load_csv():
    with open(BASE/'data/threat_intelligence_dataset.csv', encoding='utf-8') as f: return list(csv.DictReader(f))

def seed():
    c=db()
    if c.execute('SELECT COUNT(*) FROM threats').fetchone()[0]: c.close(); return
    for r in load_csv():
        c.execute('INSERT INTO threats VALUES(?,?,?,?,?,?,?,?,?,?)',(r['threat_id'],r['threat_name'],r['threat_category'],r['description'],r['severity'],int(r['risk_score']),int(r['confidence_score']),r['status'],r['first_seen'],r['last_seen']))
        c.execute('INSERT INTO indicators(threat_id,indicator_type,indicator_value,first_seen,last_seen) VALUES(?,?,?,?,?)',(r['threat_id'],r['indicator_type'],r['indicator_value'],r['first_seen'],r['last_seen']))
        c.execute('INSERT OR IGNORE INTO sources(source_name,reliability) VALUES(?,?)',(r['source_name'],source_reliability(r['source_name'])))
        m=map_attack(r['threat_category'])
        if m['justified']: c.execute('INSERT INTO attack_mappings(threat_id,tactic,technique) VALUES(?,?,?)',(r['threat_id'],m['tactic'],m['technique']))
        a=generate_threat_alert({'threat_id':r['threat_id'],'indicator_value':r['indicator_value'],'severity':r['severity'],'risk_score':int(r['risk_score']),'confidence_score':int(r['confidence_score'])})
        if a: c.execute('INSERT INTO alerts(threat_id,severity,risk_score,confidence_score,status,created_at,alert_type,description) VALUES(?,?,?,?,?,?,?,?)',(r['threat_id'],a['severity'],a['risk_score'],a['confidence_score'],a['status'],r['timestamp'],a['alert_type'],a['description']))
    # safe synthetic vulnerability set
    for i,cvss in enumerate([9.1,8.8,7.5,6.5,5.3],1):
        sev='CRITICAL' if cvss>=9 else 'HIGH' if cvss>=7.5 else 'MEDIUM'
        c.execute('INSERT INTO vulnerabilities(cve_id,severity,cvss_score,patch_available,priority_score) VALUES(?,?,?,?,?)',(f'CVE-2026-{9000+i}',sev,cvss,1 if i%2 else 0,round(cvss*10)))
    c.commit(); c.close()

@app.route('/')
def home(): return send_from_directory(BASE/'frontend','index.html')
@app.get('/api/health')
def health(): return {'status':'ok','mode':'synthetic offline demo'}
@app.get('/api/dashboard/stats')
def stats():
    c=db(); q=lambda s:c.execute(s).fetchone()[0]
    out={'total_threats':q('SELECT COUNT(*) FROM threats'),'critical':q("SELECT COUNT(*) FROM threats WHERE severity='CRITICAL'"),'high':q("SELECT COUNT(*) FROM threats WHERE severity='HIGH'"),'active_indicators':q('SELECT COUNT(*) FROM indicators'),'open_investigations':q("SELECT COUNT(*) FROM threats WHERE status IN ('NEW','UNDER_REVIEW')"),'average_confidence':round(c.execute('SELECT AVG(confidence_score) FROM threats').fetchone()[0] or 0),'vulnerabilities':q('SELECT COUNT(*) FROM vulnerabilities'),'alerts':q('SELECT COUNT(*) FROM alerts'),'severity':dict(c.execute('SELECT severity,COUNT(*) n FROM threats GROUP BY severity').fetchall()),'categories':dict(c.execute('SELECT category,COUNT(*) n FROM threats GROUP BY category').fetchall()),'indicator_types':dict(c.execute('SELECT indicator_type,COUNT(*) n FROM indicators GROUP BY indicator_type').fetchall()),'status':dict(c.execute('SELECT status,COUNT(*) n FROM threats GROUP BY status').fetchall())}; c.close(); return jsonify(out)
@app.get('/api/threats')
def threats():
    c=db(); rows=c.execute('SELECT t.*,i.indicator_type,i.indicator_value FROM threats t JOIN indicators i ON t.threat_id=i.threat_id ORDER BY t.risk_score DESC LIMIT 100').fetchall(); c.close(); return jsonify([dict(x) for x in rows])
@app.get('/api/threats/<tid>')
def threat(tid):
    c=db(); r=c.execute('SELECT * FROM threats WHERE threat_id=?',(tid,)).fetchone(); i=c.execute('SELECT * FROM indicators WHERE threat_id=?',(tid,)).fetchall(); a=c.execute('SELECT * FROM alerts WHERE threat_id=?',(tid,)).fetchall(); m=c.execute('SELECT * FROM attack_mappings WHERE threat_id=?',(tid,)).fetchall(); n=c.execute('SELECT * FROM analyst_notes WHERE threat_id=?',(tid,)).fetchall(); c.close(); return jsonify({'threat':dict(r) if r else None,'indicators':[dict(x) for x in i],'alerts':[dict(x) for x in a],'attack_mapping':[dict(x) for x in m],'notes':[dict(x) for x in n]})
@app.get('/api/indicators/search')
def search():
    v=request.args.get('q','').strip(); c=db(); r=c.execute('SELECT t.*,i.indicator_type,i.indicator_value FROM indicators i JOIN threats t ON t.threat_id=i.threat_id WHERE lower(i.indicator_value)=lower(?) OR lower(i.indicator_value) LIKE lower(?) LIMIT 20',(v,'%'+v+'%')).fetchall(); c.close(); return jsonify({'validation':validate_indicator(v),'results':[dict(x) for x in r]})
@app.get('/api/alerts')
def alerts():
    c=db(); r=c.execute('SELECT * FROM alerts ORDER BY alert_id DESC LIMIT 100').fetchall(); c.close(); return jsonify([dict(x) for x in r])
@app.put('/api/alerts/<int:aid>/status')
def alert_status(aid):
    s=(request.json or {}).get('status','NEW'); allowed={'NEW','INVESTIGATING','MONITORING','RESOLVED','FALSE_POSITIVE'}
    if s not in allowed: return jsonify({'error':'Invalid status'}),400
    c=db(); c.execute('UPDATE alerts SET status=? WHERE alert_id=?',(s,aid)); c.commit(); c.close(); return {'status':s}
@app.post('/api/threats/<tid>/notes')
def note(tid):
    n=(request.json or {}).get('note','').strip()
    if not n or len(n)>1000: return jsonify({'error':'Note required and must be <=1000 chars'}),400
    c=db(); c.execute("INSERT INTO analyst_notes(threat_id,note,created_at) VALUES(?,?,datetime('now'))",(tid,n)); c.commit(); c.close(); return {'saved':True}
@app.get('/api/vulnerabilities')
def vulns():
    c=db(); r=c.execute('SELECT * FROM vulnerabilities ORDER BY priority_score DESC').fetchall(); c.close(); return jsonify([dict(x) for x in r])
@app.get('/api/awareness/modules')
def modules(): return jsonify(json.loads((BASE/'awareness/modules.json').read_text()))
@app.get('/api/quiz')
def quiz():
    qs=json.loads((BASE/'awareness/quiz_questions.json').read_text()); return jsonify([{k:v for k,v in q.items() if k!='correct'} for q in qs])
@app.post('/api/quiz/submit')
def quiz_submit():
    answers=(request.json or {}).get('answers',[]); qs=json.loads((BASE/'awareness/quiz_questions.json').read_text()); correct=sum(1 for i,a in enumerate(answers[:len(qs)]) if a==qs[i]['correct']); score=round(correct/len(qs)*100); level='Needs Improvement' if score<=40 else 'Basic Awareness' if score<=60 else 'Good Awareness' if score<=80 else 'Strong Awareness'; return {'score':score,'correct':correct,'total':len(qs),'level':level}
if __name__=='__main__': init_db(); seed(); app.run(debug=True)
