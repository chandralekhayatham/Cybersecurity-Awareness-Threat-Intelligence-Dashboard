import csv,random,hashlib,datetime as dt
from pathlib import Path
random.seed(42)
CATS=["PHISHING","MALWARE","RANSOMWARE","CREDENTIAL THREATS","WEB THREATS","NETWORK THREATS","VULNERABILITY EXPOSURE","SOCIAL ENGINEERING","DATA EXPOSURE","ACCOUNT SECURITY"]
TYPES=["IP ADDRESS","DOMAIN","URL","FILE HASH","EMAIL/SENDER DOMAIN","CVE ID"]
SOURCES=["Internal SOC","Security Vendor","Public Threat Feed","Research Report","Community Submission","Unknown Source"]
SEVS=["INFORMATIONAL","LOW","MEDIUM","HIGH","CRITICAL"]
STAT=["NEW","UNDER_REVIEW","MONITORING","CLOSED","FALSE_POSITIVE"]
def indicator(i,t):
    if t=="IP ADDRESS": return f"198.51.100.{i%240+1}"
    if t=="DOMAIN": return ["example.com","example.org","example.net","login-check.invalid","security-alert.invalid"][i%5]
    if t=="URL": return f"https://example.org/demo/path/{i}"
    if t=="FILE HASH": return hashlib.sha256(f"synthetic-{i}".encode()).hexdigest()
    if t=="EMAIL/SENDER DOMAIN": return ["example.com","example.org","example.net"][i%3]
    return f"CVE-2026-{1000+i%9000:04d}"
def main(n=2000):
    out=Path(__file__).parent/'threat_intelligence_dataset.csv'; now=dt.datetime(2026,10,4)
    fields=['threat_id','timestamp','threat_name','threat_category','indicator_type','indicator_value','source_name','confidence_score','severity','risk_score','status','first_seen','last_seen','country_or_region_optional','description','mitre_tactic_optional','mitre_technique_optional','cve_id_optional']
    with out.open('w',newline='',encoding='utf-8') as f:
      w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
      for i in range(1,n+1):
        cat=CATS[i%len(CATS)]; typ=TYPES[i%len(TYPES)]; sev=SEVS[i%len(SEVS)]; conf=random.randint(45,98); risk=min(100,max(5,conf+random.randint(-20,15)))
        day=now-dt.timedelta(days=random.randint(0,120)); attack={"PHISHING":("Initial Access","Phishing"),"CREDENTIAL THREATS":("Credential Access","Valid Accounts"),"RANSOMWARE":("Impact","Data Encrypted for Impact")}.get(cat,("",""))
        w.writerow({'threat_id':f'THR-2026-{i:05d}','timestamp':day.isoformat(),'threat_name':f'Synthetic {cat.title()} Observation {i}','threat_category':cat,'indicator_type':typ,'indicator_value':indicator(i,typ),'source_name':random.choice(SOURCES),'confidence_score':conf,'severity':sev,'risk_score':risk,'status':random.choice(STAT),'first_seen':day.date().isoformat(),'last_seen':(day+dt.timedelta(days=random.randint(0,10))).date().isoformat(),'country_or_region_optional':'DEMO','description':'SYNTHETIC / DEMO ONLY — defensive threat-intelligence record.','mitre_tactic_optional':attack[0],'mitre_technique_optional':attack[1],'cve_id_optional':indicator(i,typ) if typ=='CVE ID' else ''})
    print(f'Generated {n} safe synthetic records at {out}')
if __name__=='__main__': main()
