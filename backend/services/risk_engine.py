SEV={'INFORMATIONAL':10,'LOW':30,'MEDIUM':50,'HIGH':70,'CRITICAL':90}
SRC={'Internal SOC':100,'Security Vendor':90,'Public Threat Feed':80,'Research Report':75,'Community Submission':55,'Unknown Source':30}
def calculate_threat_risk(severity,confidence,recency=70,observations=50,source_reliability=70,context=50,related_alerts=0):
    sev=SEV.get(str(severity).upper(),50); obs=min(100,int(observations)); ctx=min(100,int(context)); rel=min(100,int(source_reliability)); conf=min(100,int(confidence)); rec=min(100,int(recency)); alerts=min(100,related_alerts*10)
    score=round(sev*.30+conf*.25+rec*.15+obs*.10+rel*.10+max(ctx,alerts)*.10)
    return max(0,min(100,score))
def classify_risk(score):
    return 'INFORMATIONAL' if score<=20 else 'LOW' if score<=40 else 'MEDIUM' if score<=60 else 'HIGH' if score<=80 else 'CRITICAL'
def source_reliability(source): return SRC.get(source,30)
def calculate_confidence(source,observations,validated=True,correlated=False):
    score=source_reliability(source)*.55+min(100,observations*5)*.25+(100 if validated else 30)*.10+(90 if correlated else 45)*.10
    return round(score)
def calculate_vulnerability_priority(cvss,asset_criticality=50,exposure=50,known_exploited=False,business_context=50):
    score=(float(cvss)*10)*.35+asset_criticality*.20+exposure*.15+(100 if known_exploited else 20)*.20+business_context*.10
    return round(min(100,score))
