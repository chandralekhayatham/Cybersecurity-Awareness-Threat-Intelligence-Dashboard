from collections import defaultdict
def correlate_threats(records):
    groups=defaultdict(list)
    for r in records: groups[(r.get('threat_category'),r.get('first_seen','')[:10])].append(r)
    return [v for v in groups.values() if len(v)>1]
def correlate_alerts(alerts):
    groups={}
    for a in alerts:
        key=(a['threat_id'],a['alert_type'],a['severity'])
        groups.setdefault(key,{'representative':a,'observation_count':0})['observation_count']+=1
    return list(groups.values())
