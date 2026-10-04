def generate_threat_alert(row):
    if row['risk_score']>=70 or row['confidence_score']>=85:
        return {'alert_type':'THREAT_RISK_THRESHOLD','severity':row['severity'],'risk_score':row['risk_score'],'confidence_score':row['confidence_score'],'description':f"Review synthetic indicator {row['indicator_value']} in context.",'status':'NEW'}
    return None
