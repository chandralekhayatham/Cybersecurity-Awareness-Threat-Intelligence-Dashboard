MAPPINGS={'PHISHING':('Initial Access','Phishing'),'CREDENTIAL THREATS':('Credential Access','Valid Accounts'),'SOCIAL ENGINEERING':('Initial Access','Phishing'),'RANSOMWARE':('Impact','Data Encrypted for Impact')}
def map_attack(category):
    tactic,technique=MAPPINGS.get(str(category).upper(),(None,None))
    return {'tactic':tactic,'technique':technique,'justified':bool(tactic)}
