import ipaddress,re
from urllib.parse import urlparse

DOMAIN_RE=re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$|^([A-Za-z0-9-]+\.)*invalid$")
CVE_RE=re.compile(r"^CVE-\d{4}-\d{4,}$",re.I)

def validate_indicator(value):
    raw=(value or '').strip(); notes=[]
    try:
        ip=ipaddress.ip_address(raw); return {'valid':True,'indicator_type':'IP ADDRESS','normalized_value':str(ip),'validation_notes':'Valid IP syntax.'}
    except ValueError: pass
    if CVE_RE.fullmatch(raw): return {'valid':True,'indicator_type':'CVE ID','normalized_value':raw.upper(),'validation_notes':'Valid CVE identifier syntax.'}
    if re.fullmatch(r'[0-9a-fA-F]{32}',raw): return {'valid':True,'indicator_type':'FILE HASH','normalized_value':raw.lower(),'validation_notes':'Valid MD5-format hash.'}
    if re.fullmatch(r'[0-9a-fA-F]{40}',raw): return {'valid':True,'indicator_type':'FILE HASH','normalized_value':raw.lower(),'validation_notes':'Valid SHA-1-format hash.'}
    if re.fullmatch(r'[0-9a-fA-F]{64}',raw): return {'valid':True,'indicator_type':'FILE HASH','normalized_value':raw.lower(),'validation_notes':'Valid SHA-256-format hash.'}
    if raw.lower().startswith(('http://','https://')):
        u=urlparse(raw); valid=bool(u.netloc); return {'valid':valid,'indicator_type':'URL','normalized_value':raw,'validation_notes':'URL syntax checked only; it was not contacted.' if valid else 'Invalid URL syntax.'}
    if DOMAIN_RE.fullmatch(raw.lower()): return {'valid':True,'indicator_type':'DOMAIN','normalized_value':raw.lower(),'validation_notes':'Valid domain syntax.'}
    return {'valid':False,'indicator_type':'UNKNOWN','normalized_value':raw,'validation_notes':'Syntax not recognized. Validation does not determine maliciousness.'}
