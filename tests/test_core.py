from backend.services.ioc_validator import validate_indicator
from backend.services.risk_engine import calculate_threat_risk,classify_risk,calculate_confidence,source_reliability
from backend.services.attack_mapper import map_attack

def test_valid_ipv4(): assert validate_indicator('198.51.100.25')['valid']
def test_invalid_ipv4(): assert not validate_indicator('999.999.999.999')['valid']
def test_domain(): assert validate_indicator('login-check.invalid')['indicator_type']=='DOMAIN'
def test_url_is_not_contacted(): assert validate_indicator('https://example.org/demo')['indicator_type']=='URL'
def test_hash(): assert validate_indicator('a'*64)['valid']
def test_cve(): assert validate_indicator('CVE-2026-1234')['valid']
def test_risk_boundaries(): assert classify_risk(calculate_threat_risk('CRITICAL',95)) in {'HIGH','CRITICAL'}
def test_confidence(): assert calculate_confidence('Internal SOC',10)>calculate_confidence('Unknown Source',1)
def test_source_reliability(): assert source_reliability('Internal SOC')>source_reliability('Unknown Source')
def test_attack_mapping(): assert map_attack('PHISHING')['tactic']=='Initial Access'
