"""End-to-end verification for the Phase 0/1/2 alert pipeline.

Exercises:
  - alert_store save/get/list/update
  - EDRAdapter -> Alert normalization (Wazuh + Elkeid + Syslog + SecAgent)
  - POST /api/v1/alerts/ingest
  - GET  /api/v1/alerts (filters)
  - PATCH /api/v1/alerts/{id}/status (RBAC)
  - unknown source fallback

Requires PG to be reachable (192.168.80.101:5432 in this env).
The conftest has already initialized the schema; we just hit the API.
"""
import os
import pytest
import json


# Force the right env BEFORE importing anything (env must be set before
# any src.* module reads settings).
os.environ['NACOS_SERVER'] = ''
os.environ['API_SECRET_KEY'] = 'test-secret-key-12345678'
os.environ['STORE_BACKEND'] = 'memory'
os.environ['PG_HOST'] = '192.168.80.101'
os.environ['ES_HOSTS'] = 'http://192.168.80.101:9200'
os.environ['REDIS_HOST'] = '192.168.80.101'
os.environ['LOG_LEVEL'] = 'WARNING'


WAZUH = {
    'id': 'e2e-wazuh-001',
    'timestamp': '2026-07-27T10:00:00Z',
    'agent': {'name': 'e2e-host', 'id': 'e2e-ag', 'ip': '10.10.10.10'},
    'rule': {'level': 12, 'id': '5715', 'description': 'SSH brute force',
             'groups': ['auth'], 'mitre': {'id': ['T1110']}},
    'data': {'srcip': '203.0.113.7', 'dstip': '10.10.10.10', 'sha256': 'feed'},
}

ELKEID = {
    'alert_id': 'e2e-elkeid-001',
    'time': '2026-07-27T10:00:00Z',
    'data': {
        'level': 5, 'rule_id': 'R1', 'rule_name': 'netcat',
        'srcip': '1.2.3.4', 'domain': 'evil.example', 'sha256': 'h1',
        'tactic': ['TA0002'], 'description': 'suspicious',
    },
    'host': {'hostname': 'web-01', 'ip': '10.0.0.5', 'agent_id': 'ag-1'},
}

SYSLOG = {
    'msg': 'kernel panic on host1',
    'hostname': 'host1',
    'program': 'kernel',
    'priority': '<0>',
}


@pytest.fixture(scope='module')
def client():
    from fastapi.testclient import TestClient
    from src.api.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope='module')
def admin_headers(client):
    r = client.post('/api/v1/auth/login', json={'username': 'admin', 'password': 'admin123'})
    assert r.status_code == 200, f'login failed: {r.text}'
    return {'Authorization': 'Bearer ' + r.json()['access_token']}


@pytest.fixture(scope='module')
def viewer_headers(client):
    r = client.post('/api/v1/auth/login', json={'username': 'viewer', 'password': 'viewer123'})
    assert r.status_code == 200, f'login failed: {r.text}'
    return {'Authorization': 'Bearer ' + r.json()['access_token']}


def test_01_wazuh_ingest(client, admin_headers):
    r = client.post('/api/v1/alerts/ingest',
                    json={'source': 'wazuh', 'payload': WAZUH},
                    headers=admin_headers)
    assert r.status_code == 200, f'ingest failed: {r.text}'
    body = r.json()
    assert body['alert_id'] == 'wazuh:e2e-wazuh-001'
    assert body['severity'] == 'critical'


def test_02_elkeid_ingest(client, admin_headers):
    r = client.post('/api/v1/alerts/ingest',
                    json={'source': 'elkeid', 'payload': ELKEID},
                    headers=admin_headers)
    assert r.status_code == 200, f'ingest failed: {r.text}'
    assert r.json()['alert_id'] == 'elkeid:e2e-elkeid-001'


def test_03_syslog_ingest(client, admin_headers):
    r = client.post('/api/v1/alerts/ingest',
                    json={'source': 'syslog', 'payload': SYSLOG},
                    headers=admin_headers)
    assert r.status_code == 200, f'ingest failed: {r.text}'
    assert r.json()['severity'] == 'critical'  # <0> -> severity 0 -> CRITICAL


def test_04_unknown_source_falls_back_to_syslog(client, admin_headers):
    r = client.post('/api/v1/alerts/ingest',
                    json={'source': 'nonexistent', 'payload': {'msg': 'hi'}},
                    headers=admin_headers)
    assert r.status_code == 200, f'ingest failed: {r.text}'


def test_05_list_with_severity_filter(client, admin_headers):
    r = client.get('/api/v1/alerts', params={'severity': 'critical', 'limit': 50},
                   headers=admin_headers)
    assert r.status_code == 200
    items = r.json()['items']
    assert items, 'no critical alerts'
    for a in items:
        assert a['severity'] == 'critical', f'filter leaked: {a}'


def test_06_list_with_source_filter(client, admin_headers):
    r = client.get('/api/v1/alerts', params={'source': 'wazuh', 'limit': 50},
                   headers=admin_headers)
    assert r.status_code == 200
    items = r.json()['items']
    for a in items:
        assert a['source'] == 'wazuh'


def test_07_get_single_alert(client, admin_headers):
    r = client.get('/api/v1/alerts/wazuh:e2e-wazuh-001', headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert body['alert_id'] == 'wazuh:e2e-wazuh-001'
    assert body['severity'] == 'critical'
    assert body['hostname'] == 'e2e-host'
    # iocs must be a structured dict (not a string)
    assert isinstance(body.get('iocs'), dict), f'iocs should be dict, got: {type(body.get("iocs"))}'
    assert '203.0.113.7' in body['iocs']['ips']
    assert 'feed' in body['iocs']['hashes']
    assert 'T1110' in body['mitre_attack']


def test_08_patch_status_persists(client, admin_headers):
    aid = 'wazuh:e2e-wazuh-001'
    r = client.patch(f'/api/v1/alerts/{aid}/status',
                     json={'status': 'acknowledged'}, headers=admin_headers)
    assert r.status_code == 200
    assert r.json()['status'] == 'acknowledged'
    # Re-fetch
    r2 = client.get(f'/api/v1/alerts/{aid}', headers=admin_headers)
    assert r2.json()['status'] == 'acknowledged'


def test_09_rbac_viewer_cannot_patch(client, viewer_headers):
    aid = 'wazuh:e2e-wazuh-001'
    r = client.patch(f'/api/v1/alerts/{aid}/status',
                     json={'status': 'resolved'}, headers=viewer_headers)
    assert r.status_code == 403, f'viewer should be 403, got {r.status_code}: {r.text}'


def test_10_rbac_viewer_can_list(client, viewer_headers):
    r = client.get('/api/v1/alerts', headers=viewer_headers)
    assert r.status_code == 200


def test_11_patch_invalid_status_rejected(client, admin_headers):
    aid = 'wazuh:e2e-wazuh-001'
    r = client.patch(f'/api/v1/alerts/{aid}/status',
                     json={'status': 'bogus'}, headers=admin_headers)
    assert r.status_code == 400, f'should reject: {r.text}'


def test_12_404_for_missing(client, admin_headers):
    r = client.get('/api/v1/alerts/wazuh:does-not-exist', headers=admin_headers)
    assert r.status_code == 404


def test_13_list_pagination(client, admin_headers):
    r1 = client.get('/api/v1/alerts', params={'limit': 1, 'offset': 0}, headers=admin_headers)
    assert r1.status_code == 200
    b1 = r1.json()
    assert len(b1['items']) <= 1
    assert b1['limit'] == 1
    assert b1['offset'] == 0
