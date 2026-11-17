from fastapi.testclient import TestClient


def test_spa_navigation_can_be_refreshed(tmp_path, monkeypatch):
    import api.main as main
    (tmp_path / 'index.html').write_text('<html>dashboard</html>')
    monkeypatch.setattr(main, '_REACT_BUILD', tmp_path)
    client = TestClient(main.create_app())
    assert client.get('/train').status_code == 200
    assert 'dashboard' in client.get('/train').text
    assert client.get('/api/missing').status_code == 404
