"""AlertStore: ring buffer push/pop/wrap-around and filtering."""


def test_push_assigns_uuid_and_returns_alert(fresh_alert_store):
    out = fresh_alert_store.push({"is_attack": True, "src_ip": "10.0.0.1"})
    assert "id" in out and len(out["id"]) > 0
    assert out["src_ip"] == "10.0.0.1"


def test_get_returns_newest_first(fresh_alert_store):
    fresh_alert_store.push({"is_attack": False, "src_ip": "first"})
    fresh_alert_store.push({"is_attack": False, "src_ip": "second"})
    fresh_alert_store.push({"is_attack": True,  "src_ip": "third"})

    items = fresh_alert_store.get(limit=10)
    assert len(items) == 3
    assert items[0]["src_ip"] == "third"
    assert items[2]["src_ip"] == "first"


def test_filter_by_attack_type(fresh_alert_store):
    for i in range(5):
        fresh_alert_store.push({"is_attack": i % 2 == 0, "src_ip": f"x{i}"})

    attack_only = fresh_alert_store.get(filter_type="attack")
    benign_only = fresh_alert_store.get(filter_type="benign")
    assert all(a["is_attack"] for a in attack_only)
    assert all(not a["is_attack"] for a in benign_only)
    assert len(attack_only) + len(benign_only) == 5


def test_ring_buffer_drops_oldest_when_full(fresh_alert_store):
    # maxlen is 10 from the fixture
    for i in range(15):
        fresh_alert_store.push({"is_attack": False, "src_ip": f"x{i}"})

    items = fresh_alert_store.get(limit=20)
    assert len(items) == 10
    assert items[0]["src_ip"] == "x14"  # newest preserved
    assert items[-1]["src_ip"] == "x5"  # oldest five evicted


def test_clear_empties_buffer(fresh_alert_store):
    for i in range(3):
        fresh_alert_store.push({"is_attack": False})
    removed = fresh_alert_store.clear()
    assert removed == 3
    assert fresh_alert_store.get() == []


def test_unclassified_flows_are_not_counted_as_benign():
    from api.services.alert_store import AlertStore

    store = AlertStore()
    store.push({'prediction': 'Unclassified', 'is_attack': False})
    store.push({'prediction': 'Benign', 'is_attack': False})
    stats = store.stats()
    assert stats['benign'] == 1
    assert stats['unclassified'] == 1
