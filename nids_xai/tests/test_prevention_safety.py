import unittest
from unittest.mock import patch

from api.services.prevention_service import PreventionService


class PreventionSafetyTests(unittest.TestCase):
    def test_failed_firewall_block_is_not_reported_as_blocked(self):
        service = PreventionService()
        service.set_mode('enforce')
        with patch('api.services.prevention_service.subprocess.run', side_effect=OSError('unavailable')):
            result = service.block_ip('192.0.2.1', 'test')
        self.assertNotEqual(result['action'], 'blocked_iptables')
        self.assertEqual(service.get_blocked(), [])

    def test_enforced_block_is_removed_after_mode_change(self):
        service = PreventionService()
        service.set_mode('enforce')
        with patch.object(service, '_block_with_iptables'), patch.object(service, '_unblock_with_iptables') as remove:
            service.block_ip('192.0.2.2', 'test')
            service.set_mode('monitor')
            service.unblock_ip('192.0.2.2')
            remove.assert_called_once_with('192.0.2.2')


if __name__ == '__main__':
    unittest.main()


class PreventionTransitionTests(unittest.TestCase):
    def test_dry_run_record_can_become_a_real_block(self):
        service = PreventionService()
        service.set_mode('dry_run')
        service.block_ip('192.0.2.8', 'test')
        service.set_mode('enforce')
        with patch.object(service, '_block_with_iptables') as apply:
            result = service.block_ip('192.0.2.8', 'test')
        apply.assert_called_once_with('192.0.2.8')
        self.assertEqual(result['action'], 'blocked_iptables')
