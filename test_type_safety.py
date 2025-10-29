"""
Comprehensive tests for type safety fixes in API response handling.

This test suite verifies that all functions handle dict/list/None responses
gracefully without crashing, addressing the "'list' object has no attribute 'items'" error.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from server import safe_dict_items


class TestSafeDictItems(unittest.TestCase):
    """Test the safe_dict_items utility function with various input types."""

    def test_dict_input(self):
        """Test normal dict input - should iterate normally."""
        test_dict = {'a': 1, 'b': 2, 'c': 3}
        result = list(safe_dict_items(test_dict))
        expected = [('a', 1), ('b', 2), ('c', 3)]
        self.assertEqual(sorted(result), sorted(expected))

    def test_list_of_dicts_with_sid(self):
        """Test list of dicts with 'sid' field - should extract sid as key."""
        test_list = [
            {'sid': 'sensor1', 'data': 'value1'},
            {'sid': 'sensor2', 'data': 'value2'}
        ]
        result = list(safe_dict_items(test_list))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ('sensor1', {'sid': 'sensor1', 'data': 'value1'}))
        self.assertEqual(result[1], ('sensor2', {'sid': 'sensor2', 'data': 'value2'}))

    def test_list_of_dicts_with_id(self):
        """Test list of dicts with 'id' field - should extract id as key."""
        test_list = [
            {'id': 'item1', 'data': 'value1'},
            {'id': 'item2', 'data': 'value2'}
        ]
        result = list(safe_dict_items(test_list))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ('item1', {'id': 'item1', 'data': 'value1'}))
        self.assertEqual(result[1], ('item2', {'id': 'item2', 'data': 'value2'}))

    def test_list_of_strings(self):
        """Test list of strings (like getAllOnlineSensors returns) - should use string as both key and value."""
        test_list = ['sensor-id-1', 'sensor-id-2', 'sensor-id-3']
        result = list(safe_dict_items(test_list))
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0], ('sensor-id-1', 'sensor-id-1'))
        self.assertEqual(result[1], ('sensor-id-2', 'sensor-id-2'))
        self.assertEqual(result[2], ('sensor-id-3', 'sensor-id-3'))

    def test_list_without_key_fields(self):
        """Test list without sid/id fields - should use index as key."""
        test_list = [
            {'data': 'value1'},
            {'data': 'value2'}
        ]
        result = list(safe_dict_items(test_list))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0], ('0', {'data': 'value1'}))
        self.assertEqual(result[1], ('1', {'data': 'value2'}))

    def test_none_input(self):
        """Test None input - should return empty iteration."""
        result = list(safe_dict_items(None))
        self.assertEqual(result, [])

    def test_empty_dict(self):
        """Test empty dict - should return empty iteration."""
        result = list(safe_dict_items({}))
        self.assertEqual(result, [])

    def test_empty_list(self):
        """Test empty list - should return empty iteration."""
        result = list(safe_dict_items([]))
        self.assertEqual(result, [])

    def test_custom_key_extractor(self):
        """Test custom key extractor function."""
        test_list = [
            {'custom_id': 'item1', 'data': 'value1'},
            {'custom_id': 'item2', 'data': 'value2'}
        ]

        def extractor(item):
            return item['custom_id']

        result = list(safe_dict_items(test_list, default_key_extractor=extractor))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0][0], 'item1')
        self.assertEqual(result[1][0], 'item2')

    def test_custom_key_extractor_with_error(self):
        """Test custom key extractor that fails - should fallback to index."""
        test_list = [
            {'data': 'value1'},
            {'data': 'value2'}
        ]

        def failing_extractor(item):
            raise KeyError("no key")

        result = list(safe_dict_items(test_list, default_key_extractor=failing_extractor))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0][0], '0')  # Fallback to index
        self.assertEqual(result[1][0], '1')


class TestFunctionTypeSafety(unittest.TestCase):
    """Test that functions handle different response types without crashing."""

    def setUp(self):
        """Set up mocks for testing."""
        self.mock_context = Mock()
        self.mock_sdk = Mock()

    @patch('server.get_sdk_from_context')
    def test_get_online_sensors_with_list(self, mock_get_sdk):
        """Test get_online_sensors handles list response (SDK's actual return type)."""
        from server import get_online_sensors

        mock_get_sdk.return_value = self.mock_sdk
        # SDK actually returns a list of SIDs
        self.mock_sdk.getAllOnlineSensors.return_value = ['sid1', 'sid2', 'sid3']

        result = get_online_sensors(self.mock_context)

        self.assertIn('sensors', result)
        self.assertEqual(len(result['sensors']), 3)
        self.assertEqual(result['sensors'][0]['sid'], 'sid1')

    @patch('server.get_sdk_from_context')
    def test_get_online_sensors_with_dict(self, mock_get_sdk):
        """Test get_online_sensors handles dict response (backward compatibility)."""
        from server import get_online_sensors

        mock_get_sdk.return_value = self.mock_sdk
        # Old format: dict with full info
        self.mock_sdk.getAllOnlineSensors.return_value = {
            'sid1': {'hostname': 'host1', 'plat': 'windows'},
            'sid2': {'hostname': 'host2', 'plat': 'linux'}
        }

        result = get_online_sensors(self.mock_context)

        self.assertIn('sensors', result)
        self.assertEqual(len(result['sensors']), 2)
        self.assertEqual(result['sensors'][0]['hostname'], 'host1')

    @patch('server.get_sdk_from_context')
    def test_search_hosts_with_list(self, mock_get_sdk):
        """Test search_hosts handles list response."""
        from server import search_hosts

        mock_get_sdk.return_value = self.mock_sdk
        # API might return list instead of dict
        self.mock_sdk.hosts.return_value = ['sid1', 'sid2']

        result = search_hosts('test*', self.mock_context)

        self.assertIn('sensors', result)
        self.assertEqual(len(result['sensors']), 2)

    @patch('server.get_sdk_from_context')
    def test_search_hosts_with_dict(self, mock_get_sdk):
        """Test search_hosts handles dict response."""
        from server import search_hosts

        mock_get_sdk.return_value = self.mock_sdk
        # Expected format: dict
        self.mock_sdk.hosts.return_value = {
            'sid1': {'hostname': 'host1'},
            'sid2': {'hostname': 'host2'}
        }

        result = search_hosts('test*', self.mock_context)

        self.assertIn('sensors', result)
        self.assertEqual(len(result['sensors']), 2)

    @patch('server.get_sdk_from_context')
    def test_search_hosts_with_none(self, mock_get_sdk):
        """Test search_hosts handles None response."""
        from server import search_hosts

        mock_get_sdk.return_value = self.mock_sdk
        self.mock_sdk.hosts.return_value = None

        result = search_hosts('test*', self.mock_context)

        self.assertIn('sensors', result)
        self.assertEqual(result['sensors'], [])

    @patch('server.get_sdk_from_context')
    @patch('server.limacharlie.Hive')
    def test_hive_list_functions_with_dict(self, mock_hive_class, mock_get_sdk):
        """Test hive.list() functions handle dict response (normal case)."""
        from server import get_detection_rules

        mock_get_sdk.return_value = self.mock_sdk

        # Create mock HiveRecord objects
        mock_record1 = Mock()
        mock_record1.toJSON.return_value = {'name': 'rule1', 'data': 'value1'}
        mock_record2 = Mock()
        mock_record2.toJSON.return_value = {'name': 'rule2', 'data': 'value2'}

        # Mock hive.list() to return dict of HiveRecord objects
        mock_hive = Mock()
        mock_hive.list.return_value = {
            'rule1': mock_record1,
            'rule2': mock_record2
        }
        mock_hive_class.return_value = mock_hive

        result = get_detection_rules(self.mock_context)

        self.assertIn('rules', result)
        self.assertGreater(len(result['rules']), 0)

    @patch('server.get_sdk_from_context')
    @patch('server.limacharlie.Hive')
    def test_hive_list_functions_with_list(self, mock_hive_class, mock_get_sdk):
        """Test hive.list() functions handle list response (error case)."""
        from server import get_fp_rules

        mock_get_sdk.return_value = self.mock_sdk

        # Mock hive.list() to return list (error case from API)
        mock_hive = Mock()
        mock_hive.list.return_value = [
            {'name': 'rule1', 'data': 'value1'},
            {'name': 'rule2', 'data': 'value2'}
        ]
        mock_hive_class.return_value = mock_hive

        result = get_fp_rules(self.mock_context)

        # Should not crash, should return something
        self.assertIn('rules', result)

    @patch('server.get_sdk_from_context')
    @patch('server.limacharlie.Hive')
    def test_hive_list_functions_with_none(self, mock_hive_class, mock_get_sdk):
        """Test hive.list() functions handle None response."""
        from server import list_rules

        mock_get_sdk.return_value = self.mock_sdk

        # Mock hive.list() to return None
        mock_hive = Mock()
        mock_hive.list.return_value = None
        mock_hive_class.return_value = mock_hive

        result = list_rules('dr-general', self.mock_context)

        self.assertIn('rules', result)
        self.assertEqual(result['rules'], {})


class TestRegressionPrevention(unittest.TestCase):
    """Test that the fixes don't break existing functionality."""

    @patch('server.get_sdk_from_context')
    def test_existing_dict_behavior_preserved(self, mock_get_sdk):
        """Ensure normal dict responses still work exactly as before."""
        from server import get_online_sensors

        mock_sdk = Mock()
        mock_get_sdk.return_value = mock_sdk

        # Old working format
        mock_sdk.getAllOnlineSensors.return_value = {
            'sensor1': {
                'hostname': 'test-host',
                'plat': 'windows',
                'arch': 'x64',
                'int_ip': '10.0.0.1',
                'ext_ip': '1.2.3.4',
                'last_seen': 1234567890
            }
        }

        result = get_online_sensors(Mock())

        # Verify all fields are preserved
        self.assertEqual(len(result['sensors']), 1)
        sensor = result['sensors'][0]
        self.assertEqual(sensor['hostname'], 'test-host')
        self.assertEqual(sensor['platform'], 'windows')
        self.assertEqual(sensor['architecture'], 'x64')
        self.assertEqual(sensor['internal_ip'], '10.0.0.1')
        self.assertEqual(sensor['external_ip'], '1.2.3.4')
        self.assertEqual(sensor['last_seen'], 1234567890)


if __name__ == '__main__':
    unittest.main()
