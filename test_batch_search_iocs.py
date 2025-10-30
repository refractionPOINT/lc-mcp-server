"""
Test for batch_search_iocs data transformation fix.

This test verifies that the batch_search_iocs function correctly transforms
the list of dicts input format into the dict of lists format expected by the SDK.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from server import batch_search_iocs


class TestBatchSearchIocsTransformation(unittest.TestCase):
    """Test the batch_search_iocs function data transformation."""

    @patch('server.get_sdk_from_context')
    def test_transforms_list_to_dict_format(self, mock_get_sdk):
        """Test that input list of dicts is correctly transformed to dict of lists."""
        # Setup mock SDK
        mock_sdk = Mock()
        mock_get_sdk.return_value = mock_sdk

        # Mock the getBatchObjectInformation method to capture what it receives
        mock_sdk.getBatchObjectInformation.return_value = {
            'last_1_days': {'hash': {'hash1': 5, 'hash2': 3}},
            'last_7_days': {'hash': {'hash1': 20, 'hash2': 15}},
        }

        # Create mock context
        mock_ctx = Mock()

        # Input format: list of dicts
        input_objects = [
            {"type": "hash", "name": "hash1", "info": "summary"},
            {"type": "hash", "name": "hash2", "info": "summary"},
            {"type": "domain", "name": "example.com", "info": "summary"},
            {"type": "domain", "name": "test.com", "info": "summary"},
        ]

        # Call the function
        result = batch_search_iocs(objects=input_objects, ctx=mock_ctx)

        # Verify getBatchObjectInformation was called with correct format
        mock_sdk.getBatchObjectInformation.assert_called_once()
        call_args = mock_sdk.getBatchObjectInformation.call_args

        # Extract the 'objects' parameter from the call
        transformed_objects = call_args.kwargs['objects']

        # Expected format: dict of lists
        expected_transformed = {
            'hash': ['hash1', 'hash2'],
            'domain': ['example.com', 'test.com']
        }

        # Verify transformation is correct
        self.assertEqual(transformed_objects, expected_transformed)

        # Verify result is returned correctly
        self.assertIn('results', result)
        self.assertIsInstance(result['results'], dict)

    @patch('server.get_sdk_from_context')
    def test_handles_single_type(self, mock_get_sdk):
        """Test transformation with objects of a single type."""
        mock_sdk = Mock()
        mock_get_sdk.return_value = mock_sdk
        mock_sdk.getBatchObjectInformation.return_value = {}
        mock_ctx = Mock()

        input_objects = [
            {"type": "hash", "name": "hash1", "info": "summary"},
            {"type": "hash", "name": "hash2", "info": "summary"},
        ]

        result = batch_search_iocs(objects=input_objects, ctx=mock_ctx)

        call_args = mock_sdk.getBatchObjectInformation.call_args
        transformed_objects = call_args.kwargs['objects']

        expected_transformed = {
            'hash': ['hash1', 'hash2']
        }

        self.assertEqual(transformed_objects, expected_transformed)

    @patch('server.get_sdk_from_context')
    def test_handles_empty_list(self, mock_get_sdk):
        """Test transformation with empty input list."""
        mock_sdk = Mock()
        mock_get_sdk.return_value = mock_sdk
        mock_sdk.getBatchObjectInformation.return_value = {}
        mock_ctx = Mock()

        input_objects = []

        result = batch_search_iocs(objects=input_objects, ctx=mock_ctx)

        call_args = mock_sdk.getBatchObjectInformation.call_args
        transformed_objects = call_args.kwargs['objects']

        # Should result in empty dict
        self.assertEqual(transformed_objects, {})

    @patch('server.get_sdk_from_context')
    def test_skips_objects_without_type_or_name(self, mock_get_sdk):
        """Test that objects missing 'type' or 'name' are skipped."""
        mock_sdk = Mock()
        mock_get_sdk.return_value = mock_sdk
        mock_sdk.getBatchObjectInformation.return_value = {}
        mock_ctx = Mock()

        input_objects = [
            {"type": "hash", "name": "hash1", "info": "summary"},
            {"type": "hash"},  # Missing 'name'
            {"name": "hash2"},  # Missing 'type'
            {"type": "domain", "name": "example.com", "info": "summary"},
        ]

        result = batch_search_iocs(objects=input_objects, ctx=mock_ctx)

        call_args = mock_sdk.getBatchObjectInformation.call_args
        transformed_objects = call_args.kwargs['objects']

        # Should only include valid objects
        expected_transformed = {
            'hash': ['hash1'],
            'domain': ['example.com']
        }

        self.assertEqual(transformed_objects, expected_transformed)

    @patch('server.get_sdk_from_context')
    def test_no_authentication(self, mock_get_sdk):
        """Test that function returns error when SDK is None."""
        mock_get_sdk.return_value = None
        mock_ctx = Mock()

        input_objects = [
            {"type": "hash", "name": "hash1", "info": "summary"}
        ]

        result = batch_search_iocs(objects=input_objects, ctx=mock_ctx)

        self.assertIn('error', result)
        self.assertEqual(result['error'], 'No authentication provided')


if __name__ == '__main__':
    unittest.main()
