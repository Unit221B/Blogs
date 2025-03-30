#!/usr/bin/env python
import os
import sys
import uuid
import unittest
import json
from unittest.mock import patch, MagicMock

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from trae_claude_cli import TraeClaudeAPI

class TestTraeClaudeAPI(unittest.TestCase):
    """Unit tests for the TraeClaudeAPI class."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a test token
        self.test_token = "test_token_" + str(uuid.uuid4())
        
        # Create a test instance with the test token
        self.api = TraeClaudeAPI(token=self.test_token)
        
        # Ensure the conversation_id is set for testing
        self.api.conversation_id = str(uuid.uuid4())
    
    def test_init(self):
        """Test initialization of the API client."""
        # Check that the token is correctly set
        self.assertEqual(self.api.auth_token, self.test_token)
        
        # Check that the base URL is correctly set
        self.assertEqual(self.api.base_url, "https://trae-api-us.mchost.guru/api/ide/v1")
        
        # Check that computer_enabled is True by default
        self.assertTrue(self.api.computer_enabled)
    
    def test_toggle_computer_use(self):
        """Test toggling computer use capability."""
        # Check initial state (should be True by default)
        self.assertTrue(self.api.computer_enabled)
        
        # Toggle to False
        self.api.toggle_computer_use()
        self.assertFalse(self.api.computer_enabled)
        
        # Toggle back to True
        self.api.toggle_computer_use()
        self.assertTrue(self.api.computer_enabled)
        
        # Explicitly set to False
        self.api.toggle_computer_use(False)
        self.assertFalse(self.api.computer_enabled)
        
        # Explicitly set to True
        self.api.toggle_computer_use(True)
        self.assertTrue(self.api.computer_enabled)
    
    @patch('requests.post')
    def test_check_auth(self, mock_post):
        """Test authentication checking."""
        # Mock the response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_post.return_value = mock_response
        
        # Check authentication
        result = self.api.check_auth()
        
        # Verify that the result is True
        self.assertTrue(result)
        
        # Verify that the post method was called with the correct arguments
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertIn("/ping", args[0])
    
    @patch('requests.post')
    @patch.object(TraeClaudeAPI, 'check_auth')
    def test_send_message(self, mock_check_auth, mock_post):
        """Test sending a message."""
        # Skip authentication check by making it return True
        mock_check_auth.return_value = True
        
        # Mock the add to history method for the test
        self.api._add_to_history = MagicMock(return_value=True)
        
        # Create a context manager mock that returns the mock response
        mock_cm = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        # Make sure iter_lines returns the correct format for our code to parse
        mock_response.iter_lines.return_value = [
            b'data: {"delta": {"text": "Test response"}}'
        ]
        mock_cm.__enter__.return_value = mock_response
        mock_post.return_value = mock_cm
        
        # Send a message
        response = self.api.send_message("Test message")
        
        # Verify that the response contains our test string
        self.assertEqual(response, "Test response")
        
        # Verify that the post method was called with the correct arguments
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        self.assertIn("/llm_raw_chat", args[0])
        self.assertEqual(kwargs['json']['user_message'], "Test message")
    
    def test_simulate_command_execution(self):
        """Test simulated command execution."""
        # Test 'ls' command
        result = self.api._simulate_command_execution("ls")
        self.assertIn("file1.txt", result)
        
        # Test 'pwd' command
        result = self.api._simulate_command_execution("pwd")
        self.assertIn("/Users", result)
        
        # Test 'echo' command
        result = self.api._simulate_command_execution("echo hello world")
        self.assertEqual(result, "hello world")
    
    def test_handle_compute_event(self):
        """Test handling compute events."""
        # Test terminal command event
        event = {
            "type": "terminal_command",
            "command": "ls -la"
        }
        result = self.api._handle_compute_event(event)
        self.assertEqual(result["type"], "terminal_command")
        self.assertEqual(result["command"], "ls -la")
        self.assertIn("file1.txt", result["result"])
        
        # Test file write event
        event = {
            "type": "file_write",
            "path": "test.txt",
            "content": "Test content"
        }
        result = self.api._handle_compute_event(event)
        self.assertEqual(result["type"], "file_write")
        self.assertEqual(result["path"], "test.txt")
        self.assertTrue(result["success"])
        
        # Test file read event
        event = {
            "type": "file_read",
            "path": "test.txt"
        }
        result = self.api._handle_compute_event(event)
        self.assertEqual(result["type"], "file_read")
        self.assertEqual(result["path"], "test.txt")
        self.assertTrue(result["success"])
        self.assertIn("Simulated content", result["content"])
        
        # Test unknown event type
        event = {
            "type": "unknown_type",
            "data": "test data"
        }
        result = self.api._handle_compute_event(event)
        self.assertEqual(result["type"], "unknown")
        self.assertIn("error", result)

if __name__ == "__main__":
    unittest.main() 