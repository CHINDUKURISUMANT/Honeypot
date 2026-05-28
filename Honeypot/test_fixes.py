# test_fixes.py
import sys
import os
import unittest
from unittest.mock import MagicMock

# Add project root to sys.path
sys.path.append(os.getcwd())

# Mock OllamaClient before imports to avoid connection errors
sys.modules["behaviour.ollama_client"] = MagicMock()

from Honeypot.services.ssh.ssh_honeypot import FakeShell
from Honeypot.behaviour.maneuvering_engine import _sanitize_output

class TestHoneypotFixes(unittest.TestCase):

    def setUp(self):
        self.mock_channel = MagicMock()
        self.shell = FakeShell("root", "127.0.0.1", self.mock_channel)
        # Mock _out to capture it
        self.shell._out = MagicMock()

    def test_issue_1_cd_no_output(self):
        """Issue 1: cd secret should update cwd and have NO output."""
        self.shell.handle("cd secret")
        self.assertEqual(self.shell.cwd, "/root/secret")
        # Check that NO output was sent (except perhaps the prompt which is handled by the loop, not handle)
        self.shell._out.assert_not_called()

    def test_issue_2_invalid_command(self):
        """Issue 2: Unknown commands should return 'command not found'."""
        self.shell.handle("asdasd")
        # Should be called once with the bash error
        self.shell._out.assert_called_with("bash: asdasd: command not found")

    def test_issue_4_cat_filesystem_consistency(self):
        """Issue 4: cat credentials.txt should work in /root/secret."""
        self.shell.cwd = "/root/secret"
        self.shell.handle("cat credentials.txt")
        # Should output the file contents from FAKE_FILE_CONTENTS
        self.assertTrue(any("Internal Service Credentials" in str(call) for call in self.shell._out.call_args_list))

    def test_issue_5_id_consistency(self):
        """Issue 5: id should be consistent."""
        self.shell.handle("id")
        out1 = self.shell._out.call_args[0][0]
        self.shell._out.reset_mock()
        self.shell.handle("ls -la") # Advance state potentially
        self.shell.handle("id")
        out2 = self.shell._out.call_args[0][0]
        self.assertEqual(out1, out2, "ID output changed between calls!")

    def test_requirement_5_ai_leakage_scrubbing(self):
        """Requirement 5: Ensure AI output is rejected if it contains sensitive data for non-read commands."""
        # Scenario: ls; whoami -> .env dump
        raw_ai_output = "total 2\n.env\nroot\nAPP_SECRET=s3cr3t_leak"
        command = "ls; whoami"
        
        # Test the sanitizer directly
        result = _sanitize_output(raw_ai_output, "prod-web-01", "root", "/root", command)
        self.assertIsNone(result, "Sanitizer should have rejected output containing APP_SECRET for 'ls' command")

        # Test valid output
        valid_output = "total 2\n.env\nroot"
        result2 = _sanitize_output(valid_output, "prod-web-01", "root", "/root", command)
        self.assertIsNotNone(result2, "Sanitizer should have allowed non-leaky output")

    def test_issue_6_performance_fire_and_forget(self):
        """Issue 6: Check command classification routing."""
        # Core commands should return UNKNOWN_CMD or CORE/CONTENT/SYSTEM
        self.assertEqual(self.shell._classify_cmd("ls", "ls"), "CORE")
        self.assertEqual(self.shell._classify_cmd("cat", "cat file.txt"), "CONTENT")
        # Compound commands are ATTACK
        self.assertEqual(self.shell._classify_cmd("ls", "ls; whoami"), "ATTACK")

if __name__ == "__main__":
    unittest.main()
