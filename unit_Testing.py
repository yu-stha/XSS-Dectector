import unittest
import sys
import os
from unittest.mock import patch, MagicMock
from bs4 import BeautifulSoup
import requests
from io import StringIO

# Import the XSS scanner functions to test
from websca import (
    get_all_forms,
    get_form_details,
    submit_form,
    scan_xss,
    clear_screen,
    xss_payloads
)

class TestXSSScanner(unittest.TestCase):
    """Test cases for the XSS Scanner functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a sample HTML with forms for testing
        self.sample_html = """
        <!DOCTYPE html>
        <html>
        <body>
            <form action="/submit" method="post">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="submit" value="Login">
            </form>
            <form action="/search" method="get">
                <input type="search" name="query">
                <input type="submit" value="Search">
            </form>
        </body>
        </html>
        """
        self.soup = BeautifulSoup(self.sample_html, "html.parser")
        self.forms = self.soup.find_all("form")
        self.test_url = "http://example.com"
        
    @patch('requests.get')
    def test_get_all_forms(self, mock_get):
        """Test 1: Verify that all forms are correctly extracted from HTML."""
        # Setup mock response
        mock_response = MagicMock()
        mock_response.content = self.sample_html
        mock_get.return_value = mock_response
        
        # Call the function
        forms = get_all_forms(self.test_url)
        
        # Assertions
        self.assertEqual(len(forms), 2)
        self.assertEqual(forms[0]['action'], '/submit')
        self.assertEqual(forms[1]['action'], '/search')
        print("Test 1: get_all_forms extracts correct number of forms ✅")
        
    def test_get_form_details(self):
        """Test 2: Verify form details extraction."""
        # Get the first form from sample HTML
        form = self.forms[0]
        
        # Call the function
        details = get_form_details(form)
        
        # Assertions
        self.assertEqual(details['action'], '/submit')
        self.assertEqual(details['method'], 'post')
        self.assertEqual(len(details['inputs']), 3)
        self.assertEqual(details['inputs'][0]['type'], 'text')
        self.assertEqual(details['inputs'][0]['name'], 'username')
        print("Test 2: get_form_details correctly extracts form information ✅")
    
    def test_get_form_details_empty_action(self):
        """Test 3: Verify form details extraction with empty action."""
        # Create a form with no action
        form_html = '<form method="post"><input type="text" name="test"></form>'
        form = BeautifulSoup(form_html, "html.parser").form
        
        # Call the function
        details = get_form_details(form)
        
        # Assertions
        self.assertEqual(details['action'], '')
        self.assertEqual(details['method'], 'post')
        print("Test 3: get_form_details handles empty action attribute correctly ✅")
        
    @patch('requests.post')
    @patch('requests.get')
    def test_submit_form_get(self, mock_get, mock_post):
        """Test 4: Test form submission with GET method."""
        # Setup
        form = self.forms[1]  # Search form with GET method
        form_details = get_form_details(form)
        payload = "<script>alert('XSS')</script>"
        
        # Mock response
        mock_response = MagicMock()
        mock_get.return_value = mock_response
        
        # Call function
        submit_form(form_details, self.test_url, payload)
        
        # Assertions
        mock_get.assert_called_once()
        mock_post.assert_not_called()
        print("Test 4: submit_form correctly uses GET method when specified ✅")
        
    @patch('requests.post')
    @patch('requests.get')
    def test_submit_form_post(self, mock_get, mock_post):
        """Test 5: Test form submission with POST method."""
        # Setup
        form = self.forms[0]  # Login form with POST method
        form_details = get_form_details(form)
        payload = "<script>alert('XSS')</script>"
        
        # Mock response
        mock_response = MagicMock()
        mock_post.return_value = mock_response
        
        # Call function
        submit_form(form_details, self.test_url, payload)
        
        # Assertions
        mock_post.assert_called_once()
        mock_get.assert_not_called()
        print("Test 5: submit_form correctly uses POST method when specified ✅")
        
    @patch('platform.system')
    @patch('os.system')
    def test_clear_screen_windows(self, mock_system, mock_platform):
        """Test 6: Test clear screen function on Windows."""
        # Setup
        mock_platform.return_value = "Windows"
        
        # Call function
        clear_screen()
        
        # Assertions
        mock_system.assert_called_with("cls")
        print("Test 6: clear_screen uses 'cls' on Windows systems ✅")
        
    @patch('platform.system')
    @patch('os.system')
    def test_clear_screen_linux(self, mock_system, mock_platform):
        """Test 7: Test clear screen function on Linux."""
        # Setup
        mock_platform.return_value = "Linux"
        
        # Call function
        clear_screen()
        
        # Assertions
        mock_system.assert_called_with("clear")
        print("Test 7: clear_screen uses 'clear' on Linux systems ✅")
        
    @patch('websca.get_all_forms')
    @patch('websca.get_form_details')
    @patch('websca.submit_form')
    def test_scan_xss_vulnerability_detected(self, mock_submit, mock_details, mock_forms):
        """Test 8: Test XSS vulnerability detection."""
        # Setup mocks
        form1 = MagicMock()
        mock_forms.return_value = [form1]
        
        form_details = {
            "action": "/submit",
            "method": "post",
            "inputs": [{"type": "text", "name": "username"}]
        }
        mock_details.return_value = form_details
        
        # This is the key change - make the response match the expected format
        mock_response = MagicMock()
        # Use the first payload from xss_payloads for testing
        payload = xss_payloads[0]
        # Ensure content is in bytes, as requests would return
        mock_response.content = payload.encode('utf-8')
        mock_submit.return_value = mock_response
        
        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Call function
        scan_xss(self.test_url)
        
        # Reset stdout
        sys.stdout = sys.__stdout__
        
        # Assertions - look for "XSS Detected" in the output
        output = captured_output.getvalue()
        self.assertIn("XSS Detected", output)
        print("Test 8: scan_xss correctly identifies XSS vulnerabilities ✅")
            
    @patch('websca.get_all_forms')
    @patch('websca.get_form_details')
    @patch('websca.submit_form')
    def test_scan_xss_no_vulnerability(self, mock_submit, mock_details, mock_forms):
        """Test 9: Test when no XSS vulnerability is found."""
        # Setup mocks
        form1 = MagicMock()
        mock_forms.return_value = [form1]
        
        form_details = {
            "action": "/submit",
            "method": "post",
            "inputs": [{"type": "text", "name": "username"}]
        }
        mock_details.return_value = form_details
        
        # Return content that doesn't contain the payload
        mock_response = MagicMock()
        mock_response.content = b"Safe content with no XSS"
        mock_submit.return_value = mock_response
        
        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Call function
        scan_xss(self.test_url)
        
        # Reset stdout
        sys.stdout = sys.__stdout__
        
        # Assertions
        output = captured_output.getvalue()
        self.assertIn("No XSS Detected", output)
        print("Test 9: scan_xss correctly reports when no vulnerabilities are found ✅")
            
    def test_xss_payloads_not_empty(self):
        """Test 10: Verify that XSS payloads list is not empty."""
        self.assertTrue(len(xss_payloads) > 0)
        print("Test 10: xss_payloads list contains test vectors ✅")

if __name__ == "__main__":
    print("Running XSS Scanner Unit Tests\n")
    unittest.main(argv=['first-arg-is-ignored'], exit=False)