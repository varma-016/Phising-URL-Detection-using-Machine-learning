#!/usr/bin/env python3
"""
Test the Universal Phishing Detector integrated into both APIs
"""

import sys
import json


def test_universal_detector_api():
    """Test UniversalPhishingDetector from api.py"""
    print("\n" + "=" * 80)
    print("TEST 1: UniversalPhishingDetector from api.py")
    print("=" * 80 + "\n")
    
    try:
        from api import UniversalPhishingDetector
        
        test_urls = [
            ("https://www.google.com", False, "Legitimate Google"),
            ("https://g00gle.com", True, "Typosquatted Google"),
            ("https://secure-login.example.com", True, "Suspicious keywords"),
            ("https://bit.ly/short", True, "URL shortener"),
        ]
        
        passed = 0
        failed = 0
        
        for url, expected_phishing, description in test_urls:
            result = UniversalPhishingDetector.analyze_url(url)
            is_correct = result['is_phishing'] == expected_phishing
            
            if is_correct:
                passed += 1
                status = "PASS"
            else:
                failed += 1
                status = "FAIL"
            
            detection = "PHISHING" if result['is_phishing'] else "LEGIT"
            print(f"  [{status}] {url}")
            print(f"        => {description} (conf: {result['confidence']:.0%})")
        
        print(f"\nResult: {passed} passed, {failed} failed")
        return failed == 0
        
    except Exception as e:
        print(f"ERROR testing api.py: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_universal_detector_simple():
    """Test UniversalPhishingDetector from api_simple.py"""
    print("\n" + "=" * 80)
    print("TEST 2: UniversalPhishingDetector from api_simple.py")
    print("=" * 80 + "\n")
    
    try:
        from api_simple import UniversalPhishingDetector
        
        test_urls = [
            ("https://www.amazon.com", False, "Legitimate Amazon"),
            ("https://example.tk", True, "Suspicious TLD"),
        ]
        
        passed = 0
        failed = 0
        
        for url, expected_phishing, description in test_urls:
            result = UniversalPhishingDetector.analyze_url(url)
            is_correct = result['is_phishing'] == expected_phishing
            
            if is_correct:
                passed += 1
                status = "PASS"
            else:
                failed += 1
                status = "FAIL"
            
            detection = "PHISHING" if result['is_phishing'] else "LEGIT"
            print(f"  [{status}] {url}")
            print(f"        => {description} (conf: {result['confidence']:.0%})")
        
        print(f"\nResult: {passed} passed, {failed} failed")
        return failed == 0
        
    except Exception as e:
        print(f"ERROR testing api_simple.py: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_imports():
    """Test all required imports"""
    print("\n" + "=" * 80)
    print("TEST 3: Verify All Imports")
    print("=" * 80 + "\n")
    
    try:
        print("  Importing from api.py...")
        from api import UniversalPhishingDetector, validate_and_normalize_url
        print("    - UniversalPhishingDetector: OK")
        print("    - validate_and_normalize_url: OK")
        
        print("  Importing from api_simple.py...")
        from api_simple import UniversalPhishingDetector as UD2
        print("    - UniversalPhishingDetector: OK")
        
        print("\nAll imports successful!")
        return True
        
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


if __name__ == '__main__':
    print("\n")
    print("=" * 80)
    print("UNIVERSAL PHISHING DETECTOR - API INTEGRATION TEST")
    print("=" * 80)
    
    all_passed = True
    
    # Test imports
    if not test_imports():
        print("\nImports failed - stopping tests")
        sys.exit(1)
    
    # Test detectors
    if not test_universal_detector_api():
        all_passed = False
    
    if not test_universal_detector_simple():
        all_passed = False
    
    # Final summary
    print("\n" + "=" * 80)
    if all_passed:
        print("SUCCESS: All tests passed! Universal detector is properly integrated!")
    else:
        print("WARNING: Some tests failed! Please review the output above.")
    print("=" * 80 + "\n")
    
    sys.exit(0 if all_passed else 1)
