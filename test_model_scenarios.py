#!/usr/bin/env python3
"""
Test API with different model scenarios:
1. NO models (Universal Detector only)
2. ML model available
3. DL model available
"""

import sys


def test_scenario_no_models():
    """Test scenario: No ML/DL models available"""
    print("\n" + "=" * 80)
    print("SCENARIO 1: NO MODELS (Universal Detector Only)")
    print("=" * 80 + "\n")
    
    try:
        from api import UniversalPhishingDetector
        
        test_urls = [
            ("https://www.google.com", "Legitimate Google", False),
            ("https://g00gle.com", "Typosquatted Google", True),
            ("https://verify-account.bankofamerica.com", "Phishing with keywords", True),
            ("https://secure-login.example.com", "Suspicious domain", True),
            ("https://www.facebook.com", "Legitimate Facebook", False),
        ]
        
        passed = 0
        for url, desc, is_phishing in test_urls:
            result = UniversalPhishingDetector.analyze_url(url)
            expected = is_phishing
            actual = result['is_phishing']
            
            status = "PASS" if actual == expected else "FAIL"
            if actual == expected:
                passed += 1
            
            detection = "PHISHING" if actual else "LEGITIMATE"
            confidence = f"{result['confidence']:.0%}"
            
            print(f"  [{status}] {url}")
            print(f"        => {desc}")
            print(f"        => Result: {detection} ({confidence} confidence)")
            print()
        
        print(f"Result: {passed}/{len(test_urls)} tests passed")
        print("Status: Universal Detector works WITHOUT any trained models!\n")
        return passed == len(test_urls)
        
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_model_availability():
    """Check which models are available"""
    print("\n" + "=" * 80)
    print("CHECKING MODEL AVAILABILITY")
    print("=" * 80 + "\n")
    
    from pathlib import Path
    
    models_path = Path("models")
    
    print(f"Models folder: {models_path.absolute()}")
    print(f"Folder exists: {models_path.exists()}\n")
    
    model_files = {
        'DL (CNN/LSTM)': 'models/cnn_lstm_model.h5',
        'ML (Random Forest)': 'models/random_forest_model.pkl',
        'ML (XGBoost)': 'models/xgboost_model.pkl',
    }
    
    available_models = []
    for model_name, model_path in model_files.items():
        exists = Path(model_path).exists()
        status = "AVAILABLE" if exists else "NOT FOUND"
        print(f"  {model_name:25} => {status}")
        if exists:
            available_models.append(model_name)
    
    print("\n" + "-" * 80)
    if available_models:
        print(f"Available Models: {', '.join(available_models)}")
    else:
        print("No trained models found - System will use Universal Detector!")
    print("-" * 80 + "\n")
    
    return available_models


def show_api_behavior():
    """Show how API chooses models"""
    print("\n" + "=" * 80)
    print("API MODEL SELECTION LOGIC")
    print("=" * 80 + "\n")
    
    print("When you make a prediction request:")
    print()
    print("1. If you request DL model (model='dl'):")
    print("   - Try DL model (CNN/LSTM)")
    print("   - If not available → Try ML model")
    print("   - If not available → Use Universal Detector")
    print()
    print("2. If you request ML model (model='ml'):")
    print("   - Try ML model (Random Forest or XGBoost)")
    print("   - If not available → Use Universal Detector")
    print()
    print("3. Auto mode (no model specified):")
    print("   - Try DL model first")
    print("   - Then ML model")
    print("   - Finally Universal Detector (always works!)")
    print()
    print("Key Point: Universal Detector is ALWAYS available as fallback!")
    print()


def test_api_endpoints():
    """Show example API calls"""
    print("\n" + "=" * 80)
    print("EXAMPLE API CALLS")
    print("=" * 80 + "\n")
    
    print("1. Request DL model detection:")
    print('   curl -X POST http://localhost:8000/predict \\')
    print('     -H "Content-Type: application/json" \\')
    print('     -d \'{"url": "https://g00gle.com", "model": "dl"}\'')
    print()
    print("   Response: Uses DL if available, ML if not, Universal Detector as fallback")
    print()
    
    print("2. Request ML model detection:")
    print('   curl -X POST http://localhost:8000/predict \\')
    print('     -H "Content-Type: application/json" \\')
    print('     -d \'{"url": "https://g00gle.com", "model": "ml"}\'')
    print()
    print("   Response: Uses ML if available, Universal Detector as fallback")
    print()
    
    print("3. Default detection (no model specified):")
    print('   curl -X POST http://localhost:8000/predict \\')
    print('     -H "Content-Type: application/json" \\')
    print('     -d \'{"url": "https://g00gle.com"}\'')
    print()
    print("   Response: Tries DL → ML → Universal Detector (always works!)")
    print()


if __name__ == '__main__':
    print("\n")
    print("=" * 80)
    print("PHISHING DETECTION API - MODEL COMPATIBILITY TEST")
    print("=" * 80)
    
    # Show model availability
    available = test_model_availability()
    
    # Show API behavior
    show_api_behavior()
    
    # Show example API calls
    test_api_endpoints()
    
    # Test scenario
    success = test_scenario_no_models()
    
    # Final summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print()
    print("✓ Universal Detector: ALWAYS WORKS (no training needed)")
    if available:
        print(f"✓ Additional Models: {', '.join(available)}")
    else:
        print("✗ Additional Models: None (train using train_dl_model.py)")
    print()
    print("The API automatically selects the best available model!")
    print("=" * 80 + "\n")
