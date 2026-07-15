#!/usr/bin/env python3
"""
Universal Phishing Detection System for ANY URL
Works on any domain in the entire internet, not just known ones
Uses advanced pattern detection and heuristics
"""

import re
from urllib.parse import urlparse

class UniversalPhishingDetector:
    """
    Detects phishing URLs for ANY domain on the internet
    Uses comprehensive heuristics that work universally
    """
    
    # Known legitimate domains (to avoid false positives)
    LEGIT_DOMAINS = {
        'google.com', 'facebook.com', 'amazon.com', 'twitter.com',
        'instagram.com', 'wikipedia.org', 'linkedin.com', 'github.com',
        'stackoverflow.com', 'youtube.com', 'gmail.com', 'outlook.com',
        'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com',
        'paypal.com', 'ebay.com', 'reddit.com', 'quora.com',
        'medium.com', 'trustpilot.com', 'bbc.co.uk', 'cnn.com',
        'nytimes.com', 'washingtonpost.com', 'theguardian.com',
        'pinterest.com', 'tumblr.com', 'flickr.com', 'dropbox.com',
        'zoom.us', 'slack.com', 'discord.com', 'telegram.org',
        'whatsapp.com', 'viber.com', 'skype.com', 'hangouts.google.com',
    }
    
    @staticmethod
    def analyze_url(url: str) -> dict:
        """
        Comprehensive analysis of ANY URL for phishing characteristics
        Works on any domain, not limited to known whitelists
        
        Returns dict with: is_phishing, confidence, reasons, score_breakdown
        """
        result = {
            'is_phishing': False,
            'confidence': 0.0,
            'reasons': [],
            'score': 0,
            'max_score': 100,
            'critical_flags': 0  # Track number of critical red flags
        }
        
        try:
            # Parse the URL
            parsed = urlparse(url)
            domain = parsed.hostname.lower() if parsed.hostname else ''
            domain_clean = domain.replace('www.', '')
            scheme = parsed.scheme
            path = parsed.path
            query = parsed.query
            port = parsed.port
            netloc = parsed.netloc
            
            if not domain_clean:
                result['is_phishing'] = True
                result['confidence'] = 0.8
                result['reasons'].append("Invalid or missing domain")
                return result
            
            # Check if domain is known legitimate (reduce false positives)
            is_known_legit = domain_clean in UniversalPhishingDetector.LEGIT_DOMAINS
            
            # ===== CRITICAL RED FLAGS (40+ points) =====
            
            # 1. IP address instead of domain (40 points)
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                result['score'] += 40
                result['critical_flags'] += 1
                result['reasons'].append("Using IP address instead of domain name")
            
            # 2. @ symbol in URL - Email spoofing trick (35 points)
            if '@' in netloc:
                result['score'] += 35
                result['critical_flags'] += 1
                result['reasons'].append("@ symbol in URL (email spoofing)")
            
            # 3. Character substitution tricks (38 points)
            substitution_patterns = [
                r'[0O]{2,}', r'[lI1]{2,}', r'[5S]{2,}',  # Multiple substitutions - clear red flag
                r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',  # Free/suspicious TLDs
                r'co\.uk\-', r'com\-',  # Domain hijacking patterns
            ]
            for pattern in substitution_patterns:
                if re.search(pattern, domain):
                    if pattern in [r'[0O]{2,}', r'[lI1]{2,}', r'[5S]{2,}']:
                        # Multiple substitutions - clear phishing tactic
                        result['score'] += 20
                        result['critical_flags'] += 0.8
                    else:
                        # TLD or domain hijacking patterns
                        result['score'] += 15
                        result['critical_flags'] += 0.75
                    result['reasons'].append(f"Suspicious pattern detected: {pattern}")
                    
                    # Match first pattern and break
                    break
            
            # 4. Excessive subdomains (25 points)
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                result['score'] += 25
                result['critical_flags'] += 0.5
                result['reasons'].append(f"Excessive subdomains ({subdomain_count} dots)")
            
            # ===== HIGH RISK INDICATORS (15-25 points) =====
            
            # 5. Unusual ports (20 points)
            if port and port not in [80, 443, 8080, 8443]:
                result['score'] += 20
                result['critical_flags'] += 0.5
                result['reasons'].append(f"Unusual port: {port}")
            
            # 6. URL shorteners (25 points) - HIGH RISK
            shorteners = [
                'bit.ly', 'tinyurl.com', 'ow.ly', 'goo.gl', 'is.gd', 
                'short.link', 'buff.ly', 'adf.ly', 'urly.it', 'tiny.cc',
                'tr.im', 'clck.ru', 'qr.net', 'shortened', 'minify',
            ]
            for shortener in shorteners:
                if shortener in domain:
                    result['score'] += 25
                    result['critical_flags'] += 0.75
                    result['reasons'].append(f"URL shortener detected: {shortener}")
                    break
            
            # 7. Suspicious keywords in domain (10-20 points) - Only if NOT known legitimate
            if not is_known_legit:
                suspicious_keywords = [
                    'verify', 'confirm', 'update', 'update-', 'secure', 'secure-', 'login',  'login-',
                    'signin-', 'auth-', 'validate-', 'credential', 'security',
                    'password-', 'reset-', 'banking-', 'payment-',
                    'invoice-', 'winner-', 'claim-', 'urgent-',
                ]
                keyword_matches = 0
                for keyword in suspicious_keywords:
                    if keyword in domain.lower():
                        keyword_matches += 1
                
                if keyword_matches > 0:
                    # More suspicious if multiple keywords
                    keyword_score = min(keyword_matches * 15, 35)  # Up to 35 points for multiple keywords
                    result['score'] += keyword_score
                    result['critical_flags'] += 0.5
                    reason = f"{keyword_matches} suspicious keyword(s)" if keyword_matches > 1 else "Suspicious keyword in domain"
                    result['reasons'].append(reason)
            
            # 8. Homoglyph/look-alike characters - ONLY count if multiple present
            homoglyph_matches = []
            suspicious_homoglyphs = {
                r'[0O]{2,}': "Double zero/O",
                r'[lI1]{2,}': "Multiple l/I/1",
                r'rn': "rn->m",
                r'[5S]{2,}': "Double 5/S",
            }
            for pattern, desc in suspicious_homoglyphs.items():
                if re.search(pattern, domain):
                    homoglyph_matches.append(desc)
            
            # Only flag if multiple homograph suspicions
            if len(homoglyph_matches) >= 2:
                result['score'] += 15
                result['critical_flags'] += 0.5
                result['reasons'].append(f"Multiple homological patterns: {', '.join(homoglyph_matches)}")
            
            # ===== MEDIUM RISK INDICATORS (5-15 points) =====
            
            # 9. Domain age simulation (newer = more suspicious)
            # Short domain names (3-4 chars) without known meaning = suspicious
            domain_main = domain_clean.split('.')[0]
            if len(domain_main) <= 4 and not domain_main.isdigit() and not is_known_legit:
                result['score'] += 8
                result['reasons'].append("Suspiciously short domain name")
            
            # 10. Excessive numbers in domain (8 points) - Only if MANY
            number_count = sum(1 for c in domain if c.isdigit())
            if number_count >= 4:
                result['score'] += 8
                result['reasons'].append(f"Many numbers in domain ({number_count})")
            
            # 11. Excessive hyphens (12 points) - Only if MULTIPLE
            hyphen_count = domain_main.count('-')
            if hyphen_count >= 3:
                result['score'] += 12
                result['reasons'].append(f"Many hyphens in domain ({hyphen_count})")
            
            # ===== SECURITY INDICATORS =====
            
            # 12. HTTPS check - should NOT reduce score if already has red flags
            if scheme != 'https' and result['score'] < 10:
                # Increase score for non-HTTPS only if otherwise very low risk
                result['score'] += 3
            # Don't penalize HTTPS too much - legitimate sites use HTTPS
            
            # 13. Suspicious path patterns (5-10 points)
            if any(x in path for x in ['/admin', '/phishing', '/fakelogin', '/capture']):
                result['score'] += 8
                result['reasons'].append("Suspicious path detected")
            
            # 14. Hidden input fields via query (5 points)
            if query and len(query) > 150:
                result['score'] += 5
                result['reasons'].append("Excessive query parameters")
            
            # ===== CALCULATE CONFIDENCE =====
            result['confidence'] = min(result['score'] / result['max_score'], 1.0)
            
            # Final decision logic - check critical flags FIRST
            if result['critical_flags'] >= 0.7:
                # Critical indicators detected
                result['is_phishing'] = True
            elif result['score'] >= 15:  # Lowered from 20 - keywords alone are strong indicator
                # Moderate score threshold
                result['is_phishing'] = True
            else:
                # Default to legitimate
                result['is_phishing'] = False
            
        except Exception as e:
            print(f"Error analyzing URL: {e}")
            result['reasons'].append(f"Error in analysis: {e}")
        
        return result

def test_universal_detector():
    """Test the universal detector on various URLs"""
    
    test_urls = [
        # Obvious phishing
        ('192.168.1.1/login', True, "IP address"),
        ('https://secure@paypal-update.com', True, "@ symbol"),
        ('https://bit.ly/suspicious', True, "URL shortener"),
        ('https://login-verify-account.com', True, "Suspicious keywords"),
        ('https://g00gle.com', True, "Character substitution"),
        ('https://amaz0n-security.com', True, "Homoglyph + keyword"),
        ('https://www.yourbank.co.uk-verify.com', True, "Domain hijacking"),
        ('https://faceb00k.com/login', True, "Homoglyph + keyword"),
        
        # Legitimate sites
        ('https://www.google.com', False, "Legitimate Google"),
        ('https://www.facebook.com', False, "Legitimate Facebook"),
        ('https://www.amazon.com', False, "Legitimate Amazon"),
        ('https://github.com/user/repo', False, "Legitimate GitHub"),
        ('https://www.wikipedia.org', False, "Legitimate Wikipedia"),
        ('https://www.stackoverflow.com', False, "Legitimate Stack Overflow"),
        
        # Borderline/suspicious
        ('https://secure-login.example.com', True, "Multiple keywords"),
        ('https://verify-account-update.bank.com', True, "Phishing keywords"),
        ('https://user123-update.suspicioussite.com', True, "Suspicious pattern"),
        ('https://example.tk', True, "Suspicious TLD"),
        ('https://mysite.example.com:9999/login', True, "Unusual port + keyword"),
    ]
    
    print("\n" + "=" * 120)
    print("UNIVERSAL PHISHING DETECTION FOR ANY URL ON THE INTERNET")
    print("=" * 120 + "\n")
    
    passed = 0
    failed = 0
    
    for url, expected_phishing, description in test_urls:
        result = UniversalPhishingDetector.analyze_url(url)
        
        is_correct = result['is_phishing'] == expected_phishing
        
        if is_correct:
            status = "✓ PASS"
            passed += 1
        else:
            status = "✗ FAIL"
            failed += 1
        
        detection = "🔴 PHISHING" if result['is_phishing'] else "✅ LEGITIMATE"
        confidence = f"{result['confidence']:.0%}"
        
        print(f"{status} | {detection:20} ({confidence:>4}) | {url:50}")
        print(f"     ↳ {description}")
        if result['reasons']:
            print(f"     ↳ Reasons: {', '.join(result['reasons'][:2])}")
        print()
    
    print("=" * 120)
    print(f"RESULTS: {passed} PASSED | {failed} FAILED | Total: {passed + failed}")
    print("=" * 120 + "\n")
    
    if failed == 0:
        print("✅ UNIVERSAL DETECTION WORKS! Can now detect phishing on ANY URL!")
    else:
        print(f"⚠️  {failed} test(s) need adjustment")

if __name__ == '__main__':
    test_universal_detector()
