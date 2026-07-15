"""
Feature Engineering Module for Phishing URL Detection
Extracts 30+ features from URLs for machine learning models
"""

import re
import json
import logging
import socket
import whois
import dns.resolver
import requests
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
from datetime import datetime
import numpy as np
from difflib import SequenceMatcher

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class URLFeatureExtractor:
    """
    Extract comprehensive features from URLs for phishing detection
    """
    
    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'secure', 'update', 'confirm', 'account',
        'bank', 'paypal', 'credential', 'password', 'signin'
    ]
    
    # Known legitimate domains (for typosquatting detection)
    KNOWN_LEGITIMATE_DOMAINS = [
        'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'wikipedia.org',
        'twitter.com', 'linkedin.com', 'reddit.com', 'instagram.com', 'github.com',
        'stackoverflow.com', 'gmail.com', 'outlook.com', 'yahoo.com', 'apple.com',
        'microsoft.com', 'netflix.com', 'paypal.com', 'ebay.com', 'alibaba.com',
        'dropbox.com', 'slack.com', 'discord.com', 'telegram.org', 'whatsapp.com',
        'uber.com', 'airbnb.com', 'spotify.com', 'twitch.tv', 'pinterest.com',
        'snapchat.com', 'tiktok.com', 'nextjs.org', 'react.dev', 'nodejs.org'
    ]
    
    def __init__(self, timeout=2):
        """Initialize with request timeout (reduced from 5 to 2 seconds)"""
        self.timeout = timeout
        
    def extract_all_features(self, url):
        """
        Extract all 30+ features from a URL
        Returns dictionary with feature names and values
        """
        features = {}
        
        try:
            # URL-based features (12 features)
            features.update(self._extract_url_features(url))
            
            # Domain-based features (8 features)
            features.update(self._extract_domain_features(url))
            
            # Content-based features (10+ features)
            features.update(self._extract_content_features(url))
            
        except Exception as e:
            logger.error(f"Error extracting features for {url}: {str(e)}")
            # Return default features on error
            features = self._get_default_features()
            
        return features
    
    def _extract_url_features(self, url):
        """Extract URL-based features"""
        features = {}
        
        # 1. URL length
        features['url_length'] = len(url)
        
        # 2. Number of dots
        features['dots_count'] = url.count('.')
        
        # 3. Number of special characters
        special_chars = len(re.findall(r'[!@#$%^&*()_+=\[\]{};:,<>?/\-]', url))
        features['special_chars_count'] = special_chars
        
        # 4. Presence of @ symbol
        features['has_at_symbol'] = 1 if '@' in url else 0
        
        # 5. Presence of IP address
        features['has_ip_address'] = self._has_ip_address(url)
        
        # 6. HTTPS usage
        features['uses_https'] = 1 if url.startswith('https') else 0
        
        # 7. Number of subdomains
        parsed = urlparse(url)
        subdomains = parsed.netloc.count('.')
        features['subdomain_count'] = subdomains
        
        # 8. Suspicious keywords count
        url_lower = url.lower()
        suspicious_count = sum(1 for keyword in self.SUSPICIOUS_KEYWORDS 
                               if keyword in url_lower)
        features['suspicious_keywords_count'] = suspicious_count
        
        # 9. Count of digits
        features['digits_count'] = sum(1 for char in url if char.isdigit())
        
        # 10. Hyphen count
        features['hyphen_count'] = url.count('-')
        
        # 11. Redirection count (//)
        features['redirection_count'] = url.count('//')
        
        # 12. Query parameter count
        parsed = urlparse(url)
        query_params = len(parse_qs(parsed.query))
        features['query_param_count'] = query_params
        
        return features
    
    def _extract_domain_features(self, url):
        """Extract domain-based features"""
        features = {}
        parsed = urlparse(url)
        domain = parsed.netloc
        
        try:
            # 13. Domain length
            features['domain_length'] = len(domain)
            
            # 14. Domain age (in days)
            domain_age = self._get_domain_age(domain)
            features['domain_age'] = domain_age if domain_age else -1
            
            # 15. Expiry duration (in days)
            expiry_days = self._get_domain_expiry(domain)
            features['expiry_duration'] = expiry_days if expiry_days else -1
            
            # 16. DNS record existence
            features['dns_exists'] = self._has_dns_record(domain)
            
            # 17. SSL certificate validity
            features['has_ssl'] = self._has_valid_ssl(domain)
            
            # 18. Port number (non-standard ports more suspicious)
            port = parsed.port if parsed.port else (443 if parsed.scheme == 'https' else 80)
            features['port'] = port
            
            # 19. Non-standard port flag
            features['is_non_standard_port'] = 1 if port not in [80, 443] else 0
            
            # 20. Typosquatting detection (similarity to known legitimate domains)
            typosquatting_score = self._get_typosquatting_score(domain)
            features['typosquatting_score'] = typosquatting_score
            
            # 21. URL path length
            features['path_length'] = len(parsed.path)
            
        except Exception as e:
            logger.warning(f"Error extracting domain features: {str(e)}")
            features['domain_age'] = -1
            features['expiry_duration'] = -1
            features['dns_exists'] = 0
            features['has_ssl'] = 0
            features['port'] = 0
            features['is_non_standard_port'] = 0
            features['path_length'] = 0
            features['domain_length'] = 0
        
        return features
    
    def _is_unreachable_url(self, url):
        """Check if URL is obviously unreachable"""
        # Skip private IP ranges
        if re.search(r'192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])|127\.0\.0\.1|localhost', url):
            return True
        # Skip obviously fake domains
        if re.search(r'paypal-|login-verify|amazon-account-verify|\.click$|\.co$', url, re.IGNORECASE):
            return True
        return False
    
    def _extract_content_features(self, url):
        """Extract content-based features from webpage"""
        features = {}
        
        # Skip content extraction for obviously unreachable URLs
        if self._is_unreachable_url(url):
            return self._get_content_defaults()
        
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, timeout=self.timeout, headers=headers, verify=False)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # 21. iFrame detection
                features['has_iframe'] = 1 if soup.find('iframe') else 0
                
                # 22. Hidden forms count
                hidden_forms = len(soup.find_all('form', {'style': re.compile('display:none|visibility:hidden')}))
                features['hidden_forms_count'] = hidden_forms
                
                # 23. External favicon
                favicon = soup.find('link', {'rel': 'icon'})
                features['has_external_favicon'] = 1 if favicon and 'href' in favicon.attrs else 0
                
                # 24. Form action mismatch
                forms = soup.find_all('form')
                form_mismatch = 0
                for form in forms:
                    if 'action' in form.attrs:
                        action_domain = urlparse(form['action']).netloc
                        page_domain = urlparse(url).netloc
                        if action_domain and action_domain != page_domain:
                            form_mismatch += 1
                features['form_action_mismatch_count'] = form_mismatch
                
                # 25. JavaScript count (potential obfuscation)
                script_tags = len(soup.find_all('script'))
                features['script_count'] = script_tags
                
                # 26. Obfuscated JavaScript detection
                obfuscated_js = 0
                for script in soup.find_all('script'):
                    if script.string:
                        if re.search(r'eval|unescape|String.fromCharCode', script.string):
                            obfuscated_js += 1
                features['obfuscated_js_count'] = obfuscated_js
                
                # 27. External links count
                external_links = 0
                for link in soup.find_all('a', {'href': True}):
                    link_domain = urlparse(link['href']).netloc
                    page_domain = urlparse(url).netloc
                    if link_domain and link_domain != page_domain:
                        external_links += 1
                features['external_links_count'] = external_links
                
                # 28. Meta redirect
                features['has_meta_redirect'] = 1 if soup.find('meta', {'http-equiv': 'refresh'}) else 0
                
                # 29. Page title length
                title = soup.find('title')
                features['title_length'] = len(title.string) if title and title.string else 0
                
                # 30. Input fields count
                input_fields = len(soup.find_all('input'))
                features['input_fields_count'] = input_fields
                
            else:
                # If page not accessible, use default values
                features.update(self._get_content_defaults())
                
        except Exception as e:
            logger.warning(f"Error extracting content features for {url}: {str(e)}")
            features.update(self._get_content_defaults())
        
        return features
    
    @staticmethod
    def _has_ip_address(url):
        """Check if URL contains IP address instead of domain"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return 1 if re.search(ip_pattern, url) else 0
    
    def _get_typosquatting_score(self, domain):
        """
        Detect typosquatting by checking similarity to known legitimate domains.
        Returns a score from 0 to 1 where 1 indicates strong similarity to a known domain.
        """
        domain_lower = domain.lower().replace('www.', '')
        
        max_similarity = 0
        for legitimate in self.KNOWN_LEGITIMATE_DOMAINS:
            # Use SequenceMatcher to compare domain names
            similarity = SequenceMatcher(None, domain_lower, legitimate).ratio()
            max_similarity = max(max_similarity, similarity)
        
        # Return score: if very similar to a known domain but not exact match, it's suspicious
        # Threshold: 0.8 similarity but not exactly the same = likely typosquatting
        if max_similarity > 0.8 and domain_lower not in self.KNOWN_LEGITIMATE_DOMAINS:
            return max_similarity
        return 0
    
    @staticmethod
    def _get_domain_age(domain):
        """Get domain age in days using WHOIS"""
        try:
            w = whois.whois(domain)
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                age = (datetime.now() - creation_date).days
                return max(0, age)
        except Exception as e:
            logger.debug(f"Could not get domain age for {domain}: {str(e)}")
        return None
    
    @staticmethod
    def _get_domain_expiry(domain):
        """Get domain expiry in days using WHOIS"""
        import socket
        try:
            # Set socket timeout to prevent long hangs
            socket.setdefaulttimeout(1)
            w = whois.whois(domain)
            if w.expiration_date:
                expiry_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                days_left = (expiry_date - datetime.now()).days
                return max(0, days_left)
        except (socket.timeout, TimeoutError):
            logger.debug(f"Timeout getting domain expiry for {domain}")
            return None
        except Exception as e:
            logger.debug(f"Could not get domain expiry for {domain}: {str(e)[:50]}")
        finally:
            socket.setdefaulttimeout(None)
        return None
    
    @staticmethod
    def _has_dns_record(domain):
        """Check if DNS record exists"""
        import socket
        try:
            socket.setdefaulttimeout(1)
            dns.resolver.resolve(domain, 'A')
            return 1
        except (socket.timeout, dns.exception.Timeout):
            logger.debug(f"Timeout checking DNS for {domain}")
            return 0
        except Exception:
            return 0
        finally:
            socket.setdefaulttimeout(None)
    
    @staticmethod
    def _has_valid_ssl(domain):
        """Check if valid SSL certificate exists"""
        import socket
        try:
            socket.setdefaulttimeout(2)
            context = requests.packages.urllib3.util.ssl_.create_urllib3_context()
            requests.head(f"https://{domain}", timeout=2, verify=context)
            return 1
        except (socket.timeout, requests.exceptions.Timeout, requests.exceptions.ConnectTimeout):
            return 0
        except Exception:
            return 0
        finally:
            socket.setdefaulttimeout(None)
    
    @staticmethod
    def _get_content_defaults():
        """Get default content features when page is not accessible"""
        return {
            'has_iframe': 0,
            'hidden_forms_count': 0,
            'has_external_favicon': 0,
            'form_action_mismatch_count': 0,
            'script_count': 0,
            'obfuscated_js_count': 0,
            'external_links_count': 0,
            'has_meta_redirect': 0,
            'title_length': 0,
            'input_fields_count': 0
        }
    
    @staticmethod
    def _get_default_features():
        """Get all default features (used on error)"""
        defaults = {
            'url_length': 0,
            'dots_count': 0,
            'special_chars_count': 0,
            'has_at_symbol': 0,
            'has_ip_address': 0,
            'uses_https': 0,
            'subdomain_count': 0,
            'suspicious_keywords_count': 0,
            'digits_count': 0,
            'hyphen_count': 0,
            'redirection_count': 0,
            'query_param_count': 0,
            'domain_length': 0,
            'domain_age': -1,
            'expiry_duration': -1,
            'dns_exists': 0,
            'has_ssl': 0,
            'port': 0,
            'is_non_standard_port': 0,
            'typosquatting_score': 0,
            'path_length': 0
        }
        defaults.update(URLFeatureExtractor._get_content_defaults())
        return defaults


if __name__ == "__main__":
    # Example usage
    extractor = URLFeatureExtractor()
    test_url = "https://www.google.com"
    features = extractor.extract_all_features(test_url)
    print(f"Extracted {len(features)} features for {test_url}")
    print(json.dumps(features, indent=2))
