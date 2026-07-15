"""
Simplified Phishing URL Detection API - Mock Version
Works immediately without requiring trained models
Perfect for testing while setting up Python environment
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, Dict, List
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from difflib import SequenceMatcher
import json
import logging
import re
import os
import math

import auth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Phishing URL Detection API",
    description="Intelligent phishing URL detection system",
    version="1.0.0"
)

# ensure user database exists
auth.init_db()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files (HTML, CSS, JS)
static_dir = os.path.dirname(os.path.abspath(__file__))
app.mount("/static", StaticFiles(directory=static_dir), name="static")


# Request/Response models
class URLInput(BaseModel):
    """URL input for prediction"""
    url: str = Field(..., description="URL to classify")
    model: Optional[str] = Field(default="ml", description="Model to use: 'ml' or 'dl'")

class BatchURLInput(BaseModel):
    """Batch URL input"""
    urls: List[str] = Field(..., description="List of URLs to classify")
    model: Optional[str] = Field(default="ml", description="Model to use")

class PredictionResponse(BaseModel):
    """Prediction response"""
    url: str
    prediction: int
    prediction_label: str
    confidence: float
    model_used: str
    timestamp: str
    features: Optional[Dict] = None

class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    mode: str

class StatsResponse(BaseModel):
    """Statistics response"""
    total_predictions: int
    phishing_detected: int
    legitimate_detected: int
    recent_scans_24h: int
    detection_rate: float


# URL Validation function
def validate_and_normalize_url(url: str) -> str:
    """
    Validate and normalize a URL to ensure it's a proper URL format.
    
    Args:
        url: Raw URL string from user input
        
    Returns:
        Normalized URL with protocol
        
    Raises:
        ValueError: If URL is invalid or incomplete
    """
    if not url or not isinstance(url, str):
        raise ValueError("URL cannot be empty")
    
    url = url.strip()
    
    if not url:
        raise ValueError("URL cannot be empty")
    
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Parse the URL
    try:
        parsed = urlparse(url)
    except Exception as e:
        raise ValueError(f"Invalid URL format: {str(e)}")
    
    hostname = parsed.hostname
    
    # Validate hostname
    if not hostname:
        raise ValueError("URL must contain a valid domain/hostname")

    # ── IPv4 address: bypass all domain-name checks ──
    _ipv4_re = re.compile(r'^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$')
    _m = _ipv4_re.match(hostname)
    if _m:
        if all(0 <= int(g) <= 255 for g in _m.groups()):
            return url  # Valid IPv4 URL — let the phishing detector handle it
        raise ValueError("Invalid IPv4 address in URL")
    
    # Must contain at least one dot (e.g., example.com)
    if '.' not in hostname:
        raise ValueError("Domain must contain at least one dot (e.g., example.com)")
    
    # Split hostname into parts
    parts = hostname.split('.')
    
    # Must have at least 2 parts (domain and TLD)
    if len(parts) < 2:
        raise ValueError("Invalid domain format")
    
    # Each part must be non-empty
    if any(not part for part in parts):
        raise ValueError("Invalid domain format")
    
    # Last part (TLD) must be at least 2 characters
    if len(parts[-1]) < 2:
        raise ValueError("Top-level domain (TLD) must be at least 2 characters")
    
    # Hostname should only contain alphanumeric characters and hyphens
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$', hostname):
        raise ValueError("Invalid characters in domain name")
    
    return url


# Simple URL Feature Analyzer
class SimplePhishingDetector:
    """Basic phishing detection without ML models"""
    
    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'secure', 'update', 'confirm', 'account',
        'bank', 'paypal', 'credential', 'password', 'signin'
    ]
    
    # Comprehensive list of popular/legitimate domains for typosquatting detection
    KNOWN_LEGITIMATE_DOMAINS = [
        # ── Search Engines ──
        'google.com', 'google.co.in', 'google.co.uk', 'google.de', 'google.fr', 'google.co.jp',
        'bing.com', 'yahoo.com', 'duckduckgo.com', 'baidu.com', 'yandex.com', 'yandex.ru',
        'ask.com', 'ecosia.org', 'startpage.com', 'wolframalpha.com',

        # ── Social Media ──
        'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'tiktok.com',
        'linkedin.com', 'reddit.com', 'pinterest.com', 'snapchat.com', 'discord.com',
        'tumblr.com', 'medium.com', 'quora.com', 'weibo.com', 'vk.com',
        'mastodon.social', 'threads.net', 'clubhouse.com', 'bluesky.social',

        # ── Video & Streaming ──
        'youtube.com', 'vimeo.com', 'twitch.tv', 'dailymotion.com',
        'netflix.com', 'spotify.com', 'hulu.com', 'disneyplus.com',
        'primevideo.com', 'hbomax.com', 'hbo.com', 'peacocktv.com',
        'paramountplus.com', 'appletv.com', 'crunchyroll.com', 'funimation.com',
        'tubi.com', 'pluto.tv', 'pandora.com', 'deezer.com',
        'soundcloud.com', 'tidal.com', 'iheartradio.com',

        # ── Communication & Messaging ──
        'gmail.com', 'outlook.com', 'yahoo.com', 'aol.com', 'mail.com',
        'protonmail.com', 'proton.me', 'zoho.com', 'fastmail.com', 'tutanota.com',
        'whatsapp.com', 'telegram.org', 'signal.org', 'skype.com', 'zoom.us',
        'slack.com', 'discord.com', 'messenger.com', 'viber.com', 'wechat.com',
        'webex.com', 'gotomeeting.com', 'ringcentral.com', 'mailchimp.com',
        'teams.microsoft.com', 'hangouts.google.com',

        # ── Tech Companies ──
        'microsoft.com', 'apple.com', 'amazon.com', 'meta.com',
        'ibm.com', 'oracle.com', 'intel.com', 'amd.com', 'nvidia.com',
        'samsung.com', 'sony.com', 'lg.com', 'dell.com', 'hp.com',
        'lenovo.com', 'asus.com', 'acer.com', 'toshiba.com', 'hitachi.com',
        'qualcomm.com', 'broadcom.com', 'cisco.com', 'juniper.com', 'vmware.com',
        'salesforce.com', 'sap.com', 'adobe.com', 'autodesk.com', 'intuit.com',
        'servicenow.com', 'workday.com', 'zendesk.com', 'hubspot.com',

        # ── Developer & Open Source ──
        'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com',
        'mozilla.org', 'python.org', 'nodejs.org', 'rust-lang.org',
        'golang.org', 'java.com', 'kotlinlang.org', 'swift.org',
        'docker.com', 'kubernetes.io', 'terraform.io', 'ansible.com',
        'elastic.co', 'grafana.com', 'jenkins.io', 'npmjs.com', 'pypi.org',
        'vuejs.org', 'angular.io', 'react.dev', 'svelte.dev', 'nextjs.org',
        'atlassian.com', 'jira.atlassian.com', 'confluence.atlassian.com', 'jetbrains.com',

        # ── Cloud & Hosting ──
        'aws.amazon.com', 'azure.microsoft.com', 'cloud.google.com',
        'digitalocean.com', 'cloudflare.com', 'fastly.com', 'netlify.com',
        'vercel.com', 'heroku.com', 'linode.com', 'vultr.com', 'ovh.com',
        'godaddy.com', 'namecheap.com', 'hostgator.com', 'bluehost.com',
        'siteground.com', 'dreamhost.com', 'wix.com', 'squarespace.com',
        'wordpress.com', 'wordpress.org', 'webflow.com',

        # ── Shopping & E-Commerce (Global) ──
        'amazon.com', 'amazon.co.uk', 'amazon.in', 'amazon.de', 'amazon.co.jp',
        'ebay.com', 'alibaba.com', 'aliexpress.com', 'shopify.com',
        'walmart.com', 'target.com', 'costco.com', 'bestbuy.com', 'homedepot.com',
        'lowes.com', 'kroger.com', 'cvs.com', 'walgreens.com', 'macys.com',
        'nordstrom.com', 'zara.com', 'hm.com', 'uniqlo.com', 'gap.com',
        'wish.com', 'etsy.com', 'newegg.com', 'overstock.com', 'wayfair.com',
        'chewy.com', 'zappos.com', 'adorama.com',

        # ── Shopping & E-Commerce (India) ──
        'flipkart.com', 'myntra.com', 'meesho.com', 'ajio.com', 'nykaa.com',
        'snapdeal.com', 'indiamart.com', 'bigbasket.com', 'jiomart.com',
        'swiggy.com', 'zomato.com', 'dunzo.com', 'blinkit.com',

        # ── Banking & Finance (Global) ──
        'paypal.com', 'stripe.com', 'square.com', 'visa.com', 'mastercard.com',
        'amex.com', 'americanexpress.com', 'discover.com', 'dinersclub.com',
        'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'capitalone.com',
        'citibank.com', 'citi.com', 'usbank.com', 'tdbank.com', 'pnc.com',
        'regions.com', 'truist.com', 'ally.com', 'synchrony.com',
        'hsbc.com', 'barclays.com', 'lloydsbank.com', 'natwest.com',
        'santander.com', 'deutschebank.com', 'commerzbank.com',
        'bnpparibas.com', 'societegenerale.com',
        'jpmorgan.com', 'morganstanley.com', 'goldmansachs.com', 'blackrock.com',
        'fidelity.com', 'schwab.com', 'vanguard.com', 'etrade.com', 'tdameritrade.com',
        'coinbase.com', 'binance.com', 'kraken.com', 'robinhood.com',
        'revolut.com', 'wise.com', 'monzo.com', 'n26.com', 'chime.com',
        'venmo.com', 'cashapp.com', 'zelle.com',

        # ── Banking & Finance (India) ──
        'sbi.co.in', 'onlinesbi.sbi', 'hdfcbank.com', 'icicibank.com', 'axisbank.com',
        'kotakbank.com', 'yesbank.in', 'indusind.com', 'idfcfirstbank.com',
        'federalbank.co.in', 'bankofbaroda.in', 'unionbankofindia.com',
        'canarabank.com', 'pnbindia.in', 'indianbank.in',
        'paytm.com', 'phonepe.com', 'mobikwik.com', 'freecharge.com',
        'billdesk.com', 'razorpay.com', 'cashfree.com',

        # ── Government & Official (India) ──
        'india.gov.in', 'mygov.in', 'uidai.gov.in', 'digilocker.gov.in',
        'irctc.co.in', 'epfindia.gov.in', 'incometax.gov.in',
        'gst.gov.in', 'sebi.gov.in', 'rbi.org.in', 'irdai.gov.in',
        'nic.in', 'passport.gov.in', 'mca.gov.in', 'nsdl.co.in',

        # ── Government & Official (USA) ──
        'irs.gov', 'ssa.gov', 'medicare.gov', 'usa.gov', 'whitehouse.gov',

        # ── News & Media (Global) ──
        'bbc.com', 'bbc.co.uk', 'cnn.com', 'reuters.com', 'apnews.com',
        'nytimes.com', 'washingtonpost.com', 'theguardian.com', 'telegraph.co.uk',
        'foxnews.com', 'nbcnews.com', 'cbsnews.com', 'bloomberg.com', 'forbes.com',
        'wsj.com', 'ft.com', 'economist.com', 'time.com', 'newsweek.com',
        'usatoday.com', 'npr.org', 'pbs.org', 'mashable.com', 'buzzfeed.com',
        'techcrunch.com', 'theverge.com', 'wired.com', 'engadget.com',
        'arstechnica.com', 'zdnet.com', 'cnet.com', 'pcmag.com', 'gizmodo.com',

        # ── News & Media (India) ──
        'ndtv.com', 'timesofindia.com', 'hindustantimes.com', 'thehindu.com',
        'livemint.com', 'economictimes.com', 'indiatoday.in', 'indianexpress.com',
        'scroll.in', 'thewire.in', 'deccanherald.com',

        # ── Productivity & Office ──
        'microsoft365.com', 'office.com', 'office365.com', 'onedrive.com',
        'drive.google.com', 'docs.google.com', 'sheets.google.com',
        'dropbox.com', 'box.com', 'icloud.com', 'notion.so',
        'asana.com', 'trello.com', 'monday.com', 'basecamp.com',
        'evernote.com', 'onenote.com', 'airtable.com', 'clickup.com',
        'figma.com', 'canva.com', 'miro.com', 'lucidchart.com',

        # ── Travel & Transportation ──
        'uber.com', 'lyft.com', 'ola.com',
        'airbnb.com', 'booking.com', 'expedia.com', 'hotels.com',
        'kayak.com', 'tripadvisor.com', 'agoda.com', 'trivago.com',
        'skyscanner.com', 'makemytrip.com', 'cleartrip.com', 'goibibo.com',
        'yatra.com', 'ixigo.com', 'irctc.co.in',
        'hertz.com', 'avis.com', 'enterprise.com',
        'delta.com', 'united.com', 'americanairlines.com',
        'britishairways.com', 'lufthansa.com', 'emirates.com', 'qatarairways.com',
        'indigo.com', 'airindia.com', 'vistara.com', 'airasia.com',

        # ── Food & Delivery ──
        'doordash.com', 'grubhub.com', 'ubereats.com', 'deliveroo.com',
        'dominos.com', 'mcdonalds.com', 'kfc.com', 'pizzahut.com', 'burgerking.com',
        'starbucks.com', 'subway.com', 'chipotle.com',

        # ── Gaming ──
        'steampowered.com', 'store.steampowered.com', 'epicgames.com',
        'ea.com', 'ubisoft.com', 'blizzard.com', 'battle.net',
        'roblox.com', 'minecraft.net', 'xbox.com', 'playstation.com',
        'nintendo.com', 'itch.io', 'gog.com',

        # ── Crypto & Blockchain ──
        'bitcoin.org', 'ethereum.org', 'coinbase.com', 'binance.com',
        'kraken.com', 'blockchain.com', 'metamask.io',

        # ── Healthcare ──
        'who.int', 'cdc.gov', 'nih.gov', 'webmd.com', 'mayoclinic.org',
        'healthline.com', 'practo.com', 'apollo247.com',

        # ── Education & Reference ──
        'wikipedia.org', 'wikimedia.org', 'wikihow.com', 'wikidata.org',
        'w3schools.com', 'mdn.mozilla.org', 'coursera.org', 'udemy.com',
        'edx.org', 'khanacademy.org', 'skillshare.com', 'udacity.com',
        'pluralsight.com', 'codecademy.com', 'freecodecamp.org',
        'geeksforgeeks.org', 'leetcode.com', 'hackerrank.com', 'codechef.com',
        'archive.org', 'scribd.com', 'academia.edu', 'researchgate.net',

        # ── Other Popular Destinations ──
        'github.io', 'github.com', 'npm.com', 'docker.com', 'kubernetes.io',
        'github.io', 'bitbucket.org',
    ]

    PROTECTED_BRAND_TOKENS = {
        'google', 'facebook', 'amazon', 'paypal', 'microsoft', 'apple', 'github',
        'youtube', 'netflix', 'spotify', 'bankofamerica', 'chase', 'wellsfargo',
        'capitalone', 'sbi', 'hdfc', 'icici', 'axisbank', 'twitter', 'instagram',
        'linkedin', 'reddit', 'snapchat', 'discord', 'telegram', 'whatsapp',
        'ebay', 'alibaba', 'walmart', 'shopify', 'flipkart', 'myntra',
        'visa', 'mastercard', 'citibank', 'barclays', 'hsbc',
        'coinbase', 'binance', 'stripe', 'zomato', 'swiggy', 'paytm', 'phonepe',
        'irctc', 'steam', 'roblox', 'adobe', 'salesforce', 'dropbox',
        'notion', 'slack', 'zoom', 'canva', 'figma', 'airbnb', 'booking',
        'expedia', 'tripadvisor', 'mcdonalds', 'starbucks', 'dominos',
        'nintendo', 'playstation', 'xbox', 'blizzard', 'epicgames',
        'blockchain', 'ethereum', 'bitcoin', 'robinhood', 'fidelity', 'schwab',
    }

    SUSPICIOUS_SUBDOMAIN_TOKENS = {
        'secure', 'login', 'verify', 'update', 'signin', 'auth', 'account', 'confirm', 'online'
    }

    HIGH_RISK_TLDS = {
        'tk': 90, 'ml': 85, 'ga': 85, 'cf': 85, 'gq': 85, 'xyz': 75,
        'click': 80, 'top': 70, 'work': 65, 'country': 65, 'stream': 70,
        'download': 75, 'review': 70, 'loan': 80, 'win': 75, 'bid': 70,
    }

    BLACKLISTED_HOSTS = {
        'malware.test', 'phishing.test', 'dangerous-site.example',
    }

    BLACKLISTED_KEYWORDS = {
        'free-gift', 'verify-now', 'reset-now', 'urgent-action', 'bank-verify',
        'gift-card', 'crypto-double', 'wallet-verify', 'account-suspend',
    }

    # TLD/SLD parts to exclude when extracting brand labels from domain names
    _COMMON_TLDS = frozenset({
        'com', 'net', 'org', 'edu', 'gov', 'io', 'co', 'in', 'uk', 'us', 'de',
        'fr', 'jp', 'au', 'cn', 'br', 'ru', 'tv', 'me', 'info', 'biz', 'int',
        'sbi', 'dev', 'app', 'ai', 'so', 'cloud', 'tech', 'digital', 'store',
        'online', 'site', 'web', 'blog', 'news', 'social', 'live', 'media',
        'mobi', 'pro', 'eu', 'ca', 'mx', 'es', 'it', 'pl', 'nl', 'se', 'no',
    })

    @classmethod
    def _known_primary_labels(cls) -> set:
        """Extract ALL meaningful brand labels from every part of every known domain."""
        labels = set()
        for domain in cls.KNOWN_LEGITIMATE_DOMAINS:
            for part in domain.split('.'):
                if part and part not in cls._COMMON_TLDS and len(part) >= 4:
                    labels.add(part)
        return labels

    @staticmethod
    def _edit_distance(a: str, b: str) -> int:
        """Damerau-Levenshtein distance: handles insert, delete, replace, transposition."""
        la, lb = len(a), len(b)
        # Fast-path: if length difference alone exceeds any useful threshold, skip
        if abs(la - lb) > 3:
            return abs(la - lb)
        d = [[0] * (lb + 1) for _ in range(la + 1)]
        for i in range(la + 1):
            d[i][0] = i
        for j in range(lb + 1):
            d[0][j] = j
        for i in range(1, la + 1):
            for j in range(1, lb + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                d[i][j] = min(
                    d[i - 1][j] + 1,       # deletion
                    d[i][j - 1] + 1,       # insertion
                    d[i - 1][j - 1] + cost # replacement
                )
                # Transposition of adjacent characters
                if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                    d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)
        return d[la][lb]

    @classmethod
    def _has_token_or_one_char_typo(cls, labels: set, token_set: set) -> bool:
        """Match exact tokens or one-edit typos (using Damerau-Levenshtein) for longer tokens."""
        if labels & token_set:
            return True
        for label in labels:
            for token in token_set:
                if len(token) >= 5 and label != token and cls._edit_distance(label, token) <= 1:
                    return True
        return False
    
    @staticmethod
    def _is_typosquatting(domain: str) -> bool:
        """
        Detect typosquatting using multiple methods:
        1. Character substitution tricks (0↔O, 1↔l, etc.)
        2. Similarity to known legitimate domains (>80%)
        3. Suspicious domain characteristics
        
        Returns True if typosquatting is detected.
        """
        domain_lower = domain.lower().replace('www.', '').split('/')[0]

        
        # ===== CHECK 1: SUSPICIOUS CHARACTER SUBSTITUTIONS =====
        suspicious_patterns = [
            r'g00gle|g0ogle', r'y0utube|youtube0', r'fac3book|facebook3|faceb0ok',
            r'tw1tter|twitte1|tw0tter', r'inst4gram|instagram4', r'amaz0n|amazo0n',
            r'gmai1|gmail1', r'paypa1|paypa\|', r'l1nkedin|linkedin1', r'r3ddit|reddit3'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain_lower):
                logger.warning(f"Suspicious character substitution detected in {domain}")
                return True
        
        # ===== CHECK 2: SIMILARITY TO KNOWN DOMAINS =====
        for legitimate_domain in SimplePhishingDetector.KNOWN_LEGITIMATE_DOMAINS:
            similarity = SequenceMatcher(None, domain_lower, legitimate_domain).ratio()
            if similarity > 0.80 and domain_lower != legitimate_domain:
                logger.warning(f"Typosquatting detected: {domain_lower} (~{similarity:.0%} to {legitimate_domain})")
                return True

        # ===== CHECK 3: TYPO ON MAIN DOMAIN LABEL =====
        domain_parts = domain_lower.split('.')
        domain_main = domain_parts[-2] if len(domain_parts) >= 2 else domain_parts[0]
        domain_tld = domain_parts[-1] if len(domain_parts) >= 2 else ''

        for legitimate_domain in SimplePhishingDetector.KNOWN_LEGITIMATE_DOMAINS:
            legit_parts = legitimate_domain.split('.')
            legit_main = legit_parts[-2] if len(legit_parts) >= 2 else legit_parts[0]
            legit_tld = legit_parts[-1] if len(legit_parts) >= 2 else ''

            # Allow edit-distance 2 for longer labels (≥9 chars), otherwise 1
            max_dist = 2 if len(legit_main) >= 9 else 1
            if (domain_tld == legit_tld and domain_main != legit_main
                    and SimplePhishingDetector._edit_distance(domain_main, legit_main) <= max_dist):
                logger.warning(f"Main-label typo: {domain_lower} resembles {legitimate_domain}")
                return True

        # ===== CHECK 4: TYPO IN ANY HOST LABEL vs ALL KNOWN BRAND LABELS =====
        # Catches: subdomain typos, cross-TLD typos, transpositions, and 2-char typos on long names.
        known_labels = SimplePhishingDetector._known_primary_labels()
        host_labels = [lbl for lbl in domain_parts[:-1] if lbl and lbl not in {'www'}]
        for label in host_labels:
            for known in known_labels:
                if len(known) < 5:
                    continue
                if label == known:
                    continue  # exact match label = the legitimate brand itself (safe sub-check)
                max_dist = 2 if len(known) >= 9 else 1
                if SimplePhishingDetector._edit_distance(label, known) <= max_dist:
                    logger.warning(f"Host label typo: {label!r} resembles {known!r} in {domain_lower}")
                    return True

        # ===== CHECK 5: BRAND TOKEN + RISKY SUBDOMAIN COMBINATION =====
        # Avoid false positives on valid multi-level domains by requiring
        # a risky token (login/verify/etc.) in subdomain labels.
        if len(domain_parts) >= 3:
            parent_label = domain_parts[-2]
            sub_labels = set(domain_parts[:-2])
            has_brand = bool(sub_labels & SimplePhishingDetector.PROTECTED_BRAND_TOKENS)
            has_risky_token = SimplePhishingDetector._has_token_or_one_char_typo(
                sub_labels,
                SimplePhishingDetector.SUSPICIOUS_SUBDOMAIN_TOKENS
            )
            if parent_label in {'bank', 'secure', 'login', 'verify', 'update'} and has_brand and has_risky_token:
                logger.warning(f"Brand token nested under generic parent domain: {domain_lower}")
                return True
        
        # ===== CHECK 6: EXCESSIVE HYPHENS =====
        main_domain = domain_parts[0] if domain_parts else ''
        if main_domain.count('-') > 2:
            logger.warning(f"Suspicious excessive hyphens in {domain}")
            return True
        
        return False
    
    @staticmethod
    def is_suspicious_url(url: str) -> tuple:
        """
        Advanced heuristic-based detection using pattern analysis
        Returns: (prediction, confidence)
        """
        score = 0
        url_lower = url.lower()
        known_safe_domains = set(SimplePhishingDetector.KNOWN_LEGITIMATE_DOMAINS)
        
        try:
            domain = url_lower.split('://')[1].split('/')[0].split(':')[0]
            domain_clean = domain.replace('www.', '')
            domain_parts = domain_clean.split('.')
            
            # Check for EXACT match with known safe domains
            is_exact_match = domain_clean in SimplePhishingDetector.KNOWN_LEGITIMATE_DOMAINS
            if is_exact_match and url.startswith('https://'):
                return (0, 0.05)  # Very safe - exact match via HTTPS
            
            # Check for typosquatting (similar but NOT exact match)
            if SimplePhishingDetector._is_typosquatting(domain):
                return (1, 0.95)  # High confidence phishing - typosquatting detected

            # Add risk only for brand + risky-token combinations.
            if len(domain_parts) >= 3:
                parent_label = domain_parts[-2]
                sub_labels = set(domain_parts[:-2])
                has_brand = bool(sub_labels & SimplePhishingDetector.PROTECTED_BRAND_TOKENS)
                has_risky_token = SimplePhishingDetector._has_token_or_one_char_typo(
                    sub_labels,
                    SimplePhishingDetector.SUSPICIOUS_SUBDOMAIN_TOKENS
                )
                if parent_label in {'bank', 'secure', 'login', 'verify', 'update'} and has_brand and has_risky_token:
                    score += 20
        except Exception as e:
            logger.debug(f"Error in domain check: {str(e)}")
        
        # ===== CRITICAL RED FLAGS (High Confidence Phishing) =====
        
        # 1. Spelling tricks/homoglyphs - explicit substitutions
        spelling_tricks = [
            'goog1e', 'g0ogle', 'googl3', 'paypa1', 'paypa|', 'amaz0n', 'amaz1n',
            'appl3', 'app1e', 'faceb0ok', 'faceb0k', 'twit3r', 'twit0r', 'redd1t',
            'fb-login', 'fb_login', 'gmai1', 'gmai.', 'yahho'
        ]
        if any(trick in url_lower for trick in spelling_tricks):
            return (1, 0.98)  # Almost certainly phishing
        
        # 2. IP address instead of domain — immediate high-confidence phishing flag
        if re.search(r'(?:^|[/@])(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)', url):
            logger.warning(f"IP address used as host: {url}")
            return (1, 0.97)  # Using an IP address is a strong phishing indicator
        
        # 3. @ symbol (email spoofing technique)
        if '@' in url:
            score += 35
        
        # 4. URL shorteners (HIGH RISK)
        shorteners = ['bit.ly', 'tinyurl', 'short.link', 'ow.ly', 'goo.gl', 'is.gd', 'buff.ly', 'adf.ly']
        if any(short in url_lower for short in shorteners):
            score += 30
        
        # ===== MEDIUM RISK INDICATORS =====
        
        # 5. Suspicious TLDs
        suspicious_tlds = [
            '.click', '.download', '.date', '.review', '.faith', '.loan',
            '.xyz', '.trade', '.stream', '.webcam', '.bid', '.win', '.tk',
            '.ml', '.ga', '.cf', '.pw', '.tk', '.gq'
        ]
        if any(url.endswith(tld) for tld in suspicious_tlds):
            score += 20
        
        # 6. Brand impersonation + suspicious path
        brand_keywords = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'bank', 'verify', 'update']
        phishing_paths = ['login', 'signin', 'verify', 'confirm', 'update', 'secure', 'account', 'password']
        
        for brand in brand_keywords:
            if brand in url_lower:
                for path in phishing_paths:
                    if path in url_lower and brand not in known_safe_domains:
                        score += 18
                        break
        
        # 7. Multiple suspicious keywords
        suspicious_keywords = [
            'login', 'signin', 'verify', 'confirm', 'account', 
            'password', 'update', 'secure', 'credential', 'click',
            'act', 'confirm-identity', 'validate', 'authenticate'
        ]
        keyword_count = sum(1 for kw in suspicious_keywords if kw in url_lower)
        if keyword_count >= 2:
            score += keyword_count * 6
        
        # 8. Excessive subdomains (obfuscation technique)
        if url.count('.') > 5:
            score += 15
        
        # 9. Hexadecimal encoding or unusual domains
        if re.search(r'%[0-9a-f]{2}', url_lower):  # URL encoded characters
            score += 12
        
        # 10. Port number (unusual/suspicious)
        port_match = re.search(r':(\d+)/', url)
        if port_match:
            port = int(port_match.group(1))
            if port not in [80, 443, 8000, 8080, 3000]:  # Common legitimate ports
                score += 10
        
        # 11. HTTP instead of HTTPS (on financial/login pages)
        if url.startswith('http://'):
            if any(keyword in url_lower for keyword in ['login', 'password', 'verify', 'paypal', 'bank', 'secure']):
                score += 15
        
        # 12. Gambling/betting sites
        gambling_keywords = ['betting', 'casino', 'poker', 'roulette', 'slots', 'jackpot', 'lottery']
        if any(gam in url_lower for gam in gambling_keywords):
            score += 20
        
        # 13. Unusually long URL (can hide phishing)
        if len(url) > 120:
            score += 10
        
        # 14. Hyphens in domain (often phishing)
        try:
            domain = url_lower.split('://')[1].split('/')[0]
            if '-' in domain and not any(safe in domain for safe in known_safe_domains):
                hyphen_count = domain.count('-')
                score += hyphen_count * 5
        except:
            pass
        
        # 15. Misspelled domains (missing letters)
        misspellings = ['goolge', 'googles', 'amzaon', 'amozon', 'facbook', 'facebok', 'twiter']
        if any(misspell in url_lower for misspell in misspellings):
            score += 25
        
        # 16. Unusual character patterns
        if re.search(r'[\.\-_]{2,}', domain if 'domain' in locals() else ''):  # Multiple consecutive special chars
            score += 8
        
        # ===== CALCULATE FINAL PREDICTION =====
        # Lower threshold for better detection
        # Score 15+ = likely phishing
        # Score 25+ = very likely phishing
        # Score 40+ = almost certainly phishing
        
        if score >= 40:
            confidence = 0.98
        elif score >= 25:
            confidence = min(0.85 + (score - 25) / 100, 0.96)
        elif score >= 15:
            confidence = min(0.65 + (score - 15) / 50, 0.85)
        else:
            confidence = score / 30 if score > 0 else 0.0
        
        # Adjusted threshold: >= 15 = phishing (was >= 20)
        prediction = 1 if score >= 15 else 0
        confidence = min(confidence, 0.99)
        
        return prediction, confidence
    
    @staticmethod
    def extract_features(url: str) -> Dict:
        """Extract basic + advanced threat intelligence features from URL."""
        parsed = urlparse(url)
        hostname = parsed.hostname.lower() if parsed.hostname else ''
        hostname_clean = hostname.replace('www.', '')
        query = parsed.query or ''
        url_lower = url.lower()

        def shannon_entropy(text: str) -> float:
            if not text:
                return 0.0
            freq = {}
            for ch in text:
                freq[ch] = freq.get(ch, 0) + 1
            entropy = 0.0
            length = len(text)
            for count in freq.values():
                p = count / length
                entropy -= p * math.log2(p)
            return entropy

        is_ip = bool(re.fullmatch(r'(\d{1,3}\.){3}\d{1,3}', hostname_clean))
        uses_https = parsed.scheme == 'https'

        # Approximate redirect intent from URL structure (no external network call).
        redirect_markers = ['redirect=', 'url=', 'next=', 'return=', 'target=', 'dest=']
        redirect_count = sum(url_lower.count(marker) for marker in redirect_markers)

        edges = []

        def add_edge(src: str, dst: str):
            if not src or not dst:
                return
            edge = (src, dst)
            if edge not in edges:
                edges.append(edge)

        # Build hierarchical domain chain: a.b.c.com -> b.c.com -> c.com -> com
        host_parts = [p for p in hostname_clean.split('.') if p]
        for i in range(len(host_parts) - 1):
            src = '.'.join(host_parts[i:])
            dst = '.'.join(host_parts[i + 1:])
            add_edge(src, dst)

        # Connect origin host to redirect destinations present in query params.
        parsed_query = parse_qs(query, keep_blank_values=True)
        for key in ['redirect', 'url', 'next', 'return', 'target', 'dest']:
            for value in parsed_query.get(key, []):
                target_host = ''
                try:
                    candidate = value if value.startswith(('http://', 'https://')) else f'https://{value.lstrip("/")}'
                    target_host = (urlparse(candidate).hostname or '').lower()
                except Exception:
                    target_host = ''
                if target_host:
                    add_edge(hostname_clean, target_host)

        # TLD risk scoring
        tld = hostname_clean.split('.')[-1] if '.' in hostname_clean else ''
        tld_risk_score = SimplePhishingDetector.HIGH_RISK_TLDS.get(tld, 10 if tld else 50)

        # Blacklist checks (offline static blocklist)
        blacklist_check = int(
            hostname_clean in SimplePhishingDetector.BLACKLISTED_HOSTS
            or any(kw in url_lower for kw in SimplePhishingDetector.BLACKLISTED_KEYWORDS)
        )

        # Brand impersonation detection via similarity to protected brands
        label_tokens = []
        for part in hostname_clean.split('.'):
            label_tokens.append(part)
            label_tokens.extend([x for x in re.split(r'[-_]', part) if x])

        brand_impersonation_detected = 0
        for token in label_tokens:
            if len(token) < 4:
                continue
            for brand in SimplePhishingDetector.PROTECTED_BRAND_TOKENS:
                if token == brand:
                    continue
                similarity = SequenceMatcher(None, token, brand).ratio()
                if similarity >= 0.86 or SimplePhishingDetector._edit_distance(token, brand) <= 1:
                    brand_impersonation_detected = 1
                    break
            if brand_impersonation_detected:
                break

        query_parameter_count = len(parse_qs(query, keep_blank_values=True))
        digits_count = sum(1 for c in url if c.isdigit())
        digit_ratio = round(digits_count / max(len(url), 1), 4)
        entropy = round(shannon_entropy(url_lower), 4)

        # Domain age estimate: heuristic fallback when WHOIS/cert transparency is unavailable.
        if hostname_clean in SimplePhishingDetector.KNOWN_LEGITIMATE_DOMAINS:
            domain_age_estimate_days = 3650
        elif blacklist_check or brand_impersonation_detected:
            domain_age_estimate_days = 30
        elif digit_ratio > 0.25 or entropy > 4.2:
            domain_age_estimate_days = 90
        else:
            domain_age_estimate_days = 365

        # SSL certificate validation approximation (offline): HTTPS + non-IP host + no punycode.
        ssl_certificate_valid = int(uses_https and not is_ip and 'xn--' not in hostname_clean)

        # Domain reputation score (0-100): higher is safer.
        reputation_penalty = 0
        reputation_penalty += tld_risk_score * 0.4
        reputation_penalty += 50 if blacklist_check else 0
        reputation_penalty += 25 if brand_impersonation_detected else 0
        reputation_penalty += min(redirect_count * 8, 24)
        reputation_penalty += 18 if ssl_certificate_valid == 0 else 0
        reputation_penalty += 12 if entropy > 4.2 else 0
        reputation_penalty += 10 if query_parameter_count >= 5 else 0
        reputation_penalty += 10 if digit_ratio >= 0.30 else 0
        domain_reputation_score = max(0, int(100 - reputation_penalty))

        return {
            'url_length': len(url),
            'dots_count': url.count('.'),
            'has_at_symbol': 1 if '@' in url else 0,
            'has_ip_address': 1 if is_ip else 0,
            'uses_https': 1 if uses_https else 0,
            'subdomain_count': max(hostname_clean.count('.') - 1, 0),
            'special_chars_count': len(re.findall(r'[!@#$%^&*()+=\[\]{};:,<>?/\\]', url)),
            'suspicious_keywords_count': sum(1 for kw in SimplePhishingDetector.SUSPICIOUS_KEYWORDS if kw in url_lower),
            'digits_count': digits_count,
            'hyphen_count': url.count('-'),
            'url_entropy': entropy,
            'brand_impersonation_detected': brand_impersonation_detected,
            'domain_age_estimate_days': domain_age_estimate_days,
            'tld_risk_score': tld_risk_score,
            'redirect_count': redirect_count,
            'blacklist_check': blacklist_check,
            'domain_reputation_score': domain_reputation_score,
            'ssl_certificate_valid': ssl_certificate_valid,
            'query_parameter_count': query_parameter_count,
            'digit_ratio': digit_ratio,
        }


# ===== UNIVERSAL PHISHING DETECTOR FOR ANY URL =====  
class UniversalPhishingDetector:
    """
    Detects phishing URLs for ANY domain on the internet
    Works on any domain, not limited to known whitelists
    """
    
    LEGIT_DOMAINS = {
        'google.com', 'facebook.com', 'amazon.com', 'twitter.com',
        'instagram.com', 'wikipedia.org', 'linkedin.com', 'github.com',
        'stackoverflow.com', 'youtube.com', 'gmail.com', 'outlook.com',
        'microsoft.com', 'apple.com', 'netflix.com', 'spotify.com',
        'paypal.com', 'ebay.com', 'reddit.com', 'quora.com',
        'medium.com', 'trustpilot.com', 'bbc.co.uk', 'cnn.com',
    }

    @staticmethod
    def _extract_labels(domain_clean: str) -> List[str]:
        """Extract meaningful domain labels excluding common TLD parts."""
        labels = []
        for part in domain_clean.split('.'):
            if part and part not in SimplePhishingDetector._COMMON_TLDS:
                labels.append(part)
                for token in re.split(r'[-_]', part):
                    if token and token not in SimplePhishingDetector._COMMON_TLDS:
                        labels.append(token)
        return labels

    @staticmethod
    def _detect_typosquatting_signal(domain_clean: str) -> Optional[str]:
        """Detect typo-based impersonation against known legitimate labels."""
        labels = UniversalPhishingDetector._extract_labels(domain_clean)
        known_labels = SimplePhishingDetector._known_primary_labels()

        for label in labels:
            if len(label) < 4:
                continue
            for known in known_labels:
                if label == known or len(known) < 4:
                    continue
                max_dist = 2 if len(known) >= 9 else 1
                if SimplePhishingDetector._edit_distance(label, known) <= max_dist:
                    return f"Typosquatting detected: '{label}' resembles '{known}'"
        return None

    @staticmethod
    def _detect_brand_similarity_signal(domain_clean: str) -> Optional[str]:
        """Detect high brand similarity even when edit distance checks are bypassed."""
        labels = UniversalPhishingDetector._extract_labels(domain_clean)

        best_score = 0.0
        best_pair = None
        for label in labels:
            if len(label) < 5:
                continue
            for brand in SimplePhishingDetector.PROTECTED_BRAND_TOKENS:
                if label == brand:
                    continue
                similarity = SequenceMatcher(None, label, brand).ratio()
                if similarity > best_score:
                    best_score = similarity
                    best_pair = (label, brand)

        if best_pair and best_score >= 0.86:
            return f"Brand similarity detected: '{best_pair[0]}' is {best_score:.0%} similar to '{best_pair[1]}'"
        return None

    @staticmethod
    def _detect_homograph_signal(url: str, domain_clean: str) -> Optional[str]:
        """Detect homograph attacks via punycode, unicode, and common confusables."""
        if 'xn--' in domain_clean:
            return "Homograph attack pattern: punycode domain (xn--)"

        if any(ord(ch) > 127 for ch in url):
            return "Homograph attack pattern: non-ASCII characters in URL"

        confusable_map = str.maketrans({
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'
        })
        normalized = domain_clean.translate(confusable_map)
        if normalized != domain_clean:
            for brand in SimplePhishingDetector.PROTECTED_BRAND_TOKENS:
                if brand in normalized and brand not in domain_clean:
                    return f"Homograph attack pattern: confusable characters mimic '{brand}'"

        return None
    
    @staticmethod
    def analyze_url(url: str) -> dict:
        """Analyze URL for phishing characteristics"""
        result = {
            'is_phishing': False,
            'confidence': 0.0,
            'reasons': [],
            'score': 0,
            'critical_flags': 0,
            'signals': []
        }
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.hostname.lower() if parsed_url.hostname else ''
            domain_clean = domain.replace('www.', '')
            netloc = parsed_url.netloc
            port = parsed_url.port
            path = parsed_url.path
            
            if not domain_clean:
                result['is_phishing'] = True
                result['confidence'] = 0.8
                return result

            advanced_features = SimplePhishingDetector.extract_features(url)
            
            is_known_legit = domain_clean in UniversalPhishingDetector.LEGIT_DOMAINS

            if not is_known_legit:
                homograph_reason = UniversalPhishingDetector._detect_homograph_signal(url, domain_clean)
                if homograph_reason:
                    result['score'] += 45
                    result['critical_flags'] += 0.9
                    result['signals'].append('Homograph Attack Detection')
                    result['reasons'].append(homograph_reason)

                typosquat_reason = UniversalPhishingDetector._detect_typosquatting_signal(domain_clean)
                if typosquat_reason:
                    result['score'] += 35
                    result['critical_flags'] += 0.7
                    result['signals'].append('Typosquatting Detection')
                    result['reasons'].append(typosquat_reason)

                brand_similarity_reason = UniversalPhishingDetector._detect_brand_similarity_signal(domain_clean)
                if brand_similarity_reason:
                    result['score'] += 28
                    result['critical_flags'] += 0.6
                    result['signals'].append('Brand Similarity Detection')
                    result['reasons'].append(brand_similarity_reason)
            
            # Critical red flags
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                result['score'] += 97
                result['critical_flags'] += 1
                result['reasons'].append("IP address used instead of domain name — strong phishing indicator")
            
            if '@' in netloc:
                result['score'] += 35
                result['critical_flags'] += 1
                result['reasons'].append("@ symbol in URL")
            
            # Character substitution
            for pattern in [r'[0O]{2,}', r'[lI1]{2,}', r'[5S]{2,}', r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$']:
                if re.search(pattern, domain):
                    result['score'] += 15
                    result['critical_flags'] += 0.7
                    result['reasons'].append(f"Suspicious pattern: {pattern}")
                    break
            
            # Suspicious keywords
            if not is_known_legit:
                keywords = ['verify', 'confirm', 'update', 'secure', 'login', 'security', 'password']
                keyword_matches = sum(1 for kw in keywords if kw in domain.lower())
                if keyword_matches > 0:
                    result['score'] += min(keyword_matches * 15, 35)
                    result['critical_flags'] += 0.5
                    result['reasons'].append(f"{keyword_matches} suspicious keyword(s)")
            
            # Unusual port
            if port and port not in [80, 443]:
                result['score'] += 20
                result['reasons'].append(f"Unusual port: {port}")

            # Advanced feature scoring
            if advanced_features['blacklist_check'] == 1:
                result['score'] += 60
                result['critical_flags'] += 1
                result['reasons'].append("Blacklist check matched known malicious indicator")

            if advanced_features['brand_impersonation_detected'] == 1:
                result['score'] += 25
                result['critical_flags'] += 0.6
                if 'Brand Similarity Detection' not in result['signals']:
                    result['signals'].append('Brand Similarity Detection')
                result['reasons'].append("Brand impersonation detected")

            if advanced_features['domain_age_estimate_days'] <= 90:
                result['score'] += 10
                result['reasons'].append("Domain age estimate indicates recently created domain")

            if advanced_features['tld_risk_score'] >= 70:
                result['score'] += 15
                result['reasons'].append(f"High-risk TLD score: {advanced_features['tld_risk_score']}")

            if advanced_features['redirect_count'] > 0:
                result['score'] += min(advanced_features['redirect_count'] * 8, 24)
                result['reasons'].append(f"Redirect-like parameters detected: {advanced_features['redirect_count']}")

            if advanced_features['domain_reputation_score'] < 40:
                result['score'] += 20
                result['critical_flags'] += 0.4
                result['reasons'].append(f"Low domain reputation score: {advanced_features['domain_reputation_score']}")

            if advanced_features['ssl_certificate_valid'] == 0:
                result['score'] += 10
                result['reasons'].append("SSL certificate validation failed or unavailable")

            if advanced_features['query_parameter_count'] >= 5:
                result['score'] += 8
                result['reasons'].append(f"High query parameter count: {advanced_features['query_parameter_count']}")

            if advanced_features['digit_ratio'] >= 0.30:
                result['score'] += 8
                result['reasons'].append(f"High digit ratio: {advanced_features['digit_ratio']:.2f}")

            if advanced_features['url_entropy'] >= 4.2:
                result['score'] += 10
                result['reasons'].append(f"High URL entropy: {advanced_features['url_entropy']:.2f}")
            
            result['confidence'] = min(result['score'] / 100.0, 1.0)
            
            # Final decision
            if result['critical_flags'] >= 0.7 or result['score'] >= 15:
                result['is_phishing'] = True

            # Keep signal list unique and deterministic for UI display
            result['signals'] = sorted(set(result['signals']))
                
        except Exception as e:
            logger.debug(f"Error in universal analysis: {e}")
        
        return result


# In-memory database for demo
class SimpleDatabase:
    """Simple in-memory database"""
    def __init__(self):
        self.predictions = []
        self.total = 0
        self.phishing = 0
        self.legitimate = 0
    
    def store_prediction(self, url: str, prediction: int, confidence: float, model: str):
        """Store a prediction"""
        self.predictions.append({
            'url': url,
            'prediction': prediction,
            'confidence': confidence,
            'model': model,
            'timestamp': datetime.now().isoformat()
        })
        self.total += 1
        if prediction == 1:
            self.phishing += 1
        else:
            self.legitimate += 1
    
    def get_stats(self):
        """Get statistics"""
        return {
            'total_predictions': self.total,
            'phishing_detected': self.phishing,
            'legitimate_detected': self.legitimate,
            'recent_scans_24h': len(self.predictions[-100:]),
            'detection_rate': (self.phishing / self.total * 100) if self.total > 0 else 0
        }


# Initialize detector and database
detector = SimplePhishingDetector()
db = SimpleDatabase()

# Routes
@app.get("/", tags=["Info"])
async def root():
    """API information"""
    return {
        "message": "Phishing URL Detection API",
        "version": "1.0.0",
        "mode": "MOCK (No ML Models Required)",
        "endpoints": {
            "health": "/health",
            "predict": "/predict",
            "batch_predict": "/batch_predict",
            "stats": "/stats",
            "history": "/history"
        }
    }

# ---------------------------------------------------
# AUTHENTICATION ENDPOINTS
# ---------------------------------------------------

class AuthRequest(BaseModel):
    username: str
    password: str

class ForgotPasswordRequest(BaseModel):
    username: str

@app.get('/')
def root():
    """Redirect to login page"""
    return {"message": "API running. Visit /static/login.html in browser or use /predict endpoint"}

@app.post('/register', tags=['Authentication'])
def register(req: AuthRequest):
    """Register a new user"""
    success, msg = auth.register_user(req.username, req.password)
    if success:
        return {'status': 'ok', 'message': msg}
    raise HTTPException(status_code=400, detail=msg)

@app.post('/login', tags=['Authentication'])
def login(req: AuthRequest):
    """Authenticate a user"""
    if auth.verify_user(req.username, req.password):
        return {'status': 'ok'}
    raise HTTPException(status_code=401, detail='Invalid credentials')


@app.post('/forgot-password', tags=['Authentication'])
def forgot_password(req: ForgotPasswordRequest):
    """Send password reset message (mock)."""
    username = req.username.strip() if req.username else ''
    if not username:
        raise HTTPException(status_code=400, detail='Username is required')

    message = auth.send_password_reset_message(username)
    return {'status': 'ok', 'message': message}



@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Check API health"""
    return HealthResponse(
        status="healthy",
        version="1.0.0",
        mode="MOCK - Using heuristic detection"
    )

@app.post("/predict", response_model=PredictionResponse, tags=["Predictions"])
async def predict(input_data: URLInput):
    """
    Predict if a URL is phishing or legitimate
    
    Args:
        input_data: URL to classify
    
    Returns:
        Prediction result with confidence score
    """
    try:
        # Validate and normalize URL
        try:
            url = validate_and_normalize_url(input_data.url)
        except ValueError as e:
            logger.error(f"URL validation failed: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Invalid URL: {str(e)}")
        
        logger.info(f"Processing URL: {url}")
        
        # Priority 1: Universal Detector (works for ANY URL)
        universal_analysis = UniversalPhishingDetector.analyze_url(url)
        if universal_analysis['is_phishing']:
            logger.warning(f"Phishing detected by universal detector for {url}")
            db.store_prediction(url, 1, universal_analysis['confidence'], "universal")
            
            return PredictionResponse(
                url=url,
                prediction=1,
                prediction_label="Phishing",
                confidence=universal_analysis['confidence'],
                model_used="Universal Detector (Multi-Method)",
                timestamp=datetime.now().isoformat(),
                features={
                    "attack_detection_modules": ", ".join(universal_analysis.get('signals', [])),
                    "detection_reasons": universal_analysis['reasons'][:3],
                    **detector.extract_features(url)
                }
            )
        
        # Priority 2: Fallback to Heuristic Detector for more analysis
        prediction, confidence = detector.is_suspicious_url(url)
        features = detector.extract_features(url)
        
        model_used = "Universal Detector + Heuristic" if universal_analysis['score'] > 0 else "Heuristic Detection"
        
        # Store in database
        db.store_prediction(url, prediction, confidence, model_used)
        
        logger.info(f"Prediction for {url}: {prediction} (confidence: {confidence:.4f}, model: {model_used})")
        
        return PredictionResponse(
            url=url,
            prediction=prediction,
            prediction_label="Phishing" if prediction == 1 else "Legitimate",
            confidence=confidence,
            model_used=model_used,
            timestamp=datetime.now().isoformat(),
            features=features
        )
    
    except Exception as e:
        logger.error(f"Error in prediction: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/batch_predict", tags=["Predictions"])
async def batch_predict(input_data: BatchURLInput):
    """
    Predict multiple URLs in batch
    
    Args:
        input_data: List of URLs to classify
    
    Returns:
        List of predictions
    """
    try:
        results = []
        
        for raw_url in input_data.urls:
            try:
                # Validate and normalize URL
                url = validate_and_normalize_url(raw_url)

                # Universal detector first for better unseen URL coverage
                universal_analysis = UniversalPhishingDetector.analyze_url(url)
                if universal_analysis['is_phishing']:
                    results.append({
                        "url": url,
                        "prediction": 1,
                        "prediction_label": "Phishing",
                        "confidence": float(universal_analysis['confidence']),
                        "model_used": "Universal Detector (Multi-Method)",
                    })
                    db.store_prediction(url, 1, universal_analysis['confidence'], "universal")
                    continue
                
                prediction, confidence = detector.is_suspicious_url(url)
                
                results.append({
                    "url": url,
                    "prediction": int(prediction),
                    "prediction_label": "Phishing" if prediction == 1 else "Legitimate",
                    "confidence": float(confidence),
                    "model_used": "Heuristic Detection"
                })
                
                db.store_prediction(url, prediction, confidence, "heuristic")
            except ValueError as e:
                logger.warning(f"Skipping invalid URL '{raw_url}': {str(e)}")
                results.append({
                    "url": raw_url,
                    "error": f"Invalid URL: {str(e)}"
                })
            except Exception as e:
                logger.warning(f"Error processing {raw_url}: {str(e)}")
                continue
        
        return {"results": results, "total": len(results)}
    
    except Exception as e:
        logger.error(f"Error in batch prediction: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/stats", response_model=StatsResponse, tags=["Statistics"])
async def get_stats():
    """Get detection statistics"""
    try:
        stats = db.get_stats()
        return StatsResponse(**stats)
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving statistics")

@app.get("/history", tags=["History"])
async def get_history(limit: int = 100):
    """Get prediction history"""
    try:
        history = db.predictions[-limit:]
        return {"history": history, "total": len(history)}
    except Exception as e:
        logger.error(f"Error getting history: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving history")

# Error handler
@app.exception_handler(Exception)
async def exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return {"detail": "Internal server error"}


if __name__ == "__main__":
    import uvicorn
    logger.info("Starting Phishing URL Detection API (MOCK MODE)...")
    logger.info("Available at http://localhost:8000")
    logger.info("API documentation at http://localhost:8000/docs")
    logger.info("NOTE: Using heuristic detection - no ML models required!")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
