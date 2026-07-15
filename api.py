"""
FastAPI Backend for Phishing URL Detection System
Provides REST API endpoints for real-time URL scanning
"""

import pickle
import logging
import time
import json
import re
from datetime import datetime
from typing import Optional, Dict, List
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from difflib import SequenceMatcher
import math
import numpy as np
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow.keras.preprocessing.sequence import pad_sequences

from fastapi import FastAPI, HTTPException, File, UploadFile, BackgroundTasks
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn
import os

import auth

from feature_engineering import URLFeatureExtractor
from database import PhishingDetectionDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Phishing URL Detection API",
    description="Real-time intelligent phishing URL detection system",
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
    models_loaded: Dict[str, bool]
    database_status: bool

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


# Typosquatting Detection
# Expanded list of popular/legitimate domains
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
    'lenovo.com', 'asus.com', 'acer.com', 'toshiba.com',
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
    'chewy.com', 'zappos.com',

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
    'confluence.atlassian.com', 'jira.atlassian.com',

    # ── Travel & Transportation ──
    'uber.com', 'lyft.com', 'ola.com',
    'airbnb.com', 'booking.com', 'expedia.com', 'hotels.com',
    'kayak.com', 'tripadvisor.com', 'agoda.com', 'trivago.com',
    'skyscanner.com', 'makemytrip.com', 'cleartrip.com', 'goibibo.com',
    'yatra.com', 'ixigo.com',
    'hertz.com', 'avis.com', 'enterprise.com',
    'delta.com', 'united.com', 'americanairlines.com',
    'britishairways.com', 'lufthansa.com', 'emirates.com', 'qatarairways.com',
    'airindia.com', 'vistara.com', 'airasia.com',

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
    'duolingo.com', 'khanacademy.org',
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

# TLD/SLD parts to exclude when extracting brand labels
_COMMON_TLDS = frozenset({
    'com', 'net', 'org', 'edu', 'gov', 'io', 'co', 'in', 'uk', 'us', 'de',
    'fr', 'jp', 'au', 'cn', 'br', 'ru', 'tv', 'me', 'info', 'biz', 'int',
    'sbi', 'dev', 'app', 'ai', 'so', 'cloud', 'tech', 'digital', 'store',
    'online', 'site', 'web', 'blog', 'news', 'mobi', 'pro', 'eu', 'ca',
    'mx', 'es', 'it', 'pl', 'nl', 'se', 'no',
})

def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein distance: handles insert, delete, replace, and transposition."""
    la, lb = len(a), len(b)
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
                d[i - 1][j] + 1,
                d[i][j - 1] + 1,
                d[i - 1][j - 1] + cost
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)
    return d[la][lb]

# Keep backwards-compatible alias used by existing code
def is_edit_distance_leq_one(a: str, b: str) -> bool:
    return edit_distance(a, b) <= 1

def has_token_or_one_char_typo(labels: set, token_set: set) -> bool:
    """Match exact tokens or one-edit typos (Damerau-Levenshtein) for longer tokens."""
    if labels & token_set:
        return True
    for label in labels:
        for token in token_set:
            if len(token) >= 5 and label != token and edit_distance(label, token) <= 1:
                return True
    return False

def known_primary_labels() -> set:
    """Extract ALL meaningful brand labels from every part of every known domain."""
    labels = set()
    for domain in KNOWN_LEGITIMATE_DOMAINS:
        for part in domain.split('.'):
            if part and part not in _COMMON_TLDS and len(part) >= 4:
                labels.add(part)
    return labels

def extract_url_intel_features(url: str) -> Dict:
    """Compute advanced URL intelligence signals (offline heuristic version)."""
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

    redirect_markers = ['redirect=', 'url=', 'next=', 'return=', 'target=', 'dest=']
    redirect_count = sum(url_lower.count(marker) for marker in redirect_markers)

    tld = hostname_clean.split('.')[-1] if '.' in hostname_clean else ''
    tld_risk_score = HIGH_RISK_TLDS.get(tld, 10 if tld else 50)

    blacklist_check = int(
        hostname_clean in BLACKLISTED_HOSTS
        or any(kw in url_lower for kw in BLACKLISTED_KEYWORDS)
    )

    label_tokens = []
    for part in hostname_clean.split('.'):
        label_tokens.append(part)
        label_tokens.extend([x for x in re.split(r'[-_]', part) if x])

    brand_impersonation_detected = 0
    for token in label_tokens:
        if len(token) < 4:
            continue
        for brand in PROTECTED_BRAND_TOKENS:
            if token == brand:
                continue
            similarity = SequenceMatcher(None, token, brand).ratio()
            if similarity >= 0.86 or edit_distance(token, brand) <= 1:
                brand_impersonation_detected = 1
                break
        if brand_impersonation_detected:
            break

    query_parameter_count = len(parse_qs(query, keep_blank_values=True))
    digits_count = sum(1 for c in url if c.isdigit())
    digit_ratio = round(digits_count / max(len(url), 1), 4)
    entropy = round(shannon_entropy(url_lower), 4)

    if hostname_clean in KNOWN_LEGITIMATE_DOMAINS:
        domain_age_estimate_days = 3650
    elif blacklist_check or brand_impersonation_detected:
        domain_age_estimate_days = 30
    elif digit_ratio > 0.25 or entropy > 4.2:
        domain_age_estimate_days = 90
    else:
        domain_age_estimate_days = 365

    ssl_certificate_valid = int(uses_https and not is_ip and 'xn--' not in hostname_clean)

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

def detect_typosquatting(url: str) -> tuple:
    """
    Detect typosquatting and phishing attempts for ANY URL.
    Uses multiple detection methods:
    1. Character substitution tricks (0→O, 1→l, etc.)
    2. Similarity to popular/legitimate domains
    3. Suspicious patterns and domain characteristics
    
    Returns tuple of (is_phishing, confidence)
    """
    try:
        parsed = urlparse(url)
        domain = parsed.hostname.lower() if parsed.hostname else ''
        domain_clean = domain.replace('www.', '')

        
        if not domain_clean:
            return False, 0.0
        
        # ===== CHECK 1: SUSPICIOUS CHARACTER SUBSTITUTIONS =====
        # These are very common in phishing: 0↔O, 1↔l, 5↔S, etc.
        suspicious_patterns = [
            (r'g00gle|g0ogle', 'Google with 0'),
            (r'y0utube|youtube0', 'YouTube with 0'),
            (r'fac3book|facebook3|faceb0ok', 'Facebook with 3 or 0'),
            (r'tw1tter|twitte1|tw0tter', 'Twitter with 1 or 0'),
            (r'inst4gram|instagram4', 'Instagram with 4'),
            (r'amaz0n|amazo0n', 'Amazon with 0'),
            (r'gmai1|gmail1', 'Gmail with 1'),
            (r'paypa1|paypa\|', 'PayPal with 1 or |'),
            (r'l1nkedin|linkedin1', 'LinkedIn with 1'),
            (r'r3ddit|reddit3', 'Reddit with 3'),
        ]
        
        for pattern, reason in suspicious_patterns:
            if re.search(pattern, domain_clean):
                logger.warning(f"Suspicious character substitution in {domain}: {reason}")
                return True, 0.98
        
        # ===== CHECK 2: EXACT MATCH WITH KNOWN LEGITIMATE DOMAIN =====
        if domain_clean in KNOWN_LEGITIMATE_DOMAINS:
            return False, 0.0
        
        # ===== CHECK 3: SIMILARITY TO KNOWN DOMAINS (>80%) =====
        for legitimate_domain in KNOWN_LEGITIMATE_DOMAINS:
            similarity = SequenceMatcher(None, domain_clean, legitimate_domain).ratio()
            
            # >80% similar but not exact = typosquatting
            if similarity > 0.80:
                logger.warning(f"Typosquatting detected: {domain} is {similarity:.1%} similar to {legitimate_domain}")
                return True, float(similarity)

        # ===== CHECK 4: TYPO ON MAIN DOMAIN LABEL =====
        domain_parts = domain_clean.split('.')
        domain_main = domain_parts[-2] if len(domain_parts) >= 2 else domain_parts[0]
        domain_tld = domain_parts[-1] if len(domain_parts) >= 2 else ''

        for legitimate_domain in KNOWN_LEGITIMATE_DOMAINS:
            legit_parts = legitimate_domain.split('.')
            legit_main = legit_parts[-2] if len(legit_parts) >= 2 else legit_parts[0]
            legit_tld = legit_parts[-1] if len(legit_parts) >= 2 else ''

            max_dist = 2 if len(legit_main) >= 9 else 1
            if (domain_tld == legit_tld and domain_main != legit_main
                    and edit_distance(domain_main, legit_main) <= max_dist):
                logger.warning(f"Main-label typo: {domain_clean} resembles {legitimate_domain}")
                return True, 0.90

        # ===== CHECK 5: TYPO IN ANY HOST LABEL vs ALL KNOWN BRAND LABELS =====
        all_known_labels = known_primary_labels()
        host_labels = [lbl for lbl in domain_parts[:-1] if lbl and lbl not in {'www'}]
        for label in host_labels:
            for known in all_known_labels:
                if len(known) < 5:
                    continue
                if label == known:
                    continue
                max_dist = 2 if len(known) >= 9 else 1
                if edit_distance(label, known) <= max_dist:
                    logger.warning(f"Host label typo: {label!r} resembles {known!r} in {domain_clean}")
                    return True, 0.90

        # ===== CHECK 6: BRAND TOKEN + RISKY SUBDOMAIN COMBINATION =====
        # Avoid false positives on valid multi-level domains by requiring
        # a risky token (login/verify/etc.) in subdomain labels.
        if len(domain_parts) >= 3:
            parent_label = domain_parts[-2]
            sub_labels = set(domain_parts[:-2])
            has_brand = bool(sub_labels & PROTECTED_BRAND_TOKENS)
            has_risky_token = has_token_or_one_char_typo(sub_labels, SUSPICIOUS_SUBDOMAIN_TOKENS)
            if parent_label in {'bank', 'secure', 'login', 'verify', 'update'} and has_brand and has_risky_token:
                logger.warning(f"Brand token nested under generic parent domain: {domain_clean}")
                return True, 0.92
        
        # ===== CHECK 7: SUSPICIOUS DOMAIN CHARACTERISTICS =====
        # Check for excessive hyphens (common in typosquatting)
        main_domain = domain_parts[0] if domain_parts else ''
        
        hyphen_count = main_domain.count('-')
        if hyphen_count > 2:
            logger.warning(f"Excessive hyphens in domain: {domain}")
            return True, 0.70
        
        # Very short domains can be suspicious
        if len(main_domain) < 3:
            logger.warning(f"Suspiciously short domain: {domain}")
            return True, 0.60
        
        return False, 0.0
        
    except Exception as e:
        logger.debug(f"Error in typosquatting detection: {e}")
        return False, 0.0


# ===== UNIVERSAL PHISHING DETECTOR FOR ANY URL =====
class UniversalPhishingDetector:
    """
    Detects phishing URLs for ANY domain on the internet
    Works on any domain, not limited to known whitelists
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
    def _extract_labels(domain_clean: str) -> List[str]:
        """Extract meaningful labels from host parts for brand analysis."""
        labels = []
        for part in domain_clean.split('.'):
            if part and part not in _COMMON_TLDS:
                labels.append(part)
                for token in re.split(r'[-_]', part):
                    if token and token not in _COMMON_TLDS:
                        labels.append(token)
        return labels

    @staticmethod
    def _detect_typosquatting_signal(domain_clean: str) -> Optional[str]:
        """Detect typo-based impersonation of known brands/domains."""
        labels = UniversalPhishingDetector._extract_labels(domain_clean)
        known_labels = known_primary_labels()

        for label in labels:
            if len(label) < 4:
                continue
            for known in known_labels:
                if len(known) < 4 or label == known:
                    continue
                max_dist = 2 if len(known) >= 9 else 1
                if edit_distance(label, known) <= max_dist:
                    return f"Typosquatting detected: '{label}' resembles '{known}'"
        return None

    @staticmethod
    def _detect_brand_similarity_signal(domain_clean: str) -> Optional[str]:
        """Detect high similarity between host labels and protected brand tokens."""
        labels = UniversalPhishingDetector._extract_labels(domain_clean)

        best_score = 0.0
        best_pair = None
        for label in labels:
            if len(label) < 5:
                continue
            for brand in PROTECTED_BRAND_TOKENS:
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
        """Detect homograph attack patterns (punycode, unicode, confusables)."""
        if 'xn--' in domain_clean:
            return "Homograph attack pattern: punycode domain (xn--)"

        if any(ord(ch) > 127 for ch in url):
            return "Homograph attack pattern: non-ASCII characters in URL"

        confusable_map = str.maketrans({
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'
        })
        normalized = domain_clean.translate(confusable_map)
        if normalized != domain_clean:
            for brand in PROTECTED_BRAND_TOKENS:
                if brand in normalized and brand not in domain_clean:
                    return f"Homograph attack pattern: confusable characters mimic '{brand}'"

        return None
    
    @staticmethod
    def analyze_url(url: str) -> dict:
        """
        Comprehensive analysis of ANY URL for phishing characteristics
        Works on any domain, not limited to known whitelists
        
        Returns dict with: is_phishing, confidence, reasons, score
        """
        result = {
            'is_phishing': False,
            'confidence': 0.0,
            'reasons': [],
            'score': 0,
            'max_score': 100,
            'critical_flags': 0,
            'signals': []
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
            advanced_features = extract_url_intel_features(url)

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

            # Explicit requested intelligence features
            if advanced_features['blacklist_check'] == 1:
                result['score'] += 60
                result['critical_flags'] += 1
                result['reasons'].append("Blacklist check matched known malicious indicator")

            if advanced_features['brand_impersonation_detected'] == 1:
                result['score'] += 25
                result['critical_flags'] += 0.6
                if 'Brand Impersonation Detection' not in result['signals']:
                    result['signals'].append('Brand Impersonation Detection')
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
            
            # ===== CRITICAL RED FLAGS =====
            
            # 1. IP address instead of domain — immediate high-confidence phishing
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                result['score'] += 97
                result['critical_flags'] += 1
                result['reasons'].append("IP address used instead of domain name — strong phishing indicator")
            
            # 2. @ symbol in URL (35 points) - Email spoofing
            if '@' in netloc:
                result['score'] += 35
                result['critical_flags'] += 1
                result['reasons'].append("@ symbol in URL (email spoofing)")
            
            # 3. Character substitution tricks
            substitution_patterns = [
                r'[0O]{2,}', r'[lI1]{2,}', r'[5S]{2,}',  # Multiple substitutions
                r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',  # Suspicious TLDs
                r'co\.uk\-', r'com\-',  # Domain hijacking
            ]
            for pattern in substitution_patterns:
                if re.search(pattern, domain):
                    if pattern in [r'[0O]{2,}', r'[lI1]{2,}', r'[5S]{2,}']:
                        result['score'] += 20
                        result['critical_flags'] += 0.8
                    else:
                        result['score'] += 15
                        result['critical_flags'] += 0.75
                    result['reasons'].append(f"Suspicious pattern detected: {pattern}")
                    break
            
            # 4. Excessive subdomains (25 points)
            subdomain_count = domain.count('.')
            if subdomain_count > 3:
                result['score'] += 25
                result['critical_flags'] += 0.5
                result['reasons'].append(f"Excessive subdomains ({subdomain_count} dots)")
            
            # ===== HIGH RISK INDICATORS =====
            
            # 5. Unusual ports
            if port and port not in [80, 443, 8080, 8443]:
                result['score'] += 20
                result['critical_flags'] += 0.5
                result['reasons'].append(f"Unusual port: {port}")
            
            # 6. URL shorteners
            shorteners = [
                'bit.ly', 'tinyurl.com', 'ow.ly', 'goo.gl', 'is.gd',
                'short.link', 'buff.ly', 'adf.ly', 'urly.it', 'tiny.cc',
            ]
            for shortener in shorteners:
                if shortener in domain:
                    result['score'] += 25
                    result['critical_flags'] += 0.75
                    result['reasons'].append(f"URL shortener detected: {shortener}")
                    break
            
            # 7. Suspicious keywords in domain
            if not is_known_legit:
                suspicious_keywords = [
                    'verify', 'confirm', 'update', 'update-', 'secure', 'secure-', 'login',
                    'login-', 'signin-', 'auth-', 'validate-', 'credential', 'security',
                    'password-', 'reset-', 'banking-', 'payment-',
                    'invoice-', 'winner-', 'claim-', 'urgent-',
                ]
                keyword_matches = sum(1 for kw in suspicious_keywords if kw in domain.lower())
                if keyword_matches > 0:
                    keyword_score = min(keyword_matches * 15, 35)
                    result['score'] += keyword_score
                    result['critical_flags'] += 0.5
                    reason = f"{keyword_matches} suspicious keyword(s)" if keyword_matches > 1 else "Suspicious keyword"
                    result['reasons'].append(reason)
            
            # 8. Very short domains
            domain_main = domain_clean.split('.')[0]
            if len(domain_main) <= 4 and not domain_main.isdigit() and not is_known_legit:
                result['score'] += 8
                result['reasons'].append("Suspiciously short domain name")
            
            # 9. Excessive numbers
            number_count = sum(1 for c in domain if c.isdigit())
            if number_count >= 4:
                result['score'] += 8
                result['reasons'].append(f"Many numbers in domain ({number_count})")
            
            # 10. Excessive hyphens
            hyphen_count = domain_main.count('-')
            if hyphen_count >= 3:
                result['score'] += 12
                result['reasons'].append(f"Many hyphens in domain ({hyphen_count})")
            
            # 11. Suspicious path
            if any(x in path for x in ['/admin', '/phishing', '/fakelogin', '/capture']):
                result['score'] += 8
                result['reasons'].append("Suspicious path detected")
            
            # 12. Excessive query parameters
            if query and len(query) > 150:
                result['score'] += 5
                result['reasons'].append("Excessive query parameters")
            
            # ===== CALCULATE CONFIDENCE =====
            result['confidence'] = min(result['score'] / result['max_score'], 1.0)
            
            # Final decision
            if result['critical_flags'] >= 0.7:
                result['is_phishing'] = True
            elif result['score'] >= 15:
                result['is_phishing'] = True

            # Keep signal list unique and stable for API/UI
            result['signals'] = sorted(set(result['signals']))
            result['advanced_features'] = advanced_features
            
        except Exception as e:
            logger.debug(f"Error in universal analysis: {e}")
        
        return result


# Model loader class
class ModelManager:
    """Load and manage trained models"""
    
    def __init__(self):
        self.ml_model = None
        self.dl_model = None
        self.scaler = None
        self.char_vocab = None
        self.max_url_length = 100
        self.feature_extractor = URLFeatureExtractor()
        self._load_models()
    
    def _load_models(self):
        """Load all trained models"""
        try:
            # Load ML model
            if Path("models/random_forest_model.pkl").exists():
                with open("models/random_forest_model.pkl", 'rb') as f:
                    self.ml_model = pickle.load(f)
                logger.info("Random Forest model loaded")
            elif Path("models/xgboost_model.pkl").exists():
                with open("models/xgboost_model.pkl", 'rb') as f:
                    self.ml_model = pickle.load(f)
                logger.info("XGBoost model loaded")
            else:
                logger.warning("No ML model found")
            
            # Load scaler
            if Path("models/scaler.pkl").exists():
                with open("models/scaler.pkl", 'rb') as f:
                    self.scaler = pickle.load(f)
                logger.info("Scaler loaded")
            
            # Load DL model
            if Path("models/cnn_model.h5").exists():
                self.dl_model = tf.keras.models.load_model("models/cnn_model.h5")
                logger.info("CNN model loaded")
            elif Path("models/lstm_model.h5").exists():
                self.dl_model = tf.keras.models.load_model("models/lstm_model.h5")
                logger.info("LSTM model loaded")
            
            # Load character vocabulary
            if Path("models/char_vocab.pkl").exists():
                with open("models/char_vocab.pkl", 'rb') as f:
                    vocab_data = pickle.load(f)
                    self.char_vocab = vocab_data['char_to_idx']
                    self.max_url_length = vocab_data['max_url_length']
                logger.info("Character vocabulary loaded")
        
        except Exception as e:
            logger.error(f"Error loading models: {str(e)}")
    
    def predict_ml(self, url: str) -> tuple:
        """
        Make prediction using ML model
        
        Args:
            url: URL to classify
        
        Returns:
            Tuple of (prediction, confidence, features)
        """
        try:
            # Extract features
            features = self.feature_extractor.extract_all_features(url)
            
            # Convert to numpy array in correct order
            feature_names = sorted(features.keys())
            feature_values = np.array([[features[name] for name in feature_names]]).astype(float)
            
            # Scale features
            feature_values_scaled = self.scaler.transform(feature_values)
            
            # Predict
            prediction = self.ml_model.predict(feature_values_scaled)[0]
            confidence = self.ml_model.predict_proba(feature_values_scaled)[0]
            
            return int(prediction), float(max(confidence)), features
        except Exception as e:
            logger.error(f"Error in ML prediction: {str(e)}")
            raise
    
    def predict_dl(self, url: str) -> tuple:
        """
        Make prediction using Deep Learning model
        
        Args:
            url: URL to classify
        
        Returns:
            Tuple of (prediction, confidence)
        """
        try:
            # Encode URL as character sequence
            seq = [self.char_vocab.get(char, 0) for char in url]
            X = pad_sequences([seq], maxlen=self.max_url_length, padding='post')
            
            # Predict
            prediction_proba = self.dl_model.predict(X, verbose=0)[0][0]
            prediction = 1 if prediction_proba > 0.5 else 0
            confidence = prediction_proba if prediction == 1 else (1 - prediction_proba)
            
            return int(prediction), float(confidence), {}
        except Exception as e:
            logger.error(f"Error in DL prediction: {str(e)}")
            raise


# Initialize components
models = ModelManager()
db = PhishingDetectionDatabase()

# Routes

@app.get("/", tags=["Health"])
async def root():
    """Root endpoint"""
    return {
        "message": "Phishing URL Detection API",
        "version": "1.0.0",
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

@app.get('/')
def root():
    """Redirect to login page"""
    return {"message": "API running. Visit /static/login.html in browser or use /predict endpoint"}

class AuthRequest(BaseModel):
    username: str
    password: str

class ForgotPasswordRequest(BaseModel):
    username: str

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
    """Check API health and model availability"""
    return HealthResponse(
        status="healthy",
        models_loaded={
            "ml_model": models.ml_model is not None,
            "dl_model": models.dl_model is not None,
            "scaler": models.scaler is not None
        },
        database_status=True
    )

@app.post("/predict", response_model=PredictionResponse, tags=["Predictions"])
async def predict(input_data: URLInput, background_tasks: BackgroundTasks):
    """
    Predict if a URL is phishing or legitimate
    
    Args:
        input_data: URL to classify
    
    Returns:
        Prediction result with confidence score
    """
    start_time = time.time()
    
    try:
        url = input_data.url
        model_choice = input_data.model.lower()
        
        # Validate and normalize URL
        try:
            url = validate_and_normalize_url(url)
        except ValueError as e:
            logger.error(f"URL validation failed: {str(e)}")
            raise HTTPException(status_code=400, detail=f"Invalid URL: {str(e)}")
        
        logger.info(f"Processing URL: {url}")
        
        # Check with universal detector first (works for ANY URL)
        universal_analysis = UniversalPhishingDetector.analyze_url(url)
        if universal_analysis['is_phishing']:
            logger.warning(f"Phishing detected by universal detector for {url}")
            processing_time = (time.time() - start_time) * 1000
            
            background_tasks.add_task(
                db.store_prediction, url, 1, universal_analysis['confidence'], "Universal Detector", {}
            )
            background_tasks.add_task(
                db.store_scan_result, url, 1, "Universal Detector", universal_analysis['confidence'], processing_time
            )
            
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
                    **universal_analysis.get('advanced_features', {})
                }
            )
        
        # Check for typosquatting (legacy check)
        is_typosquatting, typo_confidence = detect_typosquatting(url)
        if is_typosquatting:
            logger.warning(f"Typosquatting detected for {url}")
            processing_time = (time.time() - start_time) * 1000
            background_tasks.add_task(db.store_prediction, url, 1, typo_confidence, "Typosquatting Detection", {})
            background_tasks.add_task(db.store_scan_result, url, 1, "Typosquatting Detection", typo_confidence, processing_time)
            
            return PredictionResponse(
                url=url,
                prediction=1,
                prediction_label="Phishing",
                confidence=typo_confidence,
                model_used="Typosquatting Detection",
                timestamp=datetime.now().isoformat(),
                features={
                    "attack_detection_modules": "Typosquatting Detection",
                    "typosquatting_detected": True
                }
            )
        
        # Check if prediction exists in database
        cached = db.get_prediction(url)
        if cached:
            logger.info(f"Using cached prediction for {url}")
            return PredictionResponse(
                url=cached['url'],
                prediction=cached['prediction'],
                prediction_label="Phishing" if cached['prediction'] == 1 else "Legitimate",
                confidence=cached['confidence'],
                model_used=cached['model_name'],
                timestamp=cached['timestamp']
            )
        
        # Make prediction - Try requested model, then ML, then Universal Detector
        prediction = None
        confidence = None
        features = None
        model_used = None
        
        # Priority 1: Try requested model
        if model_choice == 'dl' and models.dl_model:
            try:
                prediction, confidence, features = models.predict_dl(url)
                model_used = "Deep Learning (CNN/LSTM)"
                logger.info(f"Using DL model for {url}")
            except Exception as e:
                logger.warning(f"DL model failed: {e}, falling back to ML")
        
        # Priority 2: Try ML model if DL failed or not requested
        if prediction is None and models.ml_model:
            try:
                prediction, confidence, features = models.predict_ml(url)
                model_used = "Machine Learning (Random Forest/XGBoost)"
                logger.info(f"Using ML model for {url}")
            except Exception as e:
                logger.warning(f"ML model failed: {e}, falling back to Universal Detector")
        
        # Priority 3: Fallback to Universal Detector (always available)
        if prediction is None:
            logger.info(f"Using Universal Detector for {url}")
            universal_analysis = UniversalPhishingDetector.analyze_url(url)
            prediction = 1 if universal_analysis['is_phishing'] else 0
            confidence = universal_analysis['confidence']
            model_used = "Universal Detector (Multi-Method)"
            features = {"detection_reasons": universal_analysis['reasons'][:3]}
        
        # Store in database asynchronously
        processing_time = (time.time() - start_time) * 1000
        background_tasks.add_task(
            db.store_prediction, url, prediction, confidence, model_used, features
        )
        background_tasks.add_task(
            db.store_scan_result, url, prediction, model_used, confidence, processing_time
        )
        
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
async def batch_predict(input_data: BatchURLInput, background_tasks: BackgroundTasks):
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

                # Universal detector first (works for unseen/new URLs)
                universal_analysis = UniversalPhishingDetector.analyze_url(url)
                if universal_analysis['is_phishing']:
                    results.append({
                        "url": url,
                        "prediction": 1,
                        "prediction_label": "Phishing",
                        "confidence": float(universal_analysis['confidence']),
                        "model_used": "Universal Detector (Multi-Method)"
                    })
                    background_tasks.add_task(
                        db.store_prediction, url, 1, universal_analysis['confidence'], "Universal Detector", {}
                    )
                    continue
                
                # Check for typosquatting first
                is_typosquatting, typo_confidence = detect_typosquatting(url)
                if is_typosquatting:
                    results.append({
                        "url": url,
                        "prediction": 1,
                        "prediction_label": "Phishing",
                        "confidence": float(typo_confidence),
                        "model_used": "Typosquatting Detection"
                    })
                    background_tasks.add_task(db.store_prediction, url, 1, typo_confidence, "Typosquatting Detection")
                    continue
                
                if input_data.model == 'dl' and models.dl_model:
                    prediction, confidence, _ = models.predict_dl(url)
                    model_used = "Deep Learning"
                elif models.ml_model:
                    prediction, confidence, _ = models.predict_ml(url)
                    model_used = "Machine Learning"
                else:
                    continue
                
                results.append({
                    "url": url,
                    "prediction": int(prediction),
                    "prediction_label": "Phishing" if prediction == 1 else "Legitimate",
                    "confidence": float(confidence),
                    "model_used": model_used
                })
                
                # Store in database
                background_tasks.add_task(
                    db.store_prediction, url, prediction, confidence, model_used
                )
            except ValueError as e:
                logger.warning(f"Skipping invalid URL '{raw_url}': {str(e)}")
                results.append({
                    "url": raw_url,
                    "error": f"Invalid URL: {str(e)}"
                })
            except Exception as e:
                logger.warning(f"Error processing {url}: {str(e)}")
                continue
        
        return JSONResponse({"results": results, "total": len(results)})
    
    except Exception as e:
        logger.error(f"Error in batch prediction: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/stats", response_model=StatsResponse, tags=["Statistics"])
async def get_stats():
    """Get detection statistics"""
    try:
        stats = db.get_statistics()
        return StatsResponse(**stats)
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving statistics")

@app.get("/history", tags=["History"])
async def get_history(limit: int = 100, days: int = 30):
    """Get scan history"""
    try:
        history = db.get_scan_history(limit=limit, days=days)
        return JSONResponse({"history": history, "total": len(history)})
    except Exception as e:
        logger.error(f"Error getting history: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving history")

@app.get("/models", tags=["Models"])
async def get_models_info():
    """Get loaded models information"""
    try:
        metrics = db.get_model_metrics()
        return JSONResponse({"models": metrics if isinstance(metrics, list) else [metrics]})
    except Exception as e:
        logger.error(f"Error getting models: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving model info")

@app.exception_handler(Exception)
async def exception_handler(request, exc):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )


if __name__ == "__main__":
    # Run the API
    logger.info("Starting Phishing URL Detection API...")
    logger.info("Available at http://localhost:8000")
    logger.info("API documentation at http://localhost:8000/docs")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
