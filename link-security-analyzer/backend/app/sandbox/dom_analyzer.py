"""DOM analyzer: turn rendered HTML into meaningful signals.

Pure function that takes HTML + metadata and returns signals with evidence.
Implements all Stage 4 signals from spec: forms, payment fields, brand text,
urgency language, trust signals, and combination rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup
from bs4.element import Comment

# Timeout for BeautifulSoup parser (seconds)
_PARSER_TIMEOUT = 5.0
# Max HTML size to parse (500KB)
_MAX_HTML_SIZE = 500_000

# Field patterns
_PASSWORD_PATTERN = re.compile(r'type\s*=\s*["\']password["\']', re.I)
_CARD_PATTERNS = [
    re.compile(r'\b(card[\s_-]?number|cc[\s_-]?number|credit[\s_-]?card|debit[\s_-]?card)\b', re.I),
    re.compile(r'\b(cvv|cvc|security[\s_-]?code|card[\s_-]?verification)\b', re.I),
    re.compile(r'\b(expir|expiry|exp[\s_-]?date|valid[\s_-]?thru)\b', re.I),
    re.compile(r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}', re.I),  # 16-digit pattern
]
_UPI_PATTERNS = [
    re.compile(r'\b(upi[\s_-]?id|vpa|virtual[\s_-]?payment[\s_-]?address)\b', re.I),
    re.compile(r'@(ybl|paytm|oksbi|axl|ibl|icici|okaxis|okhdfcbank|okbizaxis|airtel|freecharge|gpay|phonepe)', re.I),
]
_OTP_PIN_PATTERNS = [
    re.compile(r'\b(otp|one[\s_-]?time[\s_-]?password|verification[\s_-]?code)\b', re.I),
    re.compile(r'\b(upi[\s_-]?pin|mpin|atm[\s_-]?pin|net[\s_-]?banking[\s_-]?password)\b', re.I),
    re.compile(r'\b(aadhaar|aadhar|pan[\s_-]?number|pan[\s_-]?card)\b', re.I),
]

# Urgency phrases (English + Hinglish)
_URGENCY_PHRASES = [
    # English
    r'\b(within\s+\d+\s+hours?|within\s+24\s+hours?)\b',
    r'\baccount\s+(blocked|suspended|locked|disabled|frozen|closed)\b',
    r'\b(kyc|know\s+your\s+customer)\s+(expired?|pending|required|mandatory|incomplete|update)\b',
    r'\b(immediately|urgent|asap|right\s+now|instant|act\s+now)\b',
    r'\b(last\s+chance|final\s+(warning|notice|reminder))\b',
    r'\b(verify\s+(now|immediately|within)|update\s+(now|immediately))\b',
    r'\b(claim\s+now|expire[sd]?\s+(soon|today)|limited\s+time)\b',
    # Hinglish/Hindi
    r'(आपका\s+खाता\s+बंद|अकाउंट\s+बंद)',  # your account closed
    r'(तुरंत\s+अपडेट|जल्दी\s+करें)',  # update immediately
    r'(केवाईसी\s+जरूरी|kyc\s+अपडेट)',  # KYC necessary
]
_URGENCY_REGEX = re.compile('|'.join(_URGENCY_PHRASES), re.I)

# Obfuscated JS patterns
_OBFUSCATED_JS_PATTERNS = [
    re.compile(r'eval\s*\(', re.I),
    re.compile(r'atob\s*\(', re.I),
    re.compile(r'unescape\s*\(', re.I),
    re.compile(r'fromCharCode', re.I),
]

# Known payment gateways (official domains)
_RECOGNIZED_GATEWAYS = {
    'razorpay.com',
    'stripe.com',
    'paypal.com',
    'payu.in',
    'cashfree.com',
    'paytm.com',
    'instamojo.com',
}

# Trust page keywords
_TRUST_KEYWORDS = [
    'contact', 'about', 'privacy', 'terms', 'policy',
    'support', 'help', 'disclaimer', 'legal',
]


@dataclass
class Signal:
    """One detected risk indicator."""

    id: str
    points: int
    severity: str  # info, low, medium, high, critical
    explain: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class DOMAnalysisResult:
    """Result of analyzing rendered HTML."""

    signals: list[Signal] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)


def analyze(
    html: str,
    page_url: str,
    final_url: str,
    headers: Optional[dict[str, str]] = None,
    brands: Optional[list[dict[str, Any]]] = None,
    domain_age_days: Optional[int] = None,
    auto_download: bool = False,
    redirect_chain: Optional[list[dict[str, Any]]] = None,
) -> DOMAnalysisResult:
    """Analyze rendered HTML and return signals + evidence.

    Args:
        html: Rendered HTML from Playwright (capped, untrusted)
        page_url: Original URL submitted by user
        final_url: Final URL after redirects
        headers: Response headers dict
        brands: List of brand dicts from brands.yaml
        domain_age_days: Domain age in days (from infrastructure check)
        auto_download: Whether download was attempted (from sandbox)
        redirect_chain: List of redirect hops with url/status

    Returns:
        DOMAnalysisResult with signals and evidence
    """
    signals: list[Signal] = []
    evidence: dict[str, Any] = {}

    # Cap HTML size
    if len(html) > _MAX_HTML_SIZE:
        html = html[:_MAX_HTML_SIZE]
        evidence['html_truncated'] = True

    # Parse HTML with BeautifulSoup (lxml parser, fast and lenient)
    try:
        soup = BeautifulSoup(html, 'lxml')
    except Exception as error:  # noqa: BLE001
        # Malformed HTML that even lxml can't parse
        signals.append(Signal(
            id='DOM_PARSE_ERROR',
            points=0,
            severity='info',
            explain=f'Could not parse HTML: {type(error).__name__}',
            evidence={'error': str(error)},
        ))
        return DOMAnalysisResult(signals=signals, evidence=evidence)

    # Extract registrable domains
    final_domain = _registrable_domain(final_url)
    page_domain = _registrable_domain(page_url)

    # Extract visible text (for urgency check and excerpt)
    visible_text = _extract_visible_text(soup)
    evidence['visible_text_excerpt'] = visible_text[:300] if visible_text else ''

    # Analyze forms
    forms = _analyze_forms(soup, final_url, final_domain)
    evidence['forms'] = forms
    signals.extend(_form_signals(forms, final_domain))

    # Analyze input fields
    signals.extend(_field_signals(soup, forms))

    # Brand text mismatch
    if brands:
        brand_signal = _brand_text_mismatch(soup, final_domain, brands)
        if brand_signal:
            signals.append(brand_signal)
            evidence['detected_brands'] = brand_signal.evidence.get('brands', [])

    # Hidden iframes
    iframe_signal = _hidden_iframe_signal(soup, final_domain)
    if iframe_signal:
        signals.append(iframe_signal)

    # Meta refresh redirect
    meta_signal = _meta_refresh_signal(soup, final_domain)
    if meta_signal:
        signals.append(meta_signal)

    # Urgency language
    urgency_signal = _urgency_signal(visible_text)
    if urgency_signal:
        signals.append(urgency_signal)

    # Obfuscated JS
    obfuscated_signal = _obfuscated_js_signal(soup)
    if obfuscated_signal:
        signals.append(obfuscated_signal)

    # Right-click disabled
    if _right_click_disabled(soup):
        signals.append(Signal(
            id='RIGHT_CLICK_DISABLED',
            points=3,
            severity='low',
            explain='Right-click context menu is disabled',
        ))

    # No trust pages
    trust_signal = _no_trust_pages_signal(soup)
    if trust_signal:
        signals.append(trust_signal)

    # Recognized gateway
    gateway_signal = _recognized_gateway_signal(soup, forms)
    if gateway_signal:
        signals.append(gateway_signal)

    # Auto download
    if auto_download:
        signals.append(Signal(
            id='AUTO_DOWNLOAD_ATTEMPT',
            points=30,
            severity='high',
            explain='Page attempted to trigger an automatic download',
        ))

    # Redirect chain cross-domain
    if redirect_chain and len(redirect_chain) >= 3:
        domains = [_registrable_domain(hop.get('url', '')) for hop in redirect_chain]
        unique_domains = set(d for d in domains if d)
        if len(unique_domains) >= 3:
            signals.append(Signal(
                id='REDIRECT_CHAIN_CROSS_DOMAIN',
                points=10,
                severity='low',
                explain=f'{len(redirect_chain)} redirects across {len(unique_domains)} different domains',
                evidence={'redirect_count': len(redirect_chain), 'unique_domains': len(unique_domains)},
            ))

    # Extract evidence for UI
    evidence.update({
        'third_party_scripts': _extract_third_party_scripts(soup, final_domain),
        'top_external_links': _extract_external_links(soup, final_domain),
        'has_contact_link': _has_trust_link(soup, 'contact'),
        'has_privacy_link': _has_trust_link(soup, 'privacy'),
        'has_terms_link': _has_trust_link(soup, 'terms'),
    })

    # Combination rules (require signals from other stages)
    combo_signals = _combination_rules(signals, domain_age_days)
    signals.extend(combo_signals)

    return DOMAnalysisResult(signals=signals, evidence=evidence)


def _registrable_domain(url: str) -> Optional[str]:
    """Extract registrable domain from URL."""
    if not url:
        return None
    try:
        import tldextract
        extracted = tldextract.extract(url)
        if extracted.domain and extracted.suffix:
            return f"{extracted.domain}.{extracted.suffix}"
    except Exception:  # noqa: BLE001
        pass
    return None


def _extract_visible_text(soup: BeautifulSoup) -> str:
    """Extract visible text from HTML (strips scripts, styles, comments)."""
    # Remove script and style elements
    for element in soup(['script', 'style', 'noscript']):
        element.decompose()

    # Remove comments
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        comment.extract()

    # Get text and clean whitespace
    text = soup.get_text(separator=' ', strip=True)
    # Collapse multiple spaces
    text = re.sub(r'\s+', ' ', text)
    return text


def _analyze_forms(soup: BeautifulSoup, final_url: str, final_domain: Optional[str]) -> list[dict[str, Any]]:
    """Extract form metadata."""
    forms = []
    for form in soup.find_all('form'):
        action = form.get('action', '')
        method = form.get('method', 'get').upper()

        # Resolve relative action URL
        if action:
            action_url = urljoin(final_url, action)
        else:
            action_url = final_url

        action_domain = _registrable_domain(action_url)

        # Extract fields
        fields = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            field_type = inp.get('type', 'text').lower()
            field_name = inp.get('name', '')
            field_placeholder = inp.get('placeholder', '')
            field_label = ''

            # Try to find associated label
            field_id = inp.get('id')
            if field_id:
                label = soup.find('label', attrs={'for': field_id})
                if label:
                    field_label = label.get_text(strip=True)

            fields.append({
                'type': field_type,
                'name': field_name,
                'placeholder': field_placeholder,
                'label': field_label,
            })

        forms.append({
            'action': action,
            'action_url': action_url,
            'action_domain': action_domain,
            'method': method,
            'fields': fields,
            'is_cross_domain': action_domain != final_domain if action_domain and final_domain else False,
            'is_http': action_url.startswith('http://') if action_url else False,
        })

    return forms


def _form_signals(forms: list[dict[str, Any]], final_domain: Optional[str]) -> list[Signal]:
    """Generate signals from form analysis."""
    signals = []

    for form in forms:
        # Cross-domain form post
        if form['is_cross_domain']:
            signals.append(Signal(
                id='FORM_POSTS_CROSS_DOMAIN',
                points=30,
                severity='high',
                explain=f"Form posts to different domain: {form['action_domain']}",
                evidence={'action_domain': form['action_domain'], 'page_domain': final_domain},
            ))

        # HTTP form post (check if has password field)
        if form['is_http']:
            has_password = any(f['type'] == 'password' for f in form['fields'])
            if has_password:
                signals.append(Signal(
                    id='FORM_POSTS_TO_HTTP',
                    points=20,
                    severity='high',
                    explain='Form with password field posts over insecure HTTP',
                    evidence={'action_url': form['action_url']},
                ))

        # Empty or JavaScript action with password
        action = form['action']
        has_password = any(f['type'] == 'password' for f in form['fields'])
        if has_password and (not action or action.startswith('javascript:')):
            signals.append(Signal(
                id='FORM_ACTION_EMPTY_OR_JS',
                points=8,
                severity='medium',
                explain='Password form with empty or JavaScript action (may exfiltrate via script)',
                evidence={'action': action or '(empty)'},
            ))

    return signals


def _field_signals(soup: BeautifulSoup, forms: list[dict[str, Any]]) -> list[Signal]:
    """Detect sensitive field patterns."""
    signals = []

    # Collect all text that might describe fields
    all_fields_text = []
    for form in forms:
        for field in form['fields']:
            all_fields_text.append(field['name'])
            all_fields_text.append(field['placeholder'])
            all_fields_text.append(field['label'])

    # Also check autocomplete attributes and nearby text
    for inp in soup.find_all(['input', 'textarea']):
        all_fields_text.append(inp.get('name', ''))
        all_fields_text.append(inp.get('placeholder', ''))
        all_fields_text.append(inp.get('autocomplete', ''))

        # Check aria-label
        aria_label = inp.get('aria-label', '')
        all_fields_text.append(aria_label)

    combined_text = ' '.join(all_fields_text).lower()

    # Password field
    if _PASSWORD_PATTERN.search(str(soup)) or 'password' in combined_text:
        signals.append(Signal(
            id='HAS_PASSWORD_FIELD',
            points=5,
            severity='low',
            explain='Page has a password input field',
        ))

    # Card fields
    if any(pattern.search(combined_text) for pattern in _CARD_PATTERNS):
        signals.append(Signal(
            id='HAS_CARD_FIELDS',
            points=10,
            severity='medium',
            explain='Page asks for credit/debit card information',
        ))

    # UPI fields
    if any(pattern.search(combined_text) for pattern in _UPI_PATTERNS):
        signals.append(Signal(
            id='HAS_UPI_ID_FIELD',
            points=10,
            severity='medium',
            explain='Page asks for UPI ID or VPA',
        ))

    # OTP/PIN/sensitive fields
    if any(pattern.search(combined_text) for pattern in _OTP_PIN_PATTERNS):
        signals.append(Signal(
            id='HAS_OTP_PIN_FIELD',
            points=15,
            severity='high',
            explain='Page asks for OTP, PIN, Aadhaar, or PAN',
        ))

    return signals


def _brand_text_mismatch(soup: BeautifulSoup, final_domain: Optional[str], brands: list[dict[str, Any]]) -> Optional[Signal]:
    """Detect brand mentions when domain doesn't match."""
    if not final_domain:
        return None

    # Extract text from title, headings, alt text, meta tags
    title = soup.title.string if soup.title else ''
    headings = ' '.join(tag.get_text() for tag in soup.find_all(['h1', 'h2', 'h3']))
    alt_texts = ' '.join(img.get('alt', '') for img in soup.find_all('img'))

    # Check meta og:site_name
    og_site_name = ''
    og_meta = soup.find('meta', property='og:site_name')
    if og_meta:
        og_site_name = og_meta.get('content', '')

    # Check logo filenames in img src
    logo_filenames = []
    for img in soup.find_all('img'):
        src = img.get('src', '')
        if 'logo' in src.lower():
            logo_filenames.append(src)

    combined_text = f"{title} {headings} {alt_texts} {og_site_name} {' '.join(logo_filenames)}".lower()

    # Check each brand
    detected_brands = []
    for brand in brands:
        brand_keywords = brand.get('keywords', [])
        official_domains = brand.get('official_domains', [])

        # Skip if current domain is official
        if any(official in final_domain for official in official_domains):
            continue

        # Check if brand keyword appears in text
        for keyword in brand_keywords:
            if keyword.lower() in combined_text:
                detected_brands.append(brand.get('display_name', keyword))
                break

    if detected_brands:
        return Signal(
            id='BRAND_TEXT_DOMAIN_MISMATCH',
            points=30,
            severity='high',
            explain=f"Page mentions {', '.join(detected_brands)} but domain is not official",
            evidence={'brands': detected_brands, 'domain': final_domain},
        )

    return None


def _hidden_iframe_signal(soup: BeautifulSoup, final_domain: Optional[str]) -> Optional[Signal]:
    """Detect hidden or suspicious iframes."""
    for iframe in soup.find_all('iframe'):
        # Check size
        width = iframe.get('width', '')
        height = iframe.get('height', '')
        style = iframe.get('style', '')

        # Hidden by size
        if width in ['0', '1'] or height in ['0', '1']:
            return Signal(
                id='HIDDEN_IFRAME',
                points=15,
                severity='medium',
                explain='Page contains hidden iframe (0 or 1 pixel size)',
                evidence={'iframe_src': iframe.get('src', '(no src)')},
            )

        # Hidden by CSS
        if 'display:none' in style.replace(' ', '') or 'display: none' in style:
            return Signal(
                id='HIDDEN_IFRAME',
                points=15,
                severity='medium',
                explain='Page contains hidden iframe (display:none)',
                evidence={'iframe_src': iframe.get('src', '(no src)')},
            )

        # Full-page cross-domain iframe
        src = iframe.get('src', '')
        if src:
            iframe_domain = _registrable_domain(src)
            if iframe_domain and iframe_domain != final_domain:
                # Check if it's full-page (width/height >= 90% or unspecified)
                try:
                    w = int(width.replace('%', '').replace('px', '')) if width else 100
                    h = int(height.replace('%', '').replace('px', '')) if height else 100
                    if w >= 90 and h >= 90:
                        return Signal(
                            id='HIDDEN_IFRAME',
                            points=15,
                            severity='medium',
                            explain=f'Page contains full-page cross-domain iframe to {iframe_domain}',
                            evidence={'iframe_domain': iframe_domain},
                        )
                except (ValueError, AttributeError):
                    pass

    return None


def _meta_refresh_signal(soup: BeautifulSoup, final_domain: Optional[str]) -> Optional[Signal]:
    """Detect meta refresh redirects to different domains."""
    for meta in soup.find_all('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)}):
        content = meta.get('content', '')
        # Parse content: "5; url=https://example.com"
        match = re.search(r'url\s*=\s*["\']?([^"\'>\s]+)', content, re.I)
        if match:
            redirect_url = match.group(1)
            redirect_domain = _registrable_domain(redirect_url)
            if redirect_domain and redirect_domain != final_domain:
                return Signal(
                    id='META_REFRESH_REDIRECT',
                    points=8,
                    severity='medium',
                    explain=f'Meta refresh redirect to different domain: {redirect_domain}',
                    evidence={'redirect_domain': redirect_domain},
                )

    return None


def _urgency_signal(visible_text: str) -> Optional[Signal]:
    """Detect urgency language."""
    if _URGENCY_REGEX.search(visible_text):
        matches = _URGENCY_REGEX.findall(visible_text)
        return Signal(
            id='URGENCY_LANGUAGE',
            points=10,
            severity='medium',
            explain='Page uses urgency language (account blocked, KYC expired, act now)',
            evidence={'phrases': [m[0] if isinstance(m, tuple) else m for m in matches[:3]]},
        )
    return None


def _obfuscated_js_signal(soup: BeautifulSoup) -> Optional[Signal]:
    """Detect obfuscated JavaScript."""
    for script in soup.find_all('script'):
        script_text = script.string or ''
        if len(script_text) < 100:
            continue

        # Check for eval/atob/unescape chains
        obfuscation_count = sum(1 for pattern in _OBFUSCATED_JS_PATTERNS if pattern.search(script_text))
        if obfuscation_count >= 2:
            return Signal(
                id='OBFUSCATED_JS',
                points=8,
                severity='medium',
                explain='Page contains heavily obfuscated JavaScript (eval/atob/unescape)',
            )

        # Check for very long single-line scripts (>5000 chars, no newlines)
        if '\n' not in script_text and len(script_text) > 5000:
            return Signal(
                id='OBFUSCATED_JS',
                points=8,
                severity='medium',
                explain='Page contains very long single-line script (potential obfuscation)',
            )

    return None


def _right_click_disabled(soup: BeautifulSoup) -> bool:
    """Check if right-click is disabled."""
    # Check for oncontextmenu handlers
    for tag in soup.find_all(attrs={'oncontextmenu': True}):
        handler = tag['oncontextmenu']
        if 'return false' in handler.lower() or 'preventdefault' in handler.lower():
            return True

    # Check for body oncontextmenu
    body = soup.find('body')
    if body and body.get('oncontextmenu'):
        return True

    # Check for script that disables context menu
    for script in soup.find_all('script'):
        script_text = script.string or ''
        if 'contextmenu' in script_text.lower() and ('preventdefault' in script_text.lower() or 'return false' in script_text.lower()):
            return True

    return False


def _no_trust_pages_signal(soup: BeautifulSoup) -> Optional[Signal]:
    """Check for absence of trust pages (contact, privacy, terms)."""
    links = soup.find_all('a', href=True)
    link_texts = [link.get_text().lower() for link in links]
    link_hrefs = [link['href'].lower() for link in links]

    # Check if any trust keywords appear
    has_trust_link = any(
        any(keyword in text or keyword in href for keyword in _TRUST_KEYWORDS)
        for text, href in zip(link_texts, link_hrefs)
    )

    if not has_trust_link and len(links) > 5:  # Only flag if page has links
        return Signal(
            id='NO_TRUST_PAGES',
            points=8,
            severity='low',
            explain='Page has no links to contact, about, privacy, or terms pages',
        )

    return None


def _recognized_gateway_signal(soup: BeautifulSoup, forms: list[dict[str, Any]]) -> Optional[Signal]:
    """Detect recognized payment gateways."""
    # Check script sources
    for script in soup.find_all('script', src=True):
        src = script['src']
        script_domain = _registrable_domain(src)
        if script_domain in _RECOGNIZED_GATEWAYS:
            # Also check if form posts to same domain or gateway domain
            for form in forms:
                action_domain = form.get('action_domain')
                if action_domain in _RECOGNIZED_GATEWAYS or action_domain == script_domain:
                    return Signal(
                        id='RECOGNIZED_GATEWAY',
                        points=-10,
                        severity='info',
                        explain=f'Page uses recognized payment gateway: {script_domain}',
                        evidence={'gateway': script_domain},
                    )

    # Check form actions
    for form in forms:
        action_domain = form.get('action_domain')
        if action_domain in _RECOGNIZED_GATEWAYS:
            return Signal(
                id='RECOGNIZED_GATEWAY',
                points=-10,
                severity='info',
                explain=f'Form posts to recognized payment gateway: {action_domain}',
                evidence={'gateway': action_domain},
            )

    return None


def _extract_third_party_scripts(soup: BeautifulSoup, final_domain: Optional[str]) -> list[str]:
    """Extract third-party script domains."""
    if not final_domain:
        return []

    third_party = set()
    for script in soup.find_all('script', src=True):
        src = script['src']
        script_domain = _registrable_domain(src)
        if script_domain and script_domain != final_domain:
            third_party.add(script_domain)

    return sorted(third_party)[:10]  # Top 10


def _extract_external_links(soup: BeautifulSoup, final_domain: Optional[str]) -> list[dict[str, str]]:
    """Extract top external links."""
    if not final_domain:
        return []

    external = []
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.startswith(('http://', 'https://')):
            link_domain = _registrable_domain(href)
            if link_domain and link_domain != final_domain:
                external.append({
                    'text': link.get_text(strip=True)[:50],
                    'href': href[:100],
                    'domain': link_domain,
                })

    return external[:10]  # Top 10


def _has_trust_link(soup: BeautifulSoup, keyword: str) -> bool:
    """Check if page has a specific trust link."""
    for link in soup.find_all('a', href=True):
        text = link.get_text().lower()
        href = link['href'].lower()
        if keyword in text or keyword in href:
            return True
    return False


def _combination_rules(signals: list[Signal], domain_age_days: Optional[int]) -> list[Signal]:
    """Apply combination rules that depend on multiple signals."""
    combo_signals = []

    signal_ids = {s.id for s in signals}

    # Rule 1: Credential or payment on young domain
    has_credential_or_payment = bool(
        signal_ids & {'HAS_PASSWORD_FIELD', 'HAS_CARD_FIELDS', 'HAS_UPI_ID_FIELD', 'HAS_OTP_PIN_FIELD'}
    )
    if has_credential_or_payment and domain_age_days is not None and domain_age_days < 30:
        combo_signals.append(Signal(
            id='CREDENTIAL_OR_PAYMENT_ON_YOUNG_DOMAIN',
            points=20,
            severity='high',
            explain=f'Page asks for credentials/payment on domain less than 30 days old ({domain_age_days} days)',
            evidence={'domain_age_days': domain_age_days},
        ))

    # Rule 2: Payment without known gateway on youngish domain
    has_payment = bool(signal_ids & {'HAS_CARD_FIELDS', 'HAS_UPI_ID_FIELD'})
    has_gateway = 'RECOGNIZED_GATEWAY' in signal_ids
    if has_payment and not has_gateway and domain_age_days is not None and domain_age_days < 180:
        combo_signals.append(Signal(
            id='PAYMENT_WITHOUT_KNOWN_GATEWAY',
            points=10,
            severity='medium',
            explain=f'Page asks for payment without recognized gateway on {domain_age_days}-day-old domain',
            evidence={'domain_age_days': domain_age_days},
        ))

    # Rule 3: Brand lookalike on foreign domain with credentials
    has_brand_lookalike = bool(signal_ids & {'BRAND_TEXT_DOMAIN_MISMATCH', 'VISUAL_BRAND_MATCH'})
    has_credentials = bool(signal_ids & {'HAS_PASSWORD_FIELD', 'HAS_OTP_PIN_FIELD'})
    if has_brand_lookalike and has_credentials:
        combo_signals.append(Signal(
            id='BRAND_LOOKALIKE_ON_FOREIGN_DOMAIN',
            points=25,
            severity='high',
            explain='Page impersonates a brand and asks for credentials',
        ))

    return combo_signals
