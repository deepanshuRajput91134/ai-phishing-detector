import re
import html
from features import URGENT_PHRASES, CREDENTIAL_LURES, FINANCIAL_LURES, IMPERSONAL_GREETINGS


def highlight_email_threat_cues(text: str) -> str:
    """
    Produces HTML annotated with Explainable AI (XAI) color-coded badges
    highlighting the exact words that triggered the machine learning model.
    """
    if not text:
        return ""

    escaped = html.escape(text)

    # 1. Credential Lures (Red)
    for phrase in sorted(CREDENTIAL_LURES, key=len, reverse=True):
        pattern = re.compile(rf"\b({re.escape(phrase)})\b", re.IGNORECASE)
        escaped = pattern.sub(
            r'<span style="background-color: #FEE2E2; color: #991B1B; padding: 2px 6px; border-radius: 4px; font-weight: bold; border: 1px solid #F87171;" title="[XAI: Credential Harvesting Lure]">\1</span>',
            escaped
        )

    # 2. Urgency & Panic Triggers (Orange)
    for phrase in sorted(URGENT_PHRASES, key=len, reverse=True):
        pattern = re.compile(rf"\b({re.escape(phrase)})\b", re.IGNORECASE)
        escaped = pattern.sub(
            r'<span style="background-color: #FFEDD5; color: #9A3412; padding: 2px 6px; border-radius: 4px; font-weight: bold; border: 1px solid #FB923C;" title="[XAI: Psychological Urgency Trigger]">\1</span>',
            escaped
        )

    # 3. Financial & Prize Scams (Yellow)
    for phrase in sorted(FINANCIAL_LURES, key=len, reverse=True):
        pattern = re.compile(rf"\b({re.escape(phrase)})\b", re.IGNORECASE)
        escaped = pattern.sub(
            r'<span style="background-color: #FEF9C3; color: #854D0E; padding: 2px 6px; border-radius: 4px; font-weight: bold; border: 1px solid #FACC15;" title="[XAI: Financial Scam Indicator]">\1</span>',
            escaped
        )

    # 4. Impersonal Greetings (Purple)
    for phrase in sorted(IMPERSONAL_GREETINGS, key=len, reverse=True):
        pattern = re.compile(rf"\b({re.escape(phrase)})\b", re.IGNORECASE)
        escaped = pattern.sub(
            r'<span style="background-color: #F3E8FF; color: #6B21A8; padding: 2px 6px; border-radius: 4px; font-weight: bold; border: 1px solid #C084FC;" title="[XAI: Impersonal Phishing Greeting]">\1</span>',
            escaped
        )

    # 5. Highlight URLs (Blue)
    url_pattern = re.compile(r'(https?://[^\s<>"\'`]+)', re.IGNORECASE)
    escaped = url_pattern.sub(
        r'<span style="background-color: #E0F2FE; color: #0369A1; padding: 2px 6px; border-radius: 4px; font-weight: bold; text-decoration: underline;" title="[XAI: Embedded External Hyperlink]">\1</span>',
        escaped
    )

    # Convert newlines to HTML breaks
    return escaped.replace("\n", "<br>")
