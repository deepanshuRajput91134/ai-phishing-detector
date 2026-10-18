import os
import random
import pandas as pd
from typing import Tuple

# Seed for reproducibility
random.seed(42)

def generate_url_dataset(num_samples_per_class: int = 1200) -> pd.DataFrame:
    """
    Generates a balanced dataset of legitimate and phishing URLs.
    Includes various structural patterns, domain spoofing, and lexical tricks.
    """
    legit_domains = [
        "google.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com",
        "apple.com", "youtube.com", "linkedin.com", "stackoverflow.com", "nytimes.com",
        "bbc.co.uk", "cloudflare.com", "nih.gov", "mit.edu", "stanford.edu",
        "python.org", "mozilla.org", "medium.com", "reddit.com", "dropbox.com",
        "slack.com", "salesforce.com", "zoom.us", "spotify.com", "openai.com"
    ]

    legit_paths = [
        "", "/", "/home", "/about", "/contact", "/terms-and-conditions",
        "/docs/guide/introduction", "/api/v1/users", "/posts/2026/03/update",
        "/search?q=machine+learning&page=2", "/products/category/books?sort=popular",
        "/profile/settings", "/pricing", "/features/overview", "/download/latest",
        "/blog/understanding-cybersecurity", "/explore/popular-repositories"
    ]

    legitimate_urls = []
    for _ in range(num_samples_per_class):
        domain = random.choice(legit_domains)
        path = random.choice(legit_paths)
        scheme = "https://" if random.random() > 0.1 else "http://"
        # Subdomains
        if random.random() > 0.6:
            sub = random.choice(["blog", "docs", "developer", "api", "shop", "support", "en", "status"])
            domain = f"{sub}.{domain}"
        legitimate_urls.append(f"{scheme}{domain}{path}")

    # Phishing patterns
    phish_brands = ["paypal", "apple", "netflix", "microsoft", "google", "chase", "wellsfargo", "bankofamerica", "binance", "coinbase", "meta", "amazon"]
    phish_actions = ["login", "verify", "secure", "update", "billing", "confirm", "account-alert", "security-check", "resolution-center"]
    phish_tlds = ["xyz", "top", "club", "buzz", "cf", "tk", "ml", "gq", "work", "info", "net", "support", "online"]
    phish_files = ["login.php", "signin.html", "verify.aspx", "index.php?cmd=_login-run", "update_credentials.html", "auth.php?token=92842"]

    phishing_urls = []
    for _ in range(num_samples_per_class):
        pattern_type = random.choice(["typosquat", "ip_address", "subdomain_trap", "shortener", "entropy_dga", "hyphen_soup"])
        
        if pattern_type == "typosquat":
            brand = random.choice(phish_brands)
            action = random.choice(phish_actions)
            tld = random.choice(phish_tlds)
            scheme = random.choice(["http://", "https://"])
            url = f"{scheme}{brand}-{action}.{tld}/{random.choice(phish_files)}"
            
        elif pattern_type == "ip_address":
            ip = f"{random.randint(11, 220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            port = f":{random.choice([8080, 8443, 8000, 8888])}" if random.random() > 0.5 else ""
            url = f"http://{ip}{port}/{random.choice(phish_actions)}/{random.choice(phish_files)}"
            
        elif pattern_type == "subdomain_trap":
            brand = random.choice(phish_brands)
            evil_domain = f"auth-portal-{random.randint(100, 999)}.{random.choice(phish_tlds)}"
            url = f"http://{brand}.secure.account.verify.{evil_domain}/sign-in"
            
        elif pattern_type == "shortener":
            short_svc = random.choice(["bit.ly", "tinyurl.com", "cutt.ly", "t.co", "is.gd"])
            code = "".join(random.choices("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=7))
            url = f"https://{short_svc}/{code}"
            
        elif pattern_type == "entropy_dga":
            rand_str = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16))
            tld = random.choice(phish_tlds)
            url = f"http://{rand_str}.{tld}/session/auth"
            
        else: # hyphen_soup
            brand = random.choice(phish_brands)
            action1 = random.choice(phish_actions)
            action2 = random.choice(phish_actions)
            url = f"http://secure-{brand}-{action1}-{action2}.com/login"

        phishing_urls.append(url)

    df_legit = pd.DataFrame({"url": legitimate_urls, "label": 0})
    df_phish = pd.DataFrame({"url": phishing_urls, "label": 1})
    df = pd.concat([df_legit, df_phish], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def generate_email_dataset(num_samples_per_class: int = 1000) -> pd.DataFrame:
    """
    Generates a balanced dataset of legitimate and phishing emails.
    Covers diverse business communications vs modern social engineering attacks.
    """
    # Legitimate templates
    legit_templates = [
        ("Weekly Team Sync Agenda", "Hi team,\nHere is the agenda for tomorrow's sprint sync:\n1. Roadmap review\n2. Q3 bug fixes\n3. Database migration schedule.\nPlease review the docs attached on Confluence beforehand. See you all at 10 AM."),
        ("Order Confirmation #849204", "Hello Alex,\nThank you for your purchase with Acme Store. Your order #849204 has been confirmed and is currently being prepared for shipment. You can track your package status on our official portal anytime."),
        ("Flight Booking Itinerary - Delta Airlines", "Dear Passenger,\nYour flight from Seattle to San Francisco is scheduled for departure this Friday. Please arrive 2 hours prior to board. You may check in online using your confirmation code: DL492X."),
        ("Code Review Requested: PR #142", "Deepanshu,\nSarah has requested your review on Pull Request #142: 'Refactor authentication middleware'. Please leave your feedback directly on the GitHub pull request when you have time."),
        ("Invoice for Consultation Services (INV-2026-08)", "Hi Sarah,\nPlease find attached our monthly consulting invoice for October 2026. Payment terms are net 30 via direct ACH transfer as established in our MSA. Let us know if you have questions."),
        ("Security Notice: New login from Chrome on macOS", "Hi Alex,\nWe noticed a successful login to your Google account from Chrome on macOS in Bangalore, India. If this was you, no action is required. If not, check your account activity settings."),
        ("Lunch this Friday?", "Hey mate,\nAre you free to grab lunch this Friday around 1 PM near the tech park? Let me know if that works or if another day is better."),
        ("Monthly Newsletter: Tech & AI Highlights", "Hello Reader,\nWelcome to the October edition of AI Weekly! In this issue: emerging transformer architectures, open-weights benchmarks, and best practices in container security."),
        ("Doctor's Appointment Reminder", "Hello,\nThis is a friendly reminder of your upcoming dental appointment on Thursday at 3:30 PM. Please bring your insurance card. Reply YES to confirm or call to reschedule."),
        ("Gym Membership Renewal Receipt", "Hi member,\nYour monthly fitness membership dues of $45 have been processed successfully. Your receipt is available on your member dashboard. Thank you for staying active with us!")
    ]

    # Phishing templates
    phish_templates = [
        ("URGENT: Immediate Account Suspension Notice", "Dear Customer,\nWe detected unusual login attempts to your bank account from an unknown IP address. To prevent unauthorized transactions, your access has been temporarily suspended.\nClick the link below immediately to verify your credentials within 24 hours:\nhttp://192.168.1.105/bank/verify-identity.php\nFailure to act will result in permanent account termination."),
        ("ACTION REQUIRED: Password Expired - Reset Now", "Attention User,\nYour company portal password has expired today. You are required to update your login password immediately to retain access to corporate VPN and mailbox.\nVerify your password here: http://secure-corporate-auth-update.xyz/login\nIT Support Department."),
        ("Final Warning: Unauthorized Transaction of $1,420.00", "Dear Account Holder,\nA debit card charge of $1,420.00 at 'BestBuy Electronics' was requested on your account. If you did not authorize this payment, cancel it right now by entering your card details:\nhttp://chase-security-cancelation.top/auth\nDo not ignore this urgent alert."),
        ("Notification: Direct Deposit Payroll Update Needed", "Dear Employee,\nThere was an issue processing your direct deposit for this month's payroll cycle. To avoid delays in your salary transfer, click here to validate your bank routing number and SSN:\nhttp://payroll-portal-hr-verify.info/update\nHuman Resources Division"),
        ("Apple ID Locked Due to Suspicious Activity", "Dear Client,\nYour Apple ID has been locked for security reasons. Someone in Moscow, Russia attempted to access your iCloud storage and purchases.\nUnlock and confirm your identity now: http://appleid-unlock-verification.cf/signin\nApple Support Team"),
        ("Overdue Invoice #99382 - Immediate Wire Transfer Required", "Dear Sir/Madam,\nYour company has an outstanding unpaid balance of $8,950.00. This is your final legal notice before legal proceedings and collections are initiated.\nReview and pay your overdue invoice here: http://billing-portal-invoice993.work/pay\nAccounting Team"),
        ("Tax Refund Available: Claim Your $850.00 Credit", "Dear Taxpayer,\nAfter the latest annual tax review, you are eligible to receive a tax refund of $850.00. Submit your banking credentials and card PIN on the official portal to claim your deposit:\nhttp://irs-tax-refund-portal.buzz/claim\nInternal Revenue Service"),
        ("Netflix: Update Payment Method to Avoid Interruption", "Dear Member,\nWe were unable to process your monthly subscription fee. Your streaming service will be terminated within 12 hours unless you update your credit card details immediately:\nhttp://netflix-billing-update-center.club/update\nThe Netflix Team"),
        ("Congratulations! You Have Won the International Lottery", "Attention Valued Winner,\nYour email address was selected in the Google-UK Annual Lottery Draw! You have been awarded $2,500,000.00.\nTo claim your prize, send your full name, passport copy, and bank account number to claim-agent@lottery-prizes-online.net."),
        ("Cryptocurrency Security Alert: Unauthorized Withdrawal", "Dear User,\nA withdrawal of 0.85 BTC was initiated from your wallet. If you did not make this transaction, cancel it immediately by entering your 12-word secret recovery seed phrase:\nhttp://binance-wallet-safeguard.xyz/cancel-tx")
    ]

    emails_data = []
    
    # Generate legitimate emails with slight random variations
    for _ in range(num_samples_per_class):
        subj, body = random.choice(legit_templates)
        # Add slight variation
        if random.random() > 0.5:
            ref = random.randint(1000, 99999)
            subj = f"{subj} [Ref: #{ref}]"
        emails_data.append({"subject": subj, "body": body, "label": 0})

    # Generate phishing emails with slight random variations
    for _ in range(num_samples_per_class):
        subj, body = random.choice(phish_templates)
        if random.random() > 0.4:
            alert = random.choice(["[CRITICAL ALERT]", "ALERT:", "URGENT:", "FINAL NOTICE:"])
            subj = f"{alert} {subj}"
        emails_data.append({"subject": subj, "body": body, "label": 1})

    df = pd.DataFrame(emails_data).sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def ensure_datasets(data_dir: str) -> Tuple[str, str]:
    """Generates and saves datasets if they do not already exist."""
    os.makedirs(data_dir, exist_ok=True)
    url_path = os.path.join(data_dir, "urls_dataset.csv")
    email_path = os.path.join(data_dir, "emails_dataset.csv")

    if not os.path.exists(url_path):
        print(f"[*] Generating realistic URL phishing dataset...")
        df_url = generate_url_dataset(num_samples_per_class=1500)
        df_url.to_csv(url_path, index=False)
        print(f"[+] Saved URL dataset to {url_path} ({len(df_url)} records)")
    else:
        print(f"[*] Using existing URL dataset: {url_path}")

    if not os.path.exists(email_path):
        print(f"[*] Generating realistic Email phishing dataset...")
        df_email = generate_email_dataset(num_samples_per_class=1200)
        df_email.to_csv(email_path, index=False)
        print(f"[+] Saved Email dataset to {email_path} ({len(df_email)} records)")
    else:
        print(f"[*] Using existing Email dataset: {email_path}")

    return url_path, email_path

if __name__ == "__main__":
    ensure_datasets(os.path.join(os.path.dirname(__file__), "..", "data"))
