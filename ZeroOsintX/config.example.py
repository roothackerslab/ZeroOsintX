# config.example.py - AegisOSINT Configuration Example
# Copy this to config.py and customize

class AegisConfig:
    """AegisOSINT Configuration"""
    
    # ==================== BASIC SETTINGS ====================
    TOOL_NAME = "AegisOSINT Pro"
    TOOL_VERSION = "4.0.0"
    USER_AGENT = "AegisOSINT-Pro/4.0 (+https://roothackerslab.com)"
    
    # ==================== PERFORMANCE ====================
    TIMEOUT = 8                    # Request timeout (seconds)
    MAX_THREADS = 10               # Max concurrent threads
    RETRY_ATTEMPTS = 2             # Retry failed requests
    RETRY_DELAY = 1                # Delay between retries
    
    # ==================== SUBDOMAIN WORDLIST ====================
    SUBDOMAIN_WORDLIST = [
        # Common subdomains
        "www", "mail", "ftp", "dev", "api", "test", "admin", "panel",
        "dashboard", "staging", "prod", "backup", "cache", "cdn", "vpn",
        
        # Services
        "proxy", "gateway", "auth", "oauth", "login", "secure", "portal",
        "app", "mobile", "static", "images", "assets", "files", "data",
        
        # Infrastructure
        "database", "db", "sql", "mysql", "postgres", "mongo", "redis",
        
        # Development
        "dev", "develop", "development", "test", "testing", "qa",
        "staging", "pre-prod", "production",
        
        # Internal services
        "internal", "intranet", "vpn", "ssh", "rdp",
        "jenkins", "gitlab", "github", "git",
        
        # Email & Communication
        "mail", "smtp", "pop3", "imap", "webmail",
        "chat", "slack", "teams", "discord",
        
        # Monitoring & Analytics
        "monitor", "monitoring", "analytics", "kibana", "grafana",
        "prometheus", "splunk", "datadog",
    ]
    
    # ==================== API ENDPOINTS ====================
    APIs = {
        "ip_api": "https://ip-api.com/json/",
        "hunter_io": "https://api.hunter.io/v2/",
        "shodan": "https://api.shodan.io/",  # Requires API key
        "virustotal": "https://www.virustotal.com/api/v3/",  # Requires API key
    }
    
    # ==================== API KEYS (Optional) ====================
    API_KEYS = {
        "hunter_io": "",      # Get free tier from hunter.io
        "shodan": "",         # Get from shodan.io
        "virustotal": "",     # Get from virustotal.com
    }
    
    # ==================== OUTPUT SETTINGS ====================
    OUTPUT_DIR = "aegis_reports/"
    OUTPUT_FORMATS = ["json", "html", "csv"]  # Default formats
    REPORT_NAME_FORMAT = "aegis_{target}_{timestamp}"
    
    # ==================== LOGGING ====================
    LOG_FILE = "aegis_debug.log"
    LOG_LEVEL = "INFO"  # DEBUG, INFO, WARNING, ERROR
    VERBOSE = False
    
    # ==================== RATE LIMITING ====================
    RATE_LIMIT_ENABLED = True
    RATE_LIMIT_REQUESTS = 10  # Requests per minute
    RATE_LIMIT_DELAY = 6      # Seconds between requests
    
    # ==================== PROXY SETTINGS ====================
    USE_PROXY = False
    PROXIES = {
        "http": "http://proxy.example.com:8080",
        "https": "http://proxy.example.com:8080",
    }
    
    # ==================== SCANNING OPTIONS ====================
    SCAN_OPTIONS = {
        "check_certs": True,
        "follow_redirects": True,
        "verify_ssl": True,
        "check_ssl_info": True,
        "get_headers": True,
        "extract_metadata": True,
    }
    
    # ==================== ETHICAL BOUNDARIES ====================
    ETHICAL_CHECKS = {
        "respect_robots_txt": True,
        "honor_rate_limits": True,
        "check_targets": True,
        "use_descriptive_ua": True,
    }
    
    # ==================== ADVANCED OPTIONS ====================
    DNS_SERVERS = [
        "8.8.8.8",         # Google
        "1.1.1.1",         # Cloudflare
        "208.67.222.222",  # OpenDNS
    ]
    
    DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    
    SOCIAL_PLATFORMS = {
        "GitHub": "https://github.com/{}",
        "Instagram": "https://instagram.com/{}",
        "Twitter": "https://x.com/{}",
        "LinkedIn": "https://linkedin.com/in/{}",
        "TikTok": "https://tiktok.com/@{}",
        "Reddit": "https://reddit.com/user/{}",
        "YouTube": "https://youtube.com/@{}",
    }
    
    # ==================== EXCLUSIONS ====================
    SKIP_DOMAINS = []  # Domains to skip
    SKIP_IPS = ["127.0.0.1", "::1"]  # IPs to skip
    
    # ==================== NOTIFICATION ====================
    NOTIFY_ON_COMPLETION = False
    NOTIFICATION_EMAIL = ""
    
    @classmethod
    def get_setting(cls, key, default=None):
        """Safe setting getter"""
        return getattr(cls, key, default)
    
    @classmethod
    def validate(cls):
        """Validate configuration"""
        errors = []
        
        if cls.TIMEOUT < 1:
            errors.append("TIMEOUT must be at least 1 second")
        
        if cls.MAX_THREADS < 1:
            errors.append("MAX_THREADS must be at least 1")
        
        if not cls.SUBDOMAIN_WORDLIST:
            errors.append("SUBDOMAIN_WORDLIST cannot be empty")
        
        return errors if errors else True


# ==================== QUICK PRESETS ====================
class Presets:
    """Preset configurations for different scenarios"""
    
    @staticmethod
    def fast():
        """Fast scan - fewer threads, smaller wordlist"""
        AegisConfig.MAX_THREADS = 5
        AegisConfig.SUBDOMAIN_WORDLIST = AegisConfig.SUBDOMAIN_WORDLIST[:10]
    
    @staticmethod
    def thorough():
        """Thorough scan - more threads, complete wordlist"""
        AegisConfig.MAX_THREADS = 20
        AegisConfig.TIMEOUT = 15
    
    @staticmethod
    def stealth():
        """Stealth mode - slow, respectful scanning"""
        AegisConfig.MAX_THREADS = 2
        AegisConfig.RATE_LIMIT_DELAY = 2
        AegisConfig.RATE_LIMIT_ENABLED = True


# ==================== ENVIRONMENT-SPECIFIC ====================
import os

if os.getenv("AEGIS_ENV") == "production":
    AegisConfig.LOG_LEVEL = "WARNING"
    AegisConfig.VERBOSE = False
elif os.getenv("AEGIS_ENV") == "development":
    AegisConfig.LOG_LEVEL = "DEBUG"
    AegisConfig.VERBOSE = True


# ==================== USAGE ====================
if __name__ == "__main__":
    # Validate config
    validation = AegisConfig.validate()
    if validation is True:
        print("✅ Configuration is valid!")
    else:
        print("❌ Configuration errors:")
        for error in validation:
            print(f"  - {error}")
    
    # Use preset
    Presets.thorough()
    print(f"✓ Applied 'thorough' preset")
    
    # Access settings
    timeout = AegisConfig.get_setting("TIMEOUT")
    print(f"✓ Timeout: {timeout}s")
