import re


PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "GitHub Token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "Generic API Key": re.compile(
        r"api[_-]?key\s*=\s*[\"'][^\"']+[\"']",
        re.IGNORECASE
    ),
    "Password": re.compile(
        r"password\s*=\s*[\"'][^\"']+[\"']",
        re.IGNORECASE
    ),
    "Username": re.compile(
        r"username\s*=\s*[\"'][^\"']+[\"']",
        re.IGNORECASE
    ),
    "Email Address": re.compile(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    ),
}
