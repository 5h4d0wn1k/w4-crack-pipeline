"""Documentation lab placeholders + domain constants.

Per the flagship OpSec checklist: NO real-world identifiers are ever used as
defaults. Everything here is a documentation-lab value:

  * network range 192.0.2.0/24 (RFC 5737 test-net-1)
  * example MACs 00:11:22:33:44:55-style
  * example SSIDs "lab-ap" / "lab-guest"
"""

DOC_NETWORK_RANGE = "192.0.2.0/24"
DOC_HOST_ADDRESSES = ("192.0.2.10", "192.0.2.20")
DOC_MAC_ADDRESSES = ("00:11:22:33:44:55", "00:11:22:33:44:66", "00:11:22:33:44:77")
DOC_SSIDS = ("lab-ap", "lab-guest")

LAB_MARKER = "lab"  # captured traffic / hosts must carry this token ("marked lab")

HASHCAT_MODE_WPA = 22000  # WPA-PBKDF2 PMKID+EAPOL

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
DEFAULT_RULES = "/usr/share/hashcat/rules/best64.rule"

# Offline self-test vector. WPA-PBKDF2 PMKID+EAPOL (mode 22000) example hash
# from hashcat's example-hashes documentation (hashcat.net/wiki/example_hashes
# and github.com/hashcat/hashcat/docs/hashcat-example-hashes.md). ESSID is the
# hex below = "hashcat-essid"; the documented password is "hashcat!".
SELFTEST_HASH = (
    "WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*"
    "686173686361742d6573736964***"
)
SELFTEST_PASSWORD = "hashcat!"

CAPTURE_EXTS = (".cap", ".pcap", ".pcapng", ".pcap.gz", ".cap.gz")