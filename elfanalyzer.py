from llm_analysis import analyze_malware
import os
import re
import csv
import math
import json
import base64
import hashlib
import struct
import itertools
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection, NoteSection
from elftools.elf.dynamic import DynamicSection
from elftools.elf.relocation import RelocationSection
from elftools.common.exceptions import ELFError

# Optional assembly analysis (requires capstone)
try:
    from asmanalyzer import ASMAnalyzer, capstone_available
    _ASM_AVAILABLE = capstone_available()
except ImportError:
    _ASM_AVAILABLE = False
    ASMAnalyzer    = None


class ELFAnalyzer:
    """
    Library for extracting characteristics from ELF binaries.

    Usage:
        from elfanalyzer import ELFAnalyzer

        analyzer = ELFAnalyzer("/path/to/binary")
        analyzer.analyze()

        print(analyzer.imports)
        print(analyzer.hashes)
        print(analyzer.sections)
        print(analyzer.strings)
        print(analyzer.file_size)
        print(analyzer.entropy)

    Methods:
        analyze()                   - Run full analysis
        compute_hashes()            - Compute MD5 and SHA256
        extract_printable_strings() - Extract ASCII strings
        parse_sections()            - Get ELF sections
        parse_imports()             - Get imported functions
        parse_symbols()             - Get all named symbols (.symtab + .dynsym)
        get_file_size()             - Get file size in bytes
        compute_entropy()           - Compute Shannon entropy per section and whole binary
        detect_security_features()  - Detect NX, PIE, canary, RELRO, stripped, debug, FORTIFY
        determine_static_dynamic()  - Detect static vs dynamic linking
        get_architecture()          - Get CPU architecture, bit-width, endianness, and ABI
        to_pandas_csv(path)         - Export flat feature row to CSV (appendable)
        to_numpy_npz(path)          - Export numeric features to .npz archive
    """

    # Maximum file size accepted for analysis (512 MB)
    MAX_FILE_SIZE = 512 * 1024 * 1024

    # Bounds on min_str_len to prevent regex DoS
    MIN_STR_LEN_FLOOR   = 1
    MIN_STR_LEN_CEILING = 256

    def __init__(self, path: str, min_str_len: int = 4):
        """
        Initialize the analyzer with a path to an ELF binary.

        Args:
            path        (str): Path to the ELF binary
            min_str_len (int): Minimum printable string length (default: 4)

        Raises:
            ValueError:    If path is empty, not a regular file, or min_str_len is out of range.
            PermissionError: If the file cannot be read.
            OSError:       If the file exceeds MAX_FILE_SIZE.
        """
        # -- path validation --
        if not path or not isinstance(path, str):
            raise ValueError("path must be a non-empty string")
        resolved = Path(path).resolve()
        if not resolved.exists():
            raise FileNotFoundError(f"File not found: {path}")
        if not resolved.is_file():
            raise ValueError(f"Path is not a regular file: {path}")
        if not os.access(resolved, os.R_OK):
            raise PermissionError(f"File is not readable: {path}")
        size = resolved.stat().st_size
        if size > self.MAX_FILE_SIZE:
            raise OSError(
                f"File size {size:,} bytes exceeds limit of {self.MAX_FILE_SIZE:,} bytes"
            )

        # -- min_str_len validation --
        if not isinstance(min_str_len, int) or not (self.MIN_STR_LEN_FLOOR <= min_str_len <= self.MIN_STR_LEN_CEILING):
            raise ValueError(
                f"min_str_len must be an integer between "
                f"{self.MIN_STR_LEN_FLOOR} and {self.MIN_STR_LEN_CEILING}"
            )

        self.path        = str(resolved)   # store canonical absolute path
        self.min_str_len = min_str_len
        self.hashes      = {}
        self.sections    = []
        self.strings     = []
        self.imports     = []
        self.exports     = {}
        self.file_size   = 0
        self.static      = "static"
        self.security    = {}
        self.entropy     = {}
        self.arch        = {}
        self.symbols     = []   # all non-empty named symbols from .symtab + .dynsym
        self.iocs        = {}   # populated by analyze_iocs()
        self.asm         = {}   # populated by analyze_asm()

    # ------------------------------------------------------------------ #
    #  Core analysis methods                                               #
    # ------------------------------------------------------------------ #

    def compute_hashes(self) -> dict:
        """
        Compute MD5 and SHA256 hashes of the binary.

        Returns:
            dict: Keys 'md5' and 'sha256' with hex digest strings

        Raises:
            IOError: If the file cannot be read.
        """
        hashes = {alg: hashlib.new(alg) for alg in ("md5", "sha256")}
        try:
            with open(self.path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    for h in hashes.values():
                        h.update(chunk)
        except OSError as e:
            raise IOError(f"Failed to read file for hashing: {self.path}") from e
        self.hashes = {alg: h.hexdigest() for alg, h in hashes.items()}
        return self.hashes

    # Cap on number of strings extracted to prevent memory exhaustion
    MAX_STRINGS = 100_000

    def extract_printable_strings(self) -> list:
        """
        Extract printable ASCII strings from the binary (like the `strings` command).

        Returns:
            list: Unique printable strings found in the binary (capped at MAX_STRINGS)
        """
        # min_str_len is already validated as an integer in [1, 256] so safe to interpolate
        pattern = re.compile(rb"[ -~]{" + str(self.min_str_len).encode() + rb",}")
        try:
            with open(self.path, "rb") as f:
                data = f.read()
        except OSError as e:
            raise IOError(f"Failed to read file for string extraction: {self.path}") from e

        matches = pattern.findall(data)
        seen    = set()
        result  = []
        for s in matches:
            decoded = s.decode("ascii", errors="replace").strip()
            if decoded and decoded not in seen:
                seen.add(decoded)
                result.append(decoded)
                if len(result) >= self.MAX_STRINGS:
                    break
        self.strings = result
        return self.strings

    def detect_security_features(self) -> dict:
        """
        Detect common security hardening features in the ELF binary.

        Checks for:
            - NX        : Non-executable stack (GNU_STACK segment not executable)
            - PIE       : Position Independent Executable (ET_DYN type)
            - Canary    : Stack smashing protection (__stack_chk_fail in imports)
            - RELRO     : Relocation Read-Only (none / partial / full)
            - Stripped  : Symbol table removed (.symtab missing)
            - Debug     : Compiled with debug symbols (.debug_info present)
            - FORTIFY   : Fortified libc functions (_chk suffix in imports)

        Returns:
            dict: Keys: nx, pie, canary, relro, stripped, debug, fortify
        """
        features = {
            "nx":       False,
            "pie":      False,
            "canary":   False,
            "relro":    "none",
            "stripped": True,
            "debug":    False,
            "fortify":  False,
        }

        try:
            with open(self.path, "rb") as f:
                elf = ELFFile(f)

                if elf.header["e_type"] == "ET_DYN":
                    features["pie"] = True

                for segment in elf.iter_segments():
                    if segment["p_type"] == "PT_GNU_STACK":
                        features["nx"] = not bool(segment["p_flags"] & 0x1)
                    if segment["p_type"] == "PT_GNU_RELRO":
                        features["relro"] = "partial"

                for section in elf.iter_sections():
                    if section.name == ".symtab":
                        features["stripped"] = False
                    if section.name == ".debug_info":
                        features["debug"] = True
                    if isinstance(section, DynamicSection):
                        for tag in section.iter_tags():
                            if tag.entry.d_tag == "DT_BIND_NOW":
                                features["relro"] = "full"
                            if tag.entry.d_tag == "DT_FLAGS":
                                if tag["d_val"] & 0x8:
                                    features["relro"] = "full"
                    if isinstance(section, SymbolTableSection):
                        if section.name != ".dynsym":
                            continue
                        for sym in section.iter_symbols():
                            if "__stack_chk_fail" in sym.name:
                                features["canary"] = True
                            if sym.name.endswith("_chk"):
                                features["fortify"] = True
        except ELFError as e:
            raise ValueError(f"Failed to parse ELF security features: {e}") from e

        self.security = features
        return self.security

    def compute_entropy(self) -> dict:
        """
        Compute Shannon entropy for the whole binary and each ELF section.

        Shannon entropy is measured in bits per byte (0.0 – 8.0).
        High entropy (>= 7.0) often indicates encrypted, compressed, or packed data.

        Returns:
            dict: Keys:
                '_whole_binary' : float  - entropy of the entire file
                '<section_name>': float  - entropy of each named ELF section
        """
        def _shannon(data: bytes) -> float:
            if not data:
                return 0.0
            counts = [0] * 256
            for byte in data:
                counts[byte] += 1
            length = len(data)
            entropy = 0.0
            for c in counts:
                if c:
                    p = c / length
                    entropy -= p * math.log2(p)
            return round(entropy, 6)

        result = {}

        try:
            with open(self.path, "rb") as f:
                whole = f.read()
        except OSError as e:
            raise IOError(f"Failed to read file for entropy: {self.path}") from e
        result["_whole_binary"] = _shannon(whole)

        try:
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    name = section.name if section.name else f"<unnamed@{hex(section['sh_offset'])}>"
                    result[name] = _shannon(section.data())
        except ELFError as e:
            raise ValueError(f"Failed to parse ELF sections for entropy: {e}") from e

        self.entropy = result
        return self.entropy

    def get_file_size(self) -> int:
        """
        Get the size of the binary in bytes.

        Returns:
            int: File size in bytes
        """
        self.file_size = os.path.getsize(self.path)
        return self.file_size

    def parse_sections(self) -> list:
        """
        Extract all sections from the ELF binary.

        Returns:
            list: List of dicts with keys: name, type, flags, address, offset, size, align
        """
        sections = []
        try:
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    sections.append({
                        "name":    section.name,
                        "type":    section["sh_type"],
                        "flags":   hex(section["sh_flags"]),
                        "address": hex(section["sh_addr"]),
                        "offset":  hex(section["sh_offset"]),
                        "size":    section["sh_size"],
                        "align":   section["sh_addralign"],
                    })
        except ELFError as e:
            raise ValueError(f"Failed to parse ELF sections: {e}") from e
        self.sections = sections
        return self.sections

    def parse_imports(self) -> list:
        """
        Extract imported functions from the ELF binary.

        Returns:
            list: List of dicts with keys: name, type, binding
        """
        imports = []
        try:
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    if not isinstance(section, SymbolTableSection):
                        continue
                    if section.name != ".dynsym":
                        continue
                    for sym in section.iter_symbols():
                        if sym.name == "":
                            continue
                        if sym["st_shndx"] == "SHN_UNDEF":
                            imports.append({
                                "name":    sym.name,
                                "type":    sym["st_info"]["type"],
                                "binding": sym["st_info"]["bind"],
                            })
        except ELFError as e:
            raise ValueError(f"Failed to parse ELF imports: {e}") from e
        self.imports = imports
        return self.imports

    def determine_static_dynamic(self) -> str:
        """
        Determine if the binary is statically or dynamically linked.

        Returns:
            str: 'static' or 'dynamic'
        """
        try:
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                for segment in elf.iter_segments():
                    if segment["p_type"] == "PT_DYNAMIC":
                        self.static = "dynamic"
                        return "dynamic"
                for section in elf.iter_sections():
                    if section.name == ".dynamic":
                        self.static = "dynamic"
                        return "dynamic"
        except ELFError as e:
            raise ValueError(f"Failed to determine link type: {e}") from e
        return "static"

    def get_architecture(self) -> dict:
        """
        Extract CPU architecture information from the ELF header.

        Returns:
            dict: Keys:
                machine      (str)  - e.g. 'x86_64', 'ARM', 'AArch64', 'MIPS', 'RISC-V', etc.
                bits         (int)  - 32 or 64
                endianness   (str)  - 'little' or 'big'
                abi          (str)  - OS/ABI string (e.g. 'ELFOSABI_LINUX', 'ELFOSABI_NONE')
                elf_type     (str)  - ELF type: ET_EXEC, ET_DYN, ET_REL, ET_CORE
                entry_point  (str)  - Entry point address as hex string (e.g. '0x401080')
        """
        # pyelftools e_machine strings → friendly names
        _machine_map = {
            "EM_386":     "x86",
            "EM_860":     "i860",
            "EM_X86_64":  "x86_64",
            "EM_ARM":     "ARM",
            "EM_AARCH64": "AArch64",
            "EM_MIPS":    "MIPS",
            "EM_PPC":     "PowerPC",
            "EM_PPC64":   "PowerPC64",
            "EM_S390":    "IBM S/390",
            "EM_SPARC":   "SPARC",
            "EM_SPARCV9": "SPARCv9",
            "EM_IA_64":   "IA-64",
            "EM_RISCV":   "RISC-V",
            "EM_LOONGARCH": "LoongArch",
            "EM_68K":     "Motorola 68k",
            "EM_SH":      "SuperH",
            "EM_XTENSA":  "Xtensa",
            "EM_AVR":     "AVR",
            "EM_MSP430":  "MSP430",
        }

        try:
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                hdr     = elf.header
                machine = hdr["e_machine"]
                self.arch = {
                    "machine":     _machine_map.get(machine, machine),
                    "bits":        elf.elfclass,
                    "endianness":  "little" if elf.little_endian else "big",
                    "abi":         hdr["e_ident"]["EI_OSABI"],
                    "elf_type":    hdr["e_type"],
                    "entry_point": hex(hdr["e_entry"]),
                }
        except ELFError as e:
            raise ValueError(f"Failed to parse ELF architecture: {e}") from e

        return self.arch

    def parse_symbols(self) -> list:
        """
        Extract all named symbols from .symtab and .dynsym.

        Collects both local/global defined symbols (not just imports), which
        survive cross-architecture comparison when binaries are not stripped.

        Returns:
            list: List of dicts with keys: name, type, binding, section, value, size
        """
        seen    = set()
        symbols = []
        try:
            with open(self.path, "rb") as f:
                elf = ELFFile(f)
                for section in elf.iter_sections():
                    if not isinstance(section, SymbolTableSection):
                        continue
                    if section.name not in (".symtab", ".dynsym"):
                        continue
                    for sym in section.iter_symbols():
                        name = sym.name.strip()
                        if not name or name in seen:
                            continue
                        seen.add(name)
                        symbols.append({
                            "name":    name,
                            "type":    sym["st_info"]["type"],
                            "binding": sym["st_info"]["bind"],
                            "section": sym["st_shndx"],
                            "value":   sym["st_value"],
                            "size":    sym["st_size"],
                        })
        except ELFError as e:
            raise ValueError(f"Failed to parse ELF symbols: {e}") from e
        self.symbols = symbols
        return self.symbols

    # ------------------------------------------------------------------ #
    #  IOC / malicious string analysis                                     #
    # ------------------------------------------------------------------ #

    # ── curated word lists ─────────────────────────────────────────── #

    _SHELL_CMDS = frozenset([
        "wget","curl","fetch","tftp","ftp","nc","ncat","netcat","nmap","masscan",
        "bash","sh","ash","dash","zsh","ksh","csh","tcsh","rbash",
        "chmod","chown","chattr","install","cp","mv","dd","rm",
        "python","python3","perl","ruby","lua","php","node","nodejs",
        "crontab","at","schtasks","systemctl","service","rc.local",
        "iptables","ip6tables","ufw","firewall-cmd",
        "ssh","scp","rsync","telnet","rsh","rlogin",
        "base64","xxd","od","hexdump",
        "kill","pkill","killall","nohup","disown",
        "passwd","useradd","usermod","groupadd","visudo","sudo","su",
        "mount","umount","insmod","rmmod","modprobe","lsmod",
        "echo","printf","cat","tee","awk","sed","grep","find","xargs",
        "tar","gzip","gunzip","bzip2","unzip","7z","zip",
        "openssl","gpg","ssh-keygen",
        "screen","tmux","nohup",
        "strace","ltrace","gdb","objdump","readelf",
        "socat","proxychains","tor","proxytunnel",
        "crontab","at","batch",
    ])

    _SYSCALL_STRS = frozenset([
        "execve","execvp","execvpe","execl","execlp","execle",
        "ptrace","prctl","seccomp",
        "mmap","mprotect","madvise","munmap","mremap",
        "clone","fork","vfork","unshare","setns",
        "socket","connect","bind","listen","accept","sendto","recvfrom",
        "socketpair","setsockopt","getsockopt",
        "open","openat","creat","unlink","rename","symlink","link",
        "read","write","pread","pwrite","readv","writev",
        "ioctl","fcntl","dup","dup2","pipe","pipe2",
        "kill","tkill","tgkill","sigaction","signal","raise",
        "setuid","setgid","setresuid","setresgid","capset","capget",
        "pivot_root","chroot","mount","umount","umount2",
        "inotify_add_watch","fanotify_init","fanotify_mark",
        "memfd_create","shm_open","shmget","shmat",
        "keyctl","add_key","request_key",
        "bpf","perf_event_open","userfaultfd",
        "process_vm_readv","process_vm_writev",
        "syslog","klogctl",
    ])

    _SENSITIVE_PATH_PREFIXES = (
        "/etc/", "/proc/", "/sys/", "/dev/",
        "/tmp/", "/var/tmp/", "/run/",
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
        "/lib/", "/lib64/", "/usr/lib/",
        "/root/", "/home/",
        "/boot/", "/initrd",
    )

    _SENSITIVE_PATHS = frozenset([
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
        "/etc/crontab", "/etc/cron.d", "/etc/rc.local",
        "/etc/ssh/sshd_config", "/etc/ssh/ssh_config",
        "/etc/ld.so.preload", "/etc/ld.so.conf",
        "/proc/self/mem", "/proc/self/maps", "/proc/net/tcp",
        "/proc/net/udp", "/proc/net/fib_trie",
        "/dev/mem", "/dev/kmem", "/dev/shm",
        "/tmp/.ICE-unix", "/var/run/utmp", "/var/log/wtmp",
        "/bin/sh", "/bin/bash", "/bin/dash",
    ])

    _CRYPTO_HEADERS = [
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ]

    # ── compiled regexes (class-level, compiled once) ──────────────── #

    _RE_IPV4 = re.compile(
        r"\b((?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b"
    )
    _RE_IPV6 = re.compile(
        r"\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
        r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
        r"|:(?::[0-9a-fA-F]{1,4}){1,7}"
        r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
        r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
        r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
        r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
        r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
        r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6})\b"
    )
    _RE_URL = re.compile(
        r"\b((?:https?|ftps?|sftp)://[^\s\"'<>\x00-\x1f]{4,200})",
        re.IGNORECASE,
    )
    _RE_DOMAIN = re.compile(
        r"\b((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|co|cc|ru|cn|tk|top|xyz|info|biz|gov|edu"
        r"|onion|i2p|bit|icu|site|online|club|shop|live|app|dev|cloud"
        r"|pw|su|to|in|me|tv|us|uk|de|fr|nl|br|jp|kr|au|ca))\b",
        re.IGNORECASE,
    )
    _RE_PATH = re.compile(r"(/[a-zA-Z0-9_./-]{3,120})")
    _RE_B64 = re.compile(r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
    _RE_BTC_ADDR = re.compile(r"\b([13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")

    # ── private helpers ────────────────────────────────────────────── #

    @staticmethod
    def _shannon(data: bytes) -> float:
        if not data:
            return 0.0
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    @staticmethod
    def _is_loopback_or_broadcast(ip: str) -> bool:
        parts = ip.split(".")
        if parts[0] == "127":
            return True
        if ip in ("0.0.0.0", "255.255.255.255", "224.0.0.0"):
            return True
        return False

    @staticmethod
    def _is_valid_b64_blob(s: str) -> bool:
        """Return True if s decodes to non-trivial binary or printable content."""
        try:
            decoded = base64.b64decode(s + "==")  # pad generously
            if len(decoded) < 8:
                return False
            # Must contain at least some non-null bytes
            return any(b != 0 for b in decoded)
        except Exception:
            return False

    def _xor_scan(self, raw: bytes, min_run: int = 12, max_keys: int = 255) -> list:
        """
        Sliding-window XOR scan across raw binary data.

        For each single-byte XOR key (1–max_keys), scans for runs of
        bytes that, when XORed with that key, produce a printable ASCII
        run of length >= min_run. Returns deduplicated hits.

        Args:
            raw      (bytes): Raw binary content to scan
            min_run  (int):   Minimum decoded run length to report
            max_keys (int):   Maximum XOR key value to try (1–255)

        Returns:
            list of dicts: {key (int), decoded (str), offset (int)}
        """
        printable = frozenset(range(0x20, 0x7f)) | {0x09, 0x0a, 0x0d}
        hits      = []
        seen      = set()

        for key in range(1, max_keys + 1):
            run_start = None
            run_bytes = []
            for i, b in enumerate(raw):
                xb = b ^ key
                if xb in printable:
                    if run_start is None:
                        run_start = i
                    run_bytes.append(chr(xb))
                else:
                    if len(run_bytes) >= min_run:
                        decoded = "".join(run_bytes).strip()
                        if decoded and decoded not in seen:
                            seen.add(decoded)
                            hits.append({
                                "key":     key,
                                "offset":  run_start,
                                "decoded": decoded[:200],
                            })
                    run_start = None
                    run_bytes = []
            # flush trailing run
            if len(run_bytes) >= min_run:
                decoded = "".join(run_bytes).strip()
                if decoded and decoded not in seen:
                    seen.add(decoded)
                    hits.append({"key": key, "offset": run_start, "decoded": decoded[:200]})

        return hits

    def analyze_iocs(self) -> dict:
        """
        Analyse extracted strings and raw binary for malicious indicators.

        Requires extract_printable_strings() to have been called first.
        Also performs a raw binary pass for XOR-encoded string detection.

        Detection categories:
            ipv4        — IPv4 addresses (loopback/broadcast filtered)
            ipv6        — IPv6 addresses
            urls        — http/https/ftp/sftp URLs
            domains     — bare domain names with known TLDs
            paths       — sensitive filesystem paths
            shell_cmds  — shell/tool command strings
            syscalls    — suspicious syscall/libc function name strings
            b64_blobs   — Base64-encoded blobs (>= 32 chars, decodable)
            xor_strings — XOR-obfuscated printable string runs
            crypto      — PEM headers, Bitcoin addresses

        Severity score (0.0–1.0):
            Weighted sum of per-category hit contributions, capped at 1.0.

        Returns:
            dict: {
                counts      (dict)  per-category hit counts,
                hits        (dict)  per-category raw hit lists (strings/dicts),
                severity    (float) 0.0–1.0 suspicion rating,
                verdict     (str)   CLEAN / LOW / MEDIUM / HIGH / CRITICAL
            }
        """
        strings = self.strings  # already extracted printable strings

        # ── IPv4 ──────────────────────────────────────────────────── #
        ipv4_hits = []
        for s in strings:
            for m in self._RE_IPV4.finditer(s):
                ip = m.group(1)
                if not self._is_loopback_or_broadcast(ip) and ip not in ipv4_hits:
                    ipv4_hits.append(ip)

        # ── IPv6 ──────────────────────────────────────────────────── #
        ipv6_hits = []
        for s in strings:
            for m in self._RE_IPV6.finditer(s):
                addr = m.group(1)
                if addr not in ipv6_hits:
                    ipv6_hits.append(addr)

        # ── URLs ──────────────────────────────────────────────────── #
        url_hits = []
        for s in strings:
            for m in self._RE_URL.finditer(s):
                u = m.group(1)
                if u not in url_hits:
                    url_hits.append(u)

        # ── Domains ───────────────────────────────────────────────── #
        # Exclude anything already captured as a URL host
        url_hosts = set()
        for u in url_hits:
            try:
                host = u.split("//", 1)[1].split("/")[0].split(":")[0]
                url_hosts.add(host.lower())
            except IndexError:
                pass

        domain_hits = []
        for s in strings:
            for m in self._RE_DOMAIN.finditer(s):
                d = m.group(1).lower()
                if d not in url_hosts and d not in domain_hits:
                    domain_hits.append(d)

        # ── Sensitive file paths ───────────────────────────────────── #
        path_hits = []
        for s in strings:
            for m in self._RE_PATH.finditer(s):
                p = m.group(1)
                is_sensitive = (
                    p in self._SENSITIVE_PATHS
                    or any(p.startswith(pfx) for pfx in self._SENSITIVE_PATH_PREFIXES)
                )
                if is_sensitive and p not in path_hits:
                    path_hits.append(p)

        # ── Shell commands ────────────────────────────────────────── #
        shell_hits = []
        for s in strings:
            tok = s.strip().split()[0] if s.strip() else ""
            # match bare command token or full path basename
            base = tok.split("/")[-1].lower()
            if base in self._SHELL_CMDS and base not in shell_hits:
                shell_hits.append(base)
            # also scan substrings for embedded commands
            for cmd in self._SHELL_CMDS:
                if re.search(r'\b' + re.escape(cmd) + r'\b', s) and cmd not in shell_hits:
                    shell_hits.append(cmd)

        # ── Syscall / libc strings ────────────────────────────────── #
        syscall_hits = []
        for s in strings:
            tok = s.strip()
            if tok in self._SYSCALL_STRS and tok not in syscall_hits:
                syscall_hits.append(tok)

        # ── Base64 blobs ──────────────────────────────────────────── #
        b64_hits = []
        for s in strings:
            for m in self._RE_B64.finditer(s):
                blob = m.group(0)
                if len(blob) >= 32 and self._is_valid_b64_blob(blob) and blob not in b64_hits:
                    b64_hits.append(blob[:120])  # cap stored length

        # ── XOR-encoded strings (raw binary pass) ─────────────────── #
        xor_hits = []
        try:
            with open(self.path, "rb") as f:
                raw = f.read()
            # Only scan non-section regions to reduce noise — scan full binary
            # but cap at 8 MB to keep analysis tractable
            xor_hits = self._xor_scan(raw[:8 * 1024 * 1024])
        except OSError:
            pass

        # ── Crypto indicators ─────────────────────────────────────── #
        crypto_hits = []
        joined = "\n".join(strings)
        for header in self._CRYPTO_HEADERS:
            if header in joined and header not in crypto_hits:
                crypto_hits.append(header)
        for s in strings:
            for m in self._RE_BTC_ADDR.finditer(s):
                addr = m.group(1)
                if addr not in crypto_hits:
                    crypto_hits.append(addr)

        # ── Severity score ─────────────────────────────────────────── #
        # Weights reflect detection confidence and maliciousness signal value
        _WEIGHTS = {
            "ipv4":       0.08,
            "ipv6":       0.05,
            "urls":       0.10,
            "domains":    0.08,
            "paths":      0.07,
            "shell_cmds": 0.18,
            "syscalls":   0.08,
            "b64_blobs":  0.12,
            "xor_strings":0.18,
            "crypto":     0.14,
        }

        counts = {
            "ipv4":        len(ipv4_hits),
            "ipv6":        len(ipv6_hits),
            "urls":        len(url_hits),
            "domains":     len(domain_hits),
            "paths":       len(path_hits),
            "shell_cmds":  len(shell_hits),
            "syscalls":    len(syscall_hits),
            "b64_blobs":   len(b64_hits),
            "xor_strings": len(xor_hits),
            "crypto":      len(crypto_hits),
        }

        # Non-linear: first hit carries most weight, diminishing returns after 5
        def _contribution(n: int, weight: float) -> float:
            if n == 0:
                return 0.0
            return weight * min(1.0, 0.4 + 0.12 * n)

        raw_score = sum(
            _contribution(counts[k], w) for k, w in _WEIGHTS.items()
        )
        severity = round(min(raw_score, 1.0), 4)

        verdict = (
            "CRITICAL" if severity >= 0.80 else
            "HIGH"     if severity >= 0.60 else
            "MEDIUM"   if severity >= 0.35 else
            "LOW"      if severity >= 0.10 else
            "CLEAN"
        )

        self.iocs = {
            "counts":   counts,
            "hits": {
                "ipv4":        ipv4_hits,
                "ipv6":        ipv6_hits,
                "urls":        url_hits,
                "domains":     domain_hits,
                "paths":       path_hits,
                "shell_cmds":  shell_hits,
                "syscalls":    syscall_hits,
                "b64_blobs":   b64_hits,
                "xor_strings": xor_hits,
                "crypto":      crypto_hits,
            },
            "severity": severity,
            "verdict":  verdict,
        }
        return self.iocs

    def analyze_asm(self, top_n: int = 100) -> dict:
        """
        Perform assembly-level analysis using capstone disassembly.

        Requires capstone to be installed (pip install capstone).
        If unavailable, returns {'available': False} without raising.

        Disassembles the top-N functions by size from the symbol table
        and computes trustworthy metrics from linear disassembly only.
        No control flow edge inference is performed.

        Args:
            top_n (int): Maximum functions to analyse (default 100)

        Returns:
            dict: {
                available           (bool)
                function_count      (int)
                total_instructions  (int)
                avg_instr_per_func  (float)
                avg_blocks_per_func (float)
                avg_instr_per_block (float)
                top_mnemonics       (list)
                semantic_histogram  (dict)
                wl_histogram        (dict)
                functions           (list[dict])
            }
        """
        if not _ASM_AVAILABLE or ASMAnalyzer is None:
            self.asm = {"available": False}
            return self.asm

        az       = ASMAnalyzer(self.path, self.arch, self.symbols)
        self.asm = az.analyze(top_n=top_n)

        # Store the ASMAnalyzer instance for WL similarity in xdiff
        self._asm_analyzer = az
        return self.asm

   def analyze(self) -> dict:
        """
        Run full analysis on the binary. Populates all attributes.

        Returns:
            dict: Full analysis results
        """
        self.get_file_size()
        self.compute_hashes()
        self.extract_printable_strings()
        self.parse_sections()
        self.parse_imports()
        self.parse_symbols()
        self.determine_static_dynamic()
        self.detect_security_features()
        self.compute_entropy()
        self.get_architecture()
        self.analyze_iocs()

        self.ai_analysis = analyze_malware({
            "strings": self.strings[:50],
            "imports": [i["name"] for i in self.imports],
            "ioc_summary": self.iocs.get("counts", {}),
            "entropy": self.entropy.get("_whole_binary", 0)
        })

        self.analyze_asm()

        return {
            "file_size":   self.file_size,
            "hashes":      self.hashes,
            "arch":        self.arch,
            "sections":    self.sections,
            "strings":     self.strings,
            "imports":     self.imports,
            "symbols":     self.symbols,
            "exports":     self.exports,
            "static":      self.static,
            "security":    self.security,
            "entropy":     self.entropy,
            "iocs":        self.iocs,
            "asm":         self.asm,
            "ai_analysis": self.ai_analysis,
        }
    # ------------------------------------------------------------------ #
    #  Export methods                                                      #
    # ------------------------------------------------------------------ #

    def _build_flat_row(self) -> dict:
        """Build a flat feature dict shared by both export methods."""
        if not self.hashes:
            raise RuntimeError("Call analyze() before exporting.")

        relro_map = {"none": 0, "partial": 1, "full": 2}

        # --- arch: encode bits and endianness numerically; keep strings as metadata ---
        arch_bits       = self.arch.get("bits", 0)
        arch_endian     = 0 if self.arch.get("endianness") == "little" else 1  # 0=little, 1=big

        func_count  = sum(1 for i in self.imports if i["type"] == "STT_FUNC")
        obj_count   = sum(1 for i in self.imports if i["type"] == "STT_OBJECT")
        weak_count  = sum(1 for i in self.imports if i["binding"] == "STB_WEAK")

        sym_count      = len(self.symbols)
        sym_func_count = sum(1 for s in self.symbols if s["type"] == "STT_FUNC")
        sym_obj_count  = sum(1 for s in self.symbols if s["type"] == "STT_OBJECT")
        import_names   = sorted(i["name"] for i in self.imports)

        sec_sizes   = [s["size"] for s in self.sections]
        exec_count  = sum(1 for s in self.sections if int(s["flags"], 16) & 0x4)
        write_count = sum(1 for s in self.sections if int(s["flags"], 16) & 0x1)
        mean_size   = round(sum(sec_sizes) / len(sec_sizes), 4) if sec_sizes else 0.0

        str_lens  = [len(s) for s in self.strings]
        mean_slen = round(sum(str_lens) / len(str_lens), 4) if str_lens else 0.0
        max_slen  = max(str_lens) if str_lens else 0

        key_sections = [".text", ".data", ".rodata", ".bss", ".plt", ".got"]
        row = {
            # ── identity (non-numeric, drop before ML fit) ────────── #
            "original_path":        self.path,
            "md5":                  self.hashes.get("md5", ""),
            "sha256":               self.hashes.get("sha256", ""),
            # ── architecture ──────────────────────────────────────── #
            "arch_machine":         self.arch.get("machine", ""),       # categorical str
            "arch_abi":             self.arch.get("abi", ""),           # categorical str
            "arch_elf_type":        self.arch.get("elf_type", ""),      # categorical str
            "arch_entry_point":     self.arch.get("entry_point", "0x0"),# hex str
            "arch_bits":            arch_bits,                          # 32 / 64
            "arch_endianness":      arch_endian,                        # 0=little 1=big
            # ── file ──────────────────────────────────────────────── #
            "file_size":            self.file_size,
            "is_dynamic":           int(self.static == "dynamic"),
            # ── imports ───────────────────────────────────────────── #
            "import_count":         len(self.imports),
            "import_func_count":    func_count,
            "import_obj_count":     obj_count,
            "import_weak_count":    weak_count,
            "import_names":         import_names,                       # list — drop for numpy
            # ── symbols ───────────────────────────────────────────── #
            "symbol_count":         sym_count,
            "symbol_func_count":    sym_func_count,
            "symbol_obj_count":     sym_obj_count,
            # ── sections ──────────────────────────────────────────── #
            "section_count":        len(self.sections),
            "section_mean_size":    mean_size,
            "section_total_size":   sum(sec_sizes),
            "section_exec_count":   exec_count,
            "section_write_count":  write_count,
            # ── strings ───────────────────────────────────────────── #
            "string_count":         len(self.strings),
            "string_mean_len":      mean_slen,
            "string_max_len":       max_slen,
            # ── security (all 0/1 or 0/1/2 for relro) ────────────── #
            "sec_nx":               int(self.security.get("nx",       False)),
            "sec_pie":              int(self.security.get("pie",      False)),
            "sec_canary":           int(self.security.get("canary",   False)),
            "sec_relro":            relro_map.get(self.security.get("relro", "none"), 0),
            "sec_stripped":         int(self.security.get("stripped", True)),
            "sec_debug":            int(self.security.get("debug",    False)),
            "sec_fortify":          int(self.security.get("fortify",  False)),
            # ── entropy ───────────────────────────────────────────── #
            "entropy_whole_binary": self.entropy.get("_whole_binary", 0.0),
        }

        for sec in key_sections:
            col = "entropy_" + sec.lstrip(".").replace(".", "_")
            row[col] = self.entropy.get(sec, 0.0)

        # ── IOC counts (all numeric, ML-ready) ────────────────────── #
        ioc_counts = self.iocs.get("counts", {})
        row["ioc_ipv4_count"]       = ioc_counts.get("ipv4",        0)
        row["ioc_ipv6_count"]       = ioc_counts.get("ipv6",        0)
        row["ioc_url_count"]        = ioc_counts.get("urls",         0)
        row["ioc_domain_count"]     = ioc_counts.get("domains",      0)
        row["ioc_path_count"]       = ioc_counts.get("paths",        0)
        row["ioc_shell_cmd_count"]  = ioc_counts.get("shell_cmds",   0)
        row["ioc_syscall_count"]    = ioc_counts.get("syscalls",     0)
        row["ioc_b64_count"]        = ioc_counts.get("b64_blobs",    0)
        row["ioc_xor_count"]        = ioc_counts.get("xor_strings",  0)
        row["ioc_crypto_count"]     = ioc_counts.get("crypto",       0)
        row["ioc_severity_score"]   = self.iocs.get("severity",      0.0)
        # verdict as ordinal: CLEAN=0 LOW=1 MEDIUM=2 HIGH=3 CRITICAL=4
        _verdict_map = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        row["ioc_verdict_ordinal"]  = _verdict_map.get(
            self.iocs.get("verdict", "CLEAN"), 0
        )

        # ── ASM / CFG features (0 if capstone not available) ──────── #
        asm = self.asm
        row["asm_available"]           = int(asm.get("available", False))
        row["asm_function_count"]      = asm.get("function_count",      0)
        row["asm_total_instructions"]  = asm.get("total_instructions",  0)
        row["asm_avg_instr_per_func"]  = asm.get("avg_instr_per_func",  0.0)
        row["asm_avg_blocks_per_func"] = asm.get("avg_blocks_per_func", 0.0)
        row["asm_avg_instr_per_block"] = asm.get("avg_instr_per_block", 0.0)
        # Semantic histogram as JSON string — expand with pd.Series.apply(json.loads)
        row["asm_wl_histogram"]        = json.dumps(asm.get("wl_histogram", {}))

        return row

    def to_ml_json(self, output_path: str) -> str:
        """
        Export a flat ML-ready feature JSON for this binary.

        The JSON is a single dict — one row in a future DataFrame.
        Numeric fields are ready for numpy/sklearn. Categorical string
        fields (arch_machine, arch_abi, arch_elf_type) should be
        pd.Categorical encoded before fitting. Identity fields
        (original_path, md5, sha256) should be dropped before fitting
        but kept for provenance.

        Args:
            output_path (str): Destination .json file path.

        Returns:
            str: Absolute path to the written JSON file.

        Raises:
            ValueError: If output_path is empty.
            IOError:    If the file cannot be written.
        """
        if not output_path:
            raise ValueError("output_path must be a non-empty string")

        row = self._build_flat_row()
        out = Path(output_path)
        try:
            with open(out, "w", encoding="utf-8") as f:
                json.dump(row, f, indent=2)
                f.write("\n")
        except OSError as e:
            raise IOError(f"Failed to write JSON to {output_path}: {e}") from e

        return str(out.resolve())

    def to_pandas_csv(self, output_path: str) -> str:
        """
        Export analysis results to a flat CSV file suitable for pandas.

        Args:
            output_path (str): Destination CSV file path (appends if exists).

        Returns:
            str: Absolute path to the written CSV file.

        Raises:
            ValueError: If output_path is empty or None.
        """
        if not output_path:
            raise ValueError("output_path must be a non-empty string")

        row     = self._build_flat_row()
        headers = list(row.keys())
        out     = Path(output_path)
        exists  = out.is_file()

        try:
            with open(out, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
                if not exists:
                    writer.writeheader()
                writer.writerow(row)
        except OSError as e:
            raise IOError(f"Failed to write CSV to {output_path}: {e}") from e

        return str(out.resolve())

    def to_numpy_npz(self, output_path: str) -> str:
        """
        Export numeric analysis features to a NumPy .npz archive.

        Args:
            output_path (str): Destination .npz file path (will be overwritten).

        Returns:
            str: Absolute path to the written .npz file.
        """
        try:
            import numpy as np
        except ImportError as e:
            raise ImportError("numpy is required for to_numpy_npz(). Install with: pip install numpy") from e

        row           = self._build_flat_row()
        string_keys   = {"original_path", "md5", "sha256", "arch_machine", "arch_abi", "arch_elf_type", "arch_entry_point", "import_names", "asm_wl_histogram"}
        numeric_items = [(k, v) for k, v in row.items() if k not in string_keys]

        feature_names = [k for k, _ in numeric_items]
        features      = np.array([float(v) for _, v in numeric_items], dtype=np.float64)
        meta          = json.dumps({
            "original_path":  row["original_path"],
            "md5":            row["md5"],
            "sha256":         row["sha256"],
            "arch_machine":   row["arch_machine"],
            "arch_abi":       row["arch_abi"],
            "arch_elf_type":  row["arch_elf_type"],
            "arch_entry_point": row["arch_entry_point"],
        }).encode("utf-8")

        np.savez(
            output_path,
            features      = features,
            feature_names = np.array(feature_names),
            meta          = np.frombuffer(meta, dtype=np.uint8),
        )

        final_path = output_path if output_path.endswith(".npz") else output_path + ".npz"
        return os.path.abspath(final_path)

    def __repr__(self):
        return f"ELFAnalyzer(path='{self.path}', analyzed={bool(self.hashes)})"
