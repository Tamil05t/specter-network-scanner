"""Exploit-DB correlation engine.

Responsible use only. This module is for defensive security assessment in
authorized environments. It does not execute exploits.
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
import aiofiles
import aiohttp
from whoosh import fields, index, qparser
from whoosh.filedb.filestore import RamStorage
from specter.models.dataclasses import ScanResult, Service, Vulnerability
try:
    from rapidfuzz.distance import Levenshtein as _Levenshtein
except Exception:
    _Levenshtein = None
EXPLOIT_DB_URL = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

@dataclass
class ExploitMatch:
    exploit_db_id: int
    title: str
    cve_list: List[str]
    platform: str
    exploit_type: str
    verified: bool
    confidence: float
    match_reason: str
    exploit_path: Optional[str] = None

@dataclass
class CorrelatedResult:
    matches: Dict[str, List[ExploitMatch]] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class ExploitRecord:
    exploit_db_id: int
    title: str
    platform: str
    exploit_type: str
    verified: bool
    cve_list: List[str]
    description: str

class ExploitCorrelator:
    """Correlate discovered services and vulnerabilities to Exploit-DB."""

    def __init__(self, cache_dir: str='.specter-cache', exclude_types: Optional[Sequence[str]]=None, nvd_api_key: Optional[str]=None, nvd_rate_limit: int=5, nvd_rate_window: int=30, correlation_ttl: int=900, use_searchsploit: bool=True, logger: Optional[logging.Logger]=None) -> None:
        """Initialize correlation engine settings.

Args:
    cache_dir (Any): Description of cache_dir.
    exclude_types (Any): Description of exclude_types.
    nvd_api_key (Any): Description of nvd_api_key.
    nvd_rate_limit (Any): Description of nvd_rate_limit.
    nvd_rate_window (Any): Description of nvd_rate_window.
    correlation_ttl (Any): Description of correlation_ttl.
    use_searchsploit (Any): Description of use_searchsploit.
    logger (Any): Description of logger.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of __init__
    >>> pass"""
        self._cache_dir = cache_dir
        self._exclude_types = {t.lower() for t in exclude_types or []}
        self._nvd_api_key = nvd_api_key
        self._nvd_rate_limit = nvd_rate_limit
        self._nvd_rate_window = nvd_rate_window
        self._correlation_ttl = correlation_ttl
        self._use_searchsploit = use_searchsploit
        self._logger = logger or logging.getLogger('specter.correlation')
        self._index = None
        self._schema = self._build_schema()
        self._records: Dict[int, ExploitRecord] = {}
        self._cve_map: Dict[str, List[int]] = {}
        self._correlation_cache: Dict[str, Tuple[float, List[ExploitMatch]]] = {}
        self._nvd_cache: Dict[str, Tuple[float, dict]] = {}
        self._nvd_lock = asyncio.Lock()
        self._nvd_calls: List[float] = []

    async def load_exploit_db(self) -> None:
        """Download, cache, parse, and index Exploit-DB CSV.

Args:
    None

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of load_exploit_db
    >>> pass"""
        os.makedirs(self._cache_dir, exist_ok=True)
        csv_path = os.path.join(self._cache_dir, 'files_exploits.csv')
        sha_path = os.path.join(self._cache_dir, 'files_exploits.sha256')
        await self._download_if_needed(csv_path, sha_path)
        await self._parse_csv(csv_path)
        self._build_index()

    async def correlate_service(self, service: Service) -> List[ExploitMatch]:
        """Correlate a service to exploits using multiple strategies.

Args:
    service (Any): Description of service.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of correlate_service
    >>> pass"""
        cache_key = f'service:{service.service_name}:{service.version}:{service.port}'
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached
        matches: List[ExploitMatch] = []
        if self._index is None:
            await self.load_exploit_db()
        banner = service.banner or ''
        keyword_terms = self._build_keyword_terms(service, banner)
        matches.extend(self._match_cpe_exact(service))
        matches.extend(self._match_keyword(keyword_terms))
        matches.extend(self._match_banner_regex(banner))
        matches.extend(self._match_fuzzy_version(service))
        matches.extend(self._heuristic_inference(service))
        if self._use_searchsploit and (not matches):
            matches.extend(await self._searchsploit_lookup(service))
        if not matches and self._records:
            name_lower = (service.service_name or '').lower()
            for record in self._records.values():
                if name_lower and name_lower in (record.title or '').lower():
                    matches.append(self._build_match(record, 0.9, 'substring_title'))
                elif name_lower and name_lower in (record.description or '').lower():
                    matches.append(self._build_match(record, 0.8, 'substring_description'))
        matches = self._filter_and_rank(matches)
        self._set_cached(cache_key, matches)
        self._logger.info('service correlation %s:%s -> %d matches', service.service_name, service.port, len(matches))
        return matches

    async def correlate_vulnerability(self, vuln: Vulnerability) -> List[ExploitMatch]:
        """Correlate a vulnerability to exploits via CVE mapping and keywords.

Args:
    vuln (Any): Description of vuln.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of correlate_vulnerability
    >>> pass"""
        cache_key = f'vuln:{vuln.cve_id}:{vuln.affected_service}'
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached
        if self._index is None:
            await self.load_exploit_db()
        matches: List[ExploitMatch] = []
        if vuln.cve_id and vuln.cve_id.upper().startswith('CVE-'):
            matches.extend(self._match_cve(vuln.cve_id))
        if vuln.description:
            matches.extend(self._match_keyword([vuln.description]))
        if self._use_searchsploit and (not matches):
            matches.extend(await self._searchsploit_lookup_by_text(vuln.description))
        matches = self._filter_and_rank(matches)
        self._set_cached(cache_key, matches)
        self._logger.info('vuln correlation %s -> %d matches', vuln.cve_id, len(matches))
        return matches

    async def batch_correlate(self, scan_results: ScanResult) -> CorrelatedResult:
        """Batch process services and vulnerabilities in chunks of 50.

Args:
    scan_results (Any): Description of scan_results.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of batch_correlate
    >>> pass"""
        if self._index is None:
            await self.load_exploit_db()
        result = CorrelatedResult()
        service_list: List[Service] = []
        vuln_list: List[Vulnerability] = []
        for device in scan_results.devices:
            service_list.extend(device.services)
            vuln_list.extend(device.vulnerabilities)
        for chunk in self._chunk(service_list, 50):
            tasks = [self.correlate_service(svc) for svc in chunk]
            service_matches = await asyncio.gather(*tasks)
            for svc, matches in zip(chunk, service_matches):
                key = f'service:{svc.service_name}:{svc.port}'
                result.matches[key] = matches
        for chunk in self._chunk(vuln_list, 50):
            tasks = [self.correlate_vulnerability(vuln) for vuln in chunk]
            vuln_matches = await asyncio.gather(*tasks)
            for vuln, matches in zip(chunk, vuln_matches):
                key = f'vuln:{vuln.cve_id}'
                result.matches[key] = matches
        return result

    def calculate_confidence(self, service: Service, exploit: ExploitRecord) -> float:
        """Calculate a confidence score between 0.0 and 1.0.

Args:
    service (Any): Description of service.
    exploit (Any): Description of exploit.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of calculate_confidence
    >>> pass"""
        if service.service_name.lower() in exploit.title.lower():
            return 0.85
        return 0.6

    async def fetch_nvd_cve(self, cve_id: str) -> Optional[dict]:
        """Lookup CVE details from the NVD API with rate limiting.

Args:
    cve_id (Any): Description of cve_id.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of fetch_nvd_cve
    >>> pass"""
        cached = self._get_nvd_cached(cve_id)
        if cached is not None:
            return cached
        await self._respect_nvd_rate_limit()
        headers = {}
        if self._nvd_api_key:
            headers['apiKey'] = self._nvd_api_key
        params = {'cveId': cve_id}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(NVD_API_URL, params=params, headers=headers, timeout=10) as response:
                    if response.status != 200:
                        return None
                    payload = await response.json()
                    self._set_nvd_cached(cve_id, payload)
                    return payload
        except Exception:
            return None

    async def _download_if_needed(self, csv_path: str, sha_path: str) -> None:
        """Download Exploit-DB CSV if missing or updated.

Args:
    csv_path (Any): Description of csv_path.
    sha_path (Any): Description of sha_path.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _download_if_needed
    >>> pass"""
        if not os.path.exists(csv_path):
            await self._download_csv(csv_path)
            await self._write_sha(csv_path, sha_path)
            return
        current_sha = await self._compute_sha(csv_path)
        cached_sha = await self._read_sha(sha_path)
        if cached_sha != current_sha:
            await self._write_sha(csv_path, sha_path)
            return
        remote_sha = await self._fetch_remote_sha()
        if remote_sha and remote_sha != current_sha:
            await self._download_csv(csv_path)
            await self._write_sha(csv_path, sha_path)

    async def _download_csv(self, csv_path: str) -> None:
        """Download Exploit-DB CSV to disk.

Args:
    csv_path (Any): Description of csv_path.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _download_csv
    >>> pass"""
        self._logger.info('downloading Exploit-DB CSV')
        async with aiohttp.ClientSession() as session:
            async with session.get(EXPLOIT_DB_URL, timeout=30) as response:
                response.raise_for_status()
                data = await response.read()
        async with aiofiles.open(csv_path, 'wb') as handle:
            await handle.write(data)

    async def _fetch_remote_sha(self) -> Optional[str]:
        """Fetch the remote CSV SHA256 hash.

Args:
    None

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _fetch_remote_sha
    >>> pass"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(EXPLOIT_DB_URL, timeout=30) as response:
                    response.raise_for_status()
                    data = await response.read()
            return hashlib.sha256(data).hexdigest()
        except Exception:
            return None

    async def _compute_sha(self, path: str) -> str:
        """Compute SHA256 hash for a file.

Args:
    path (Any): Description of path.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _compute_sha
    >>> pass"""
        async with aiofiles.open(path, 'rb') as handle:
            data = await handle.read()
        return hashlib.sha256(data).hexdigest()

    async def _read_sha(self, sha_path: str) -> Optional[str]:
        """Read cached SHA value from disk.

Args:
    sha_path (Any): Description of sha_path.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _read_sha
    >>> pass"""
        if not os.path.exists(sha_path):
            return None
        async with aiofiles.open(sha_path, 'r', encoding='utf-8') as handle:
            return (await handle.read()).strip() or None

    async def _write_sha(self, csv_path: str, sha_path: str) -> None:
        """Write SHA hash for CSV to disk.

Args:
    csv_path (Any): Description of csv_path.
    sha_path (Any): Description of sha_path.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _write_sha
    >>> pass"""
        sha_value = await self._compute_sha(csv_path)
        async with aiofiles.open(sha_path, 'w', encoding='utf-8') as handle:
            await handle.write(sha_value)

    async def _parse_csv(self, csv_path: str) -> None:
        """Parse Exploit-DB CSV into records.

Args:
    csv_path (Any): Description of csv_path.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _parse_csv
    >>> pass"""
        self._records.clear()
        self._cve_map.clear()
        async with aiofiles.open(csv_path, 'r', encoding='utf-8', errors='ignore') as handle:
            header = await handle.readline()
            if not header:
                return
            while True:
                line = await handle.readline()
                if not line:
                    break
                parts = self._split_csv_line(line)
                if len(parts) < 7:
                    continue
                try:
                    exploit_db_id = int(parts[0])
                except ValueError:
                    continue
                title = parts[2]
                platform = parts[5]
                exploit_type = parts[6]
                verified = parts[8].strip().lower() == '1' if len(parts) > 8 else False
                cve_list = self._extract_cves(parts)
                record = ExploitRecord(exploit_db_id=exploit_db_id, title=title, platform=platform, exploit_type=exploit_type, verified=verified, cve_list=cve_list, description=title)
                self._records[exploit_db_id] = record
                for cve in cve_list:
                    self._cve_map.setdefault(cve, []).append(exploit_db_id)

    def _build_index(self) -> None:
        """Build in-memory Whoosh index from records.

Args:
    None

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _build_index
    >>> pass"""
        storage = RamStorage()
        self._index = storage.create_index(self._schema)
        writer = self._index.writer()
        for record in self._records.values():
            writer.add_document(exploit_db_id=str(record.exploit_db_id), title=record.title, description=record.description, platform=record.platform, exploit_type=record.exploit_type, cve=' '.join(record.cve_list))
        writer.commit()

    def _match_cve(self, cve_id: str) -> List[ExploitMatch]:
        """Match exploits by CVE ID.

Args:
    cve_id (Any): Description of cve_id.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _match_cve
    >>> pass"""
        cve_id = cve_id.upper()
        matches: List[ExploitMatch] = []
        for exploit_id in self._cve_map.get(cve_id, []):
            record = self._records.get(exploit_id)
            if record is None:
                continue
            matches.append(self._build_match(record, 0.95, 'cve_match'))
        return matches

    def _match_cpe_exact(self, service: Service) -> List[ExploitMatch]:
        """Match exploits using exact service terms.

Args:
    service (Any): Description of service.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _match_cpe_exact
    >>> pass"""
        if not service.service_name:
            return []
        terms = [service.service_name]
        if service.version:
            terms.append(service.version)
        return self._match_keyword(terms, 1.0, 'exact_cpe')

    def _match_keyword(self, terms: Iterable[str], base_confidence: float=0.6, reason: str='keyword_match') -> List[ExploitMatch]:
        """Match exploits using keyword search.

Args:
    terms (Any): Description of terms.
    base_confidence (Any): Description of base_confidence.
    reason (Any): Description of reason.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _match_keyword
    >>> pass"""
        if self._index is None:
            return []
        query_text = ' '.join((t for t in terms if t))
        if not query_text:
            return []
        parser = qparser.MultifieldParser(['title', 'description'], schema=self._schema)
        query = parser.parse(query_text)
        results: List[ExploitMatch] = []
        with self._index.searcher() as searcher:
            for hit in searcher.search(query, limit=25):
                record = self._records.get(int(hit['exploit_db_id']))
                if record is None:
                    continue
                results.append(self._build_match(record, base_confidence, reason))
        return results

    def _match_banner_regex(self, banner: str) -> List[ExploitMatch]:
        """Match exploits using banner-derived terms.

Args:
    banner (Any): Description of banner.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _match_banner_regex
    >>> pass"""
        if not banner:
            return []
        terms = self._extract_products(banner)
        return self._match_keyword(terms, 0.7, 'banner_regex')

    def _match_fuzzy_version(self, service: Service) -> List[ExploitMatch]:
        """Match exploits using fuzzy version comparison.

Args:
    service (Any): Description of service.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _match_fuzzy_version
    >>> pass"""
        if not service.version or _Levenshtein is None:
            return []
        matches: List[ExploitMatch] = []
        for record in self._records.values():
            for version in self._extract_versions(record.title):
                distance = _Levenshtein.distance(service.version, version)
                if distance <= 2:
                    matches.append(self._build_match(record, 0.7, 'fuzzy_version'))
        return matches

    def _heuristic_inference(self, service: Service) -> List[ExploitMatch]:
        """Apply heuristic inferences for high-risk services.

Args:
    service (Any): Description of service.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _heuristic_inference
    >>> pass"""
        matches: List[ExploitMatch] = []
        name = (service.service_name or '').lower()
        banner = (service.banner or '').lower()
        if name in {'ftp', 'redis', 'mongodb', 'elasticsearch'}:
            matches.append(ExploitMatch(exploit_db_id=0, title=f'Heuristic: possible unauthenticated {name} exposure', cve_list=[], platform=name, exploit_type='remote', verified=False, confidence=0.6, match_reason='heuristic_exposure', exploit_path=None))
        if 'default' in banner or 'admin' in banner:
            matches.append(ExploitMatch(exploit_db_id=0, title='Heuristic: possible default credentials', cve_list=[], platform=name or 'generic', exploit_type='remote', verified=False, confidence=0.6, match_reason='heuristic_default_creds', exploit_path=None))
        return matches

    def _filter_and_rank(self, matches: List[ExploitMatch]) -> List[ExploitMatch]:
        """Filter and rank exploit matches.

Args:
    matches (Any): Description of matches.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _filter_and_rank
    >>> pass"""
        filtered = [m for m in matches if m.exploit_type.lower() not in self._exclude_types]
        unique: Dict[int, ExploitMatch] = {}
        for match in filtered:
            existing = unique.get(match.exploit_db_id)
            if existing is None or match.confidence > existing.confidence:
                unique[match.exploit_db_id] = match
        return sorted(unique.values(), key=lambda m: m.confidence, reverse=True)

    def _build_match(self, record: ExploitRecord, confidence: float, reason: str) -> ExploitMatch:
        """Build an ExploitMatch from a record.

Args:
    record (Any): Description of record.
    confidence (Any): Description of confidence.
    reason (Any): Description of reason.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _build_match
    >>> pass"""
        return ExploitMatch(exploit_db_id=record.exploit_db_id, title=record.title, cve_list=record.cve_list, platform=record.platform, exploit_type=record.exploit_type, verified=record.verified, confidence=confidence, match_reason=reason, exploit_path=None)

    def _build_schema(self) -> fields.Schema:
        """Build the Whoosh schema for indexing.

Args:
    None

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _build_schema
    >>> pass"""
        return fields.Schema(exploit_db_id=fields.ID(stored=True), title=fields.TEXT(stored=True), description=fields.TEXT(stored=True), platform=fields.KEYWORD(stored=True, commas=True), exploit_type=fields.KEYWORD(stored=True, commas=True), cve=fields.KEYWORD(stored=True, commas=True))

    def _split_csv_line(self, line: str) -> List[str]:
        """Split a CSV line while respecting quotes.

Args:
    line (Any): Description of line.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _split_csv_line
    >>> pass"""
        output: List[str] = []
        current = ''
        in_quotes = False
        for char in line:
            if char == '"':
                in_quotes = not in_quotes
            elif char == ',' and (not in_quotes):
                output.append(current)
                current = ''
            else:
                current += char
        output.append(current)
        return [item.strip() for item in output]

    def _extract_cves(self, parts: List[str]) -> List[str]:
        """Extract CVE identifiers from CSV columns.

Args:
    parts (Any): Description of parts.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _extract_cves
    >>> pass"""
        cve_text = ' '.join(parts)
        return sorted(set(re.findall('CVE-\\d{4}-\\d{4,7}', cve_text, re.IGNORECASE)))

    def _extract_products(self, banner: str) -> List[str]:
        """Extract product-like tokens from a banner.

Args:
    banner (Any): Description of banner.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _extract_products
    >>> pass"""
        words = re.findall('[A-Za-z][A-Za-z0-9\\-\\.]{2,}', banner)
        return list({w for w in words if len(w) <= 40})

    def _extract_versions(self, text: str) -> List[str]:
        """Extract version strings from text.

Args:
    text (Any): Description of text.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _extract_versions
    >>> pass"""
        return re.findall('\\d+\\.\\d+(?:\\.\\d+)?', text)

    def _build_keyword_terms(self, service: Service, banner: str) -> List[str]:
        """Build keyword list for index search.

Args:
    service (Any): Description of service.
    banner (Any): Description of banner.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _build_keyword_terms
    >>> pass"""
        terms = [service.service_name, service.version or '']
        if banner:
            terms.append(banner)
        return [t for t in terms if t]

    def _chunk(self, items: Sequence, size: int) -> List[Sequence]:
        """Split a sequence into chunks.

Args:
    items (Any): Description of items.
    size (Any): Description of size.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _chunk
    >>> pass"""
        return [items[i:i + size] for i in range(0, len(items), size)]

    def _get_cached(self, key: str) -> Optional[List[ExploitMatch]]:
        """Get cached correlation results.

Args:
    key (Any): Description of key.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _get_cached
    >>> pass"""
        entry = self._correlation_cache.get(key)
        if entry is None:
            return None
        expires_at, matches = entry
        if time.time() > expires_at:
            del self._correlation_cache[key]
            return None
        return matches

    def _set_cached(self, key: str, matches: List[ExploitMatch]) -> None:
        """Store matches in the correlation cache.

Args:
    key (Any): Description of key.
    matches (Any): Description of matches.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _set_cached
    >>> pass"""
        self._correlation_cache[key] = (time.time() + self._correlation_ttl, matches)

    async def _respect_nvd_rate_limit(self) -> None:
        """Enforce NVD API rate limit.

Args:
    None

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _respect_nvd_rate_limit
    >>> pass"""
        async with self._nvd_lock:
            now = time.time()
            self._nvd_calls = [t for t in self._nvd_calls if now - t < self._nvd_rate_window]
            if len(self._nvd_calls) >= self._nvd_rate_limit:
                sleep_for = self._nvd_rate_window - (now - self._nvd_calls[0])
                await asyncio.sleep(max(0.0, sleep_for))
            self._nvd_calls.append(time.time())

    def _get_nvd_cached(self, cve_id: str) -> Optional[dict]:
        """Fetch a cached NVD response.

Args:
    cve_id (Any): Description of cve_id.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _get_nvd_cached
    >>> pass"""
        entry = self._nvd_cache.get(cve_id)
        if entry is None:
            return None
        expires_at, payload = entry
        if time.time() > expires_at:
            del self._nvd_cache[cve_id]
            return None
        return payload

    def _set_nvd_cached(self, cve_id: str, payload: dict) -> None:
        """Store NVD response in cache.

Args:
    cve_id (Any): Description of cve_id.
    payload (Any): Description of payload.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _set_nvd_cached
    >>> pass"""
        self._nvd_cache[cve_id] = (time.time() + self._correlation_ttl, payload)

    async def _searchsploit_lookup(self, service: Service) -> List[ExploitMatch]:
        """Lookup exploits with searchsploit using service info.

Args:
    service (Any): Description of service.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _searchsploit_lookup
    >>> pass"""
        if not self._is_searchsploit_available():
            return []
        query = service.service_name
        if service.version:
            query = f'{query} {service.version}'
        return await self._searchsploit_query(query)

    async def _searchsploit_lookup_by_text(self, text: Optional[str]) -> List[ExploitMatch]:
        """Lookup exploits with searchsploit using raw text.

Args:
    text (Any): Description of text.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _searchsploit_lookup_by_text
    >>> pass"""
        if not text or not self._is_searchsploit_available():
            return []
        return await self._searchsploit_query(text)

    def _is_searchsploit_available(self) -> bool:
        """Check if searchsploit is available on PATH.

Args:
    None

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _is_searchsploit_available
    >>> pass"""
        return shutil.which('searchsploit') is not None

    async def _searchsploit_query(self, query: str) -> List[ExploitMatch]:
        """Run searchsploit query and parse results.

Args:
    query (Any): Description of query.

Returns:
    Any: Description of return value.

Raises:
    Exception: On unexpected errors.

Example:
    >>> # Example usage of _searchsploit_query
    >>> pass"""

        def run_query() -> str:
            """
            Docstring.

            Args:
                TODO
            Returns:
                TODO
            Raises:
                TODO
            Example:
                TODO
            """
            completed = subprocess.run(['searchsploit', '--json', query], capture_output=True, text=True, check=False)
            return completed.stdout
        try:
            stdout = await asyncio.to_thread(run_query)
            payload = json.loads(stdout) if stdout else {}
        except Exception:
            return []
        results: List[ExploitMatch] = []
        for entry in payload.get('RESULTS_EXPLOIT', []):
            try:
                exploit_id = int(entry.get('EDB-ID', 0))
            except ValueError:
                exploit_id = 0
            results.append(ExploitMatch(exploit_db_id=exploit_id, title=entry.get('Title', 'searchsploit result'), cve_list=self._extract_cves(json.dumps(entry)), platform=entry.get('Platform', 'unknown'), exploit_type=entry.get('Type', 'unknown'), verified=False, confidence=0.6, match_reason='searchsploit', exploit_path=entry.get('Path')))
        return results