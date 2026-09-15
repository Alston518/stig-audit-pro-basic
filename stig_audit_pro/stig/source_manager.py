"""Download, import, cache, and parse STIG source packages."""

from __future__ import annotations

import json
import re
import shutil
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable

from stig_audit_pro.core.archive_safety import MAX_ARCHIVE_BYTES, validate_zip
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata
from stig_audit_pro.stig.xccdf_importer import parse_xccdf_file

CYBER_MIL_STIG_DOWNLOADS_URL = "https://www.cyber.mil/stigs/downloads/"
CYBER_MIL_APEX_BASE_URL = "https://www.cyber.mil/lwr/apex/v67.0"
CYBER_MIL_DOWNLOAD_BASE_URL = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip"
CYBER_DOCUMENT_CONTROLLER = "@udd/01pRw0000002mOj"
S3_FILE_DOWNLOAD_CONTROLLER = "@udd/01pRw00000030Y9"
USER_AGENT = "STIG-Audit-Pro/0.2 (+https://www.cyber.mil/stigs/downloads/)"

DEFAULT_STIG_SOURCES = {
    "IOSXE_L2": ["cisco", "ios", "xe", "switch", "l2"],
    "IOSXE_NDM": ["cisco", "ios", "xe", "switch", "ndm"],
}


@dataclass(slots=True)
class StigDownloadCandidate:
    title: str
    url: str
    upload_date: str = ""
    download_type: str = ""
    classification: str = ""
    source: str = ""


class StigSourceError(RuntimeError):
    """Raised when a STIG source cannot be found, imported, or parsed."""


class StigSourceManager:
    def __init__(
        self,
        cache_dir: str | Path,
        download_page: str = CYBER_MIL_STIG_DOWNLOADS_URL,
    ) -> None:
        self.cache_dir = Path(cache_dir)
        self.download_page = download_page
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def discover_downloads(self, search_terms: Iterable[str]) -> list[StigDownloadCandidate]:
        terms = [term.lower() for term in search_terms]

        candidates = self._discover_downloads_from_catalog(terms)
        if candidates:
            return candidates

        html = ""
        try:
            html = self._read_url_text(self.download_page)
            candidates = self._extract_candidates(html, terms)
        except OSError:
            candidates = []
        if candidates:
            return candidates

        candidates = self._guess_direct_package_candidates(terms)
        if candidates:
            return candidates

        if html and self._looks_like_dynamic_shell(html):
            raise StigSourceError(
                "Cyber Exchange loaded its downloads page as a JavaScript application, and the automatic finder "
                "could not resolve a matching Cyber.mil ZIP/XML package. Use Download URL with a direct ZIP/XML "
                "package link, or use Import ZIP/XML after downloading the STIG package."
            )
        return candidates

    def download_latest(
        self,
        family: str,
        search_terms: Iterable[str] | None = None,
    ) -> StigBenchmarkMetadata:
        terms = list(search_terms or DEFAULT_STIG_SOURCES.get(family, [family]))
        candidates = self.discover_downloads(terms)
        if not candidates:
            raise StigSourceError(
                "No matching STIG ZIP/XML download link was found on the Cyber Exchange downloads page. "
                "Use Download URL with a direct ZIP/XML link, or use Import ZIP/XML after downloading the STIG package."
            )
        return self.download_from_url(candidates[0].url, family=family)

    def download_from_url(self, url: str, family: str = "") -> StigBenchmarkMetadata:
        address = url.strip()
        if not address:
            raise StigSourceError("Enter a direct STIG ZIP/XML URL first.")

        local_candidate = Path(address)
        if local_candidate.exists():
            return self.import_source(local_candidate, family=family)

        parsed = urllib.parse.urlparse(address)
        if parsed.scheme in {"", "file"}:
            local_path = self._path_from_local_address(address, parsed)
            return self.import_source(local_path, family=family)
        if parsed.scheme not in {"http", "https"}:
            raise StigSourceError("STIG download URL must be HTTP, HTTPS, file, or a local path.")

        family_name = family or self._family_from_filename(Path(parsed.path).name)
        family_dir = self.cache_dir / family_name
        family_dir.mkdir(parents=True, exist_ok=True)

        request = urllib.request.Request(address, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=60) as response:
            final_url = response.geturl()
            filename = self._filename_from_response(final_url, response.headers.get("Content-Disposition"), family_name)
            destination = family_dir / filename
            with destination.open("wb") as handle:
                shutil.copyfileobj(response, handle)
        return self.import_source(destination, family=family_name)

    def import_source(self, source_path: str | Path, family: str = "") -> StigBenchmarkMetadata:
        source = Path(source_path)
        if not source.exists():
            raise StigSourceError(f"STIG source does not exist: {source}")
        family_name = family or self._family_from_filename(source.name)
        family_dir = self.cache_dir / family_name
        family_dir.mkdir(parents=True, exist_ok=True)
        cached_source = family_dir / source.name
        if source.resolve() != cached_source.resolve():
            shutil.copy2(source, cached_source)

        xml_path = self._extract_xccdf(cached_source, family_dir, family_name)
        metadata = parse_xccdf_file(xml_path, family=family_name)
        metadata.source_path = str(cached_source)
        metadata.source_filename = cached_source.name
        self._write_metadata(family_dir, metadata)
        return metadata

    def load_cached_metadata(self) -> list[StigBenchmarkMetadata]:
        metadata_items: list[StigBenchmarkMetadata] = []
        for path in sorted(self.cache_dir.glob("*/metadata.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            if hasattr(StigBenchmarkMetadata, "model_validate"):
                metadata_items.append(StigBenchmarkMetadata.model_validate(data))  # type: ignore[attr-defined]
            else:
                metadata_items.append(StigBenchmarkMetadata.parse_obj(data))
        return metadata_items

    def _read_url_text(self, url: str) -> str:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", errors="ignore")

    def _discover_downloads_from_catalog(self, terms: list[str]) -> list[StigDownloadCandidate]:
        try:
            payload = self._call_cyber_apex(
                CYBER_DOCUMENT_CONTROLLER,
                "getCyberDocumentCatalogByDocumentLibrary",
                {"documentLibrary": "STIGs"},
            )
        except (OSError, json.JSONDecodeError, StigSourceError):
            return []

        candidates: list[StigDownloadCandidate] = []
        seen: set[str] = set()
        for item in self._catalog_records(payload):
            candidate = self._candidate_from_catalog_record(item, terms)
            if candidate and candidate.url not in seen:
                seen.add(candidate.url)
                candidates.append(candidate)
        return sorted(candidates, key=self._catalog_sort_key, reverse=True)

    def _call_cyber_apex(self, apex_class: str, method: str, params: dict[str, object]) -> object:
        encoded_class = urllib.parse.quote(apex_class, safe="")
        encoded_method = urllib.parse.quote(method, safe="")
        url = f"{CYBER_MIL_APEX_BASE_URL}/{encoded_class}/{encoded_method}"
        body = json.dumps(params).encode("utf-8")
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Origin": "https://www.cyber.mil",
            "Referer": self.download_page,
            "X-SFDC-Allow-Continuation": "false",
        }
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=30) as response:
            text = response.read().decode("utf-8", errors="ignore")
        return json.loads(text)

    def _catalog_records(self, payload: object) -> list[dict[str, object]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if not isinstance(payload, dict):
            return []
        if "FileName" in payload or "DownloadLink" in payload:
            return [payload]
        for key in ("records", "items", "data", "result", "returnValue", "body"):
            value = payload.get(key)
            records = self._catalog_records(value)
            if records:
                return records
        return []

    def _candidate_from_catalog_record(
        self,
        item: dict[str, object],
        terms: list[str],
    ) -> StigDownloadCandidate | None:
        filename = str(item.get("FileName") or item.get("Name") or "").strip()
        link = str(item.get("DownloadLink") or item.get("Url") or item.get("url") or "").strip()
        download_type = str(item.get("DownloadType") or "").strip()
        document_library = str(item.get("DocumentLibrary") or "").strip()
        upload_date = str(item.get("UploadDate") or "").strip()
        classification = str(item.get("Classification") or "").strip()
        haystack = f"{filename} {download_type} {document_library} {link}".lower()
        if not link or not self._matches_terms(haystack, terms):
            return None
        if ".zip" not in haystack and ".xml" not in haystack:
            return None
        if classification and classification.lower() != "unclassified":
            link = self._resolve_signed_url(link) or link
        return StigDownloadCandidate(
            title=filename or Path(urllib.parse.urlparse(link).path).name,
            url=link,
            upload_date=upload_date,
            download_type=download_type,
            classification=classification,
            source="cyber.mil catalog",
        )

    def _resolve_signed_url(self, s3_link: str) -> str:
        payload = self._call_cyber_apex(S3_FILE_DOWNLOAD_CONTROLLER, "getSignedUrl", {"s3Link": s3_link})
        if isinstance(payload, dict):
            value = payload.get("url") or payload.get("Url")
            if isinstance(value, str):
                return value
        return ""

    def _catalog_sort_key(self, candidate: StigDownloadCandidate) -> tuple[str, str]:
        return (candidate.upload_date, candidate.title)

    def _extract_candidates(self, html: str, terms: list[str]) -> list[StigDownloadCandidate]:
        candidates: list[StigDownloadCandidate] = []
        seen: set[str] = set()

        anchor_pattern = re.compile(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
        for href, label_html in anchor_pattern.findall(html):
            label = re.sub(r"<[^>]+>", " ", label_html)
            label = " ".join(label.split())
            self._add_candidate(candidates, seen, href, label, terms)

        direct_url_pattern = re.compile(r"https?://[^\s\"'<>]+(?:\.zip|\.xml)(?:\?[^\s\"'<>]*)?", re.IGNORECASE)
        for url in direct_url_pattern.findall(html):
            self._add_candidate(candidates, seen, url, Path(urllib.parse.urlparse(url).path).name, terms)

        return candidates

    def _add_candidate(
        self,
        candidates: list[StigDownloadCandidate],
        seen: set[str],
        href: str,
        label: str,
        terms: list[str],
    ) -> None:
        url = urllib.parse.urljoin(self.download_page, href)
        haystack = f"{label} {url}".lower()
        if ".zip" not in haystack and ".xml" not in haystack:
            return
        if not self._matches_terms(haystack, terms):
            return
        if url in seen:
            return
        seen.add(url)
        candidates.append(
            StigDownloadCandidate(
                title=label or Path(urllib.parse.urlparse(url).path).name,
                url=url,
                source="download page",
            )
        )

    def _matches_terms(self, haystack: str, terms: list[str]) -> bool:
        return all(term in haystack for term in terms)

    def _guess_direct_package_candidates(self, terms: list[str]) -> list[StigDownloadCandidate]:
        if not self._is_iosxe_switch_search(terms):
            return []
        candidates: list[StigDownloadCandidate] = []
        for yy, mm in self._quarterly_release_codes():
            release_code = f"Y{yy}M{mm}"
            filename = f"U_Cisco_IOS-XE_Switch_{release_code}_STIG.zip"
            url = f"{CYBER_MIL_DOWNLOAD_BASE_URL}/{filename}"
            if self._url_exists(url):
                candidates.append(
                    StigDownloadCandidate(
                        title=f"Cisco IOS-XE Switch L2/NDM/RTR STIG bundle {release_code}",
                        url=url,
                        upload_date=f"20{yy}-{mm}-01",
                        download_type="STIG",
                        classification="Unclassified",
                        source="direct Cyber.mil package",
                    )
                )
        return candidates

    def _is_iosxe_switch_search(self, terms: list[str]) -> bool:
        required = {"cisco", "ios", "xe", "switch"}
        return required.issubset(set(terms)) and bool({"l2", "l2s", "ndm", "rtr"} & set(terms))

    def _quarterly_release_codes(self) -> list[tuple[str, str]]:
        current_year = date.today().year
        years = range(current_year, current_year - 3, -1)
        months = ("10", "07", "04", "01")
        return [(str(year)[2:], month) for year in years for month in months]

    def _url_exists(self, url: str) -> bool:
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT}, method="HEAD")
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return 200 <= response.status < 400
        except urllib.error.HTTPError as exc:
            if exc.code != 405:
                return False
        except OSError:
            return False
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Range": "bytes=0-0"})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return 200 <= response.status < 400
        except OSError:
            return False

    def _looks_like_dynamic_shell(self, html: str) -> bool:
        lowered = html.lower()
        return "lwc" in lowered or "salesforce" in lowered or "welcome to lwc communities" in lowered

    def _path_from_local_address(self, address: str, parsed: urllib.parse.ParseResult) -> Path:
        if parsed.scheme == "file":
            return Path(urllib.request.url2pathname(parsed.path))
        return Path(address)

    def _filename_from_response(self, url: str, content_disposition: str | None, family: str) -> str:
        if content_disposition:
            match = re.search(r'filename="?([^";]+)"?', content_disposition, flags=re.IGNORECASE)
            if match:
                return Path(match.group(1)).name
        filename = Path(urllib.parse.urlparse(url).path).name
        if filename.lower().endswith((".zip", ".xml")):
            return filename
        return f"{family}_STIG.zip"

    def _extract_xccdf(self, source: Path, family_dir: Path, family: str) -> Path:
        if source.suffix.lower() == ".xml":
            if source.stat().st_size > 25 * 1024 * 1024:
                raise StigSourceError("STIG XML exceeds the supported 25 MB size limit")
            return source
        if source.suffix.lower() != ".zip":
            raise StigSourceError("STIG source must be an XCCDF XML file or ZIP package")
        if source.stat().st_size > MAX_ARCHIVE_BYTES:
            raise StigSourceError("STIG ZIP exceeds the supported 100 MB size limit")
        try:
            with zipfile.ZipFile(source) as archive:
                infos = validate_zip(archive)
                xml_names = sorted(
                    Path(info.filename) for info in infos
                    if not info.is_dir() and info.filename.lower().endswith(".xml")
                )
                xccdf_names = [path for path in xml_names if "xccdf" in path.name.lower()]
                selected = self._select_xccdf_for_family(xccdf_names or xml_names, family)
                if selected is None:
                    raise StigSourceError("No XML/XCCDF file found in STIG ZIP")
                info_by_name = {Path(info.filename): info for info in infos}
                data = archive.read(info_by_name[selected])
        except (zipfile.BadZipFile, ValueError) as exc:
            raise StigSourceError(f"Unsafe or malformed STIG ZIP: {exc}") from exc
        extracted = family_dir / Path(selected.name).name
        temporary = extracted.with_suffix(extracted.suffix + ".tmp")
        temporary.write_bytes(data)
        temporary.replace(extracted)
        return extracted

    def _select_xccdf_for_family(self, xml_files: list[Path], family: str) -> Path | None:
        if not xml_files:
            return None
        lowered_family = family.lower()
        family_markers: list[str] = []
        if "ndm" in lowered_family:
            family_markers = ["ndm"]
        elif "l2" in lowered_family:
            family_markers = ["l2s", "_l2", "-l2"]
        elif "rtr" in lowered_family:
            family_markers = ["rtr"]
        if family_markers:
            matching = [
                path
                for path in xml_files
                if any(marker in path.as_posix().lower() for marker in family_markers)
            ]
            if matching:
                return sorted(matching)[0]
        return sorted(xml_files)[0]

    def _write_metadata(self, family_dir: Path, metadata: StigBenchmarkMetadata) -> None:
        payload = json.dumps(metadata.model_dump(mode="json"), indent=2)
        (family_dir / "metadata.json").write_text(payload, encoding="utf-8")

    def _family_from_filename(self, filename: str) -> str:
        lowered = filename.lower()
        if "ndm" in lowered:
            return "IOSXE_NDM"
        if "l2" in lowered:
            return "IOSXE_L2"
        return "UNKNOWN"
