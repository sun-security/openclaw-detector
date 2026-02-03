#!/usr/bin/env python3
"""
OpenClaw Presence Scanner - CrowdStrike Falcon API Edition

Queries CrowdStrike Falcon APIs to detect OpenClaw installations across managed hosts.
Uses the Discover API to search installed applications telemetry.

Returns: 0=no detections, 1=detected on one or more hosts, 2=API/script failure

Requirements:
    pip install crowdstrike-falconpy

Environment Variables:
    FALCON_CLIENT_ID     - CrowdStrike API client ID (required)
    FALCON_CLIENT_SECRET - CrowdStrike API client secret (required)
    FALCON_BASE_URL      - CrowdStrike API base URL (optional, auto-detected)
    FALCON_MEMBER_CID    - Child CID for MSSP/parent-child scenarios (optional)

Usage:
    python openclaw-detector.py [--json] [--host-details] [--output FILE]
"""

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

try:
    from falconpy import Discover, Hosts
except ImportError:
    print("error: falconpy library not installed", file=sys.stderr)
    print("Install with: pip install crowdstrike-falconpy", file=sys.stderr)
    sys.exit(2)


# --- Detection Patterns ---

OPENCLAW_APP_PATTERNS = [
    "openclaw",
    "OpenClaw",
    "open-claw",
]


@dataclass
class Detection:
    """Represents a single OpenClaw detection on a host."""
    host_id: str
    hostname: str
    detection_type: str
    detail: str
    platform: str
    app_name: Optional[str] = None
    app_version: Optional[str] = None
    app_vendor: Optional[str] = None
    last_seen: Optional[str] = None
    os_version: Optional[str] = None


@dataclass
class ScanResult:
    """Aggregated scan results."""
    scan_time: str
    total_hosts_scanned: int
    hosts_with_detections: int
    detections: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": "detected" if self.hosts_with_detections > 0 else "not-detected",
            "scan_time": self.scan_time,
            "total_hosts_scanned": self.total_hosts_scanned,
            "hosts_with_detections": self.hosts_with_detections,
            "detections": [
                {
                    "host_id": d.host_id,
                    "hostname": d.hostname,
                    "platform": d.platform,
                    "os_version": d.os_version,
                    "detection_type": d.detection_type,
                    "detail": d.detail,
                    "app_name": d.app_name,
                    "app_version": d.app_version,
                    "app_vendor": d.app_vendor,
                    "last_seen": d.last_seen,
                }
                for d in self.detections
            ],
            "errors": self.errors,
        }


class FalconOpenClawScanner:
    """Scans CrowdStrike Falcon for OpenClaw presence using Discover API."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: Optional[str] = None,
        member_cid: Optional[str] = None,
    ):
        self.auth_params = {
            "client_id": client_id,
            "client_secret": client_secret,
        }
        if base_url:
            self.auth_params["base_url"] = base_url
        if member_cid:
            self.auth_params["member_cid"] = member_cid

        self.discover_api = None
        self.hosts_api = None
        self.detections: list[Detection] = []
        self.errors: list[str] = []
        self.hosts_cache: dict[str, dict] = {}

    def _init_discover_api(self):
        """Lazy initialization of Discover API."""
        if self.discover_api is None:
            self.discover_api = Discover(**self.auth_params)

    def _init_hosts_api(self):
        """Lazy initialization of Hosts API."""
        if self.hosts_api is None:
            self.hosts_api = Hosts(**self.auth_params)

    def _get_host_details(self, host_ids: list[str]) -> dict[str, dict]:
        """Fetch host details for given host IDs."""
        self._init_hosts_api()
        details = {}

        # Dedupe and filter empty
        host_ids = list(set(h for h in host_ids if h))
        if not host_ids:
            return details

        # Process in batches of 100 (API limit)
        for i in range(0, len(host_ids), 100):
            batch = host_ids[i : i + 100]
            response = self.hosts_api.get_device_details(ids=batch)

            if response["status_code"] == 200:
                for host in response.get("body", {}).get("resources", []):
                    details[host["device_id"]] = host
            else:
                self.errors.append(
                    f"Failed to get host details: {response.get('body', {}).get('errors', [])}"
                )

        return details

    def _get_application_details(self, app_ids: list[str]) -> list[dict]:
        """Fetch application details for given application IDs."""
        self._init_discover_api()
        applications = []

        # Process in batches of 100 (API limit)
        for i in range(0, len(app_ids), 100):
            batch = app_ids[i : i + 100]
            response = self.discover_api.get_applications(ids=batch)

            if response["status_code"] == 200:
                applications.extend(response.get("body", {}).get("resources", []))
            else:
                self.errors.append(
                    f"Failed to get application details: {response.get('body', {}).get('errors', [])}"
                )

        return applications

    def scan_installed_applications(self) -> int:
        """
        Query Falcon Discover API for installed applications matching OpenClaw patterns.
        Returns count of hosts with detections.
        """
        self._init_discover_api()
        detected_hosts = set()
        all_app_ids = []

        for app_pattern in OPENCLAW_APP_PATTERNS:
            # Use FQL filter to search for applications by name
            # The Discover API supports wildcards in the name filter
            filter_query = f"name:*'{app_pattern}'*"

            try:
                # Query for application IDs matching the pattern
                offset = None
                while True:
                    params = {
                        "filter": filter_query,
                        "limit": 100,
                    }
                    if offset:
                        params["offset"] = offset

                    response = self.discover_api.query_applications(**params)

                    if response["status_code"] == 200:
                        body = response.get("body", {})
                        app_ids = body.get("resources", [])
                        all_app_ids.extend(app_ids)

                        # Check for more results
                        meta = body.get("meta", {})
                        pagination = meta.get("pagination", {})
                        offset = pagination.get("offset")
                        total = pagination.get("total", 0)

                        # Break if no more results
                        if not offset or len(app_ids) == 0:
                            break
                    elif response["status_code"] == 400:
                        # Filter syntax might not be supported, try without wildcards
                        self.errors.append(
                            f"Filter syntax may not be supported for '{app_pattern}': "
                            f"{response.get('body', {}).get('errors', [])}"
                        )
                        break
                    else:
                        self.errors.append(
                            f"App search failed for '{app_pattern}': "
                            f"{response.get('body', {}).get('errors', [])}"
                        )
                        break

            except Exception as e:
                self.errors.append(f"App search exception for '{app_pattern}': {str(e)}")

        # Get details for all found applications
        if all_app_ids:
            applications = self._get_application_details(all_app_ids)

            # Extract unique host IDs from applications
            host_ids_to_fetch = set()
            for app in applications:
                host_id = app.get("host", {}).get("id") or app.get("aid")
                if host_id:
                    host_ids_to_fetch.add(host_id)

            # Fetch host details
            if host_ids_to_fetch:
                host_details = self._get_host_details(list(host_ids_to_fetch))
                self.hosts_cache.update(host_details)

            # Create detections
            for app in applications:
                host_id = app.get("host", {}).get("id") or app.get("aid")
                if not host_id:
                    continue

                detected_hosts.add(host_id)
                host_info = self.hosts_cache.get(host_id, {})

                self.detections.append(
                    Detection(
                        host_id=host_id,
                        hostname=app.get("host", {}).get("hostname") or host_info.get("hostname", "unknown"),
                        platform=app.get("host", {}).get("platform") or host_info.get("platform_name", "unknown"),
                        os_version=host_info.get("os_version", "unknown"),
                        last_seen=host_info.get("last_seen"),
                        detection_type="installed_app",
                        detail=f"Application '{app.get('name', 'unknown')}' found via Discover API",
                        app_name=app.get("name"),
                        app_version=app.get("version"),
                        app_vendor=app.get("vendor"),
                    )
                )

        return len(detected_hosts)

    def scan_host_tags(self) -> int:
        """
        Scan host tags and policies for OpenClaw references.
        Returns count of hosts with detections.
        """
        self._init_hosts_api()
        detected_hosts = set()

        # Search for hosts with OpenClaw-related tags
        for pattern in OPENCLAW_APP_PATTERNS:
            try:
                response = self.hosts_api.query_devices_by_filter(
                    filter=f"tags:*'{pattern}'*",
                    limit=5000,
                )

                if response["status_code"] == 200:
                    host_ids = response.get("body", {}).get("resources", [])
                    if host_ids:
                        # Fetch host details
                        host_details = self._get_host_details(host_ids)
                        self.hosts_cache.update(host_details)

                        for host_id in host_ids:
                            if host_id not in detected_hosts:
                                detected_hosts.add(host_id)
                                host_info = self.hosts_cache.get(host_id, {})
                                self.detections.append(
                                    Detection(
                                        host_id=host_id,
                                        hostname=host_info.get("hostname", "unknown"),
                                        platform=host_info.get("platform_name", "unknown"),
                                        os_version=host_info.get("os_version", "unknown"),
                                        last_seen=host_info.get("last_seen"),
                                        detection_type="host_tag",
                                        detail=f"Host tag contains '{pattern}'",
                                    )
                                )
                # Silently ignore 400 errors (unsupported filter)
            except Exception as e:
                self.errors.append(f"Tag search exception for '{pattern}': {str(e)}")

        return len(detected_hosts)

    def get_total_host_count(self) -> int:
        """Get total number of hosts in the environment."""
        self._init_hosts_api()
        response = self.hosts_api.query_devices_by_filter(limit=1)
        if response["status_code"] == 200:
            return response.get("body", {}).get("meta", {}).get("pagination", {}).get("total", 0)
        return 0

    def execute_scan(self, include_tag_scan: bool = False) -> ScanResult:
        """
        Execute the full scan and return results.

        Args:
            include_tag_scan: If True, also scan host tags (slower)
        """
        scan_start = datetime.utcnow().isoformat() + "Z"

        # Primary detection: installed applications via Discover API
        self.scan_installed_applications()

        # Optional: tag scan
        if include_tag_scan:
            self.scan_host_tags()

        # Get total hosts
        total_hosts = self.get_total_host_count()

        unique_detected_hosts = len(set(d.host_id for d in self.detections))

        return ScanResult(
            scan_time=scan_start,
            total_hosts_scanned=total_hosts,
            hosts_with_detections=unique_detected_hosts,
            detections=self.detections,
            errors=self.errors,
        )


def format_text_output(result: ScanResult, include_details: bool = False) -> str:
    """Format scan results as human-readable text."""
    lines = []

    lines.append(f"summary: {'detected' if result.hosts_with_detections > 0 else 'not-detected'}")
    lines.append(f"scan-time: {result.scan_time}")
    lines.append(f"total-hosts: {result.total_hosts_scanned}")
    lines.append(f"hosts-with-openclaw: {result.hosts_with_detections}")

    if result.detections:
        lines.append("")
        lines.append("# detections")

        # Group by host
        hosts_seen = {}
        for detection in result.detections:
            if detection.host_id not in hosts_seen:
                hosts_seen[detection.host_id] = {
                    "hostname": detection.hostname,
                    "platform": detection.platform,
                    "os_version": detection.os_version,
                    "last_seen": detection.last_seen,
                    "findings": [],
                }
            finding = f"{detection.detection_type}: {detection.detail}"
            if detection.app_version:
                finding += f" (v{detection.app_version})"
            hosts_seen[detection.host_id]["findings"].append(finding)

        for host_id, info in hosts_seen.items():
            lines.append(f"host: {info['hostname']}")
            if include_details:
                lines.append(f"  host-id: {host_id}")
                lines.append(f"  platform: {info['platform']}")
                lines.append(f"  os-version: {info['os_version']}")
                lines.append(f"  last-seen: {info['last_seen']}")
            for finding in info["findings"]:
                lines.append(f"  {finding}")

    if result.errors:
        lines.append("")
        lines.append("# errors")
        for error in result.errors:
            lines.append(f"  {error}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Scan CrowdStrike Falcon for OpenClaw presence across managed hosts"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--host-details",
        action="store_true",
        help="Include detailed host information in output",
    )
    parser.add_argument(
        "--thorough",
        action="store_true",
        help="Perform thorough scan including host tag checks (slower)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Write output to file instead of stdout",
    )
    args = parser.parse_args()

    # Get credentials from environment
    client_id = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")
    base_url = os.environ.get("FALCON_BASE_URL")
    member_cid = os.environ.get("FALCON_MEMBER_CID")

    if not client_id or not client_secret:
        print("error: FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables required", file=sys.stderr)
        print("", file=sys.stderr)
        print("Create API credentials at:", file=sys.stderr)
        print("  https://falcon.crowdstrike.com/support/api-clients-and-keys", file=sys.stderr)
        print("", file=sys.stderr)
        print("Required scopes:", file=sys.stderr)
        print("  - Discover: Read", file=sys.stderr)
        print("  - Hosts: Read", file=sys.stderr)
        sys.exit(2)

    try:
        scanner = FalconOpenClawScanner(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url,
            member_cid=member_cid,
        )

        result = scanner.execute_scan(include_tag_scan=args.thorough)

        if args.json:
            output = json.dumps(result.to_dict(), indent=2)
        else:
            output = format_text_output(result, include_details=args.host_details)

        if args.output:
            with open(args.output, "w") as f:
                f.write(output)
                f.write("\n")
            print(f"Results written to {args.output}")
        else:
            print(output)

        # Exit code: 0=clean, 1=detected, 2=failure
        if result.errors and not result.detections:
            sys.exit(2)
        elif result.hosts_with_detections > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except Exception as e:
        print(f"error: {str(e)}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
