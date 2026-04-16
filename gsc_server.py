from typing import Any, Dict, List, Optional
import logging
import os
import json
import sys
import shutil
import stat
from datetime import datetime, timedelta
from platformdirs import user_config_dir

import google.auth
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# Suppress the noisy file_cache warning from google-api-python-client.
# Some MCP hosts (e.g. GitHub Copilot CLI) treat any stderr output as a
# fatal error, so this prevents false crashes.
logging.getLogger("googleapiclient.discovery_cache").setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# MCP
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("gsc-server")

# Path to your service account JSON or user credentials JSON
# First check if GSC_CREDENTIALS_PATH environment variable is set
# Then try looking in the script directory as a fallback
GSC_CREDENTIALS_PATH = os.environ.get("GSC_CREDENTIALS_PATH")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POSSIBLE_CREDENTIAL_PATHS = [
    GSC_CREDENTIALS_PATH,  # First try the environment variable if set
    os.path.join(SCRIPT_DIR, "service_account_credentials.json"),
    # Note: CWD omitted — unpredictable location could silently load wrong credentials
]

# OAuth client secrets file path
OAUTH_CLIENT_SECRETS_FILE = os.environ.get("GSC_OAUTH_CLIENT_SECRETS_FILE")
if not OAUTH_CLIENT_SECRETS_FILE:
    OAUTH_CLIENT_SECRETS_FILE = os.path.join(SCRIPT_DIR, "client_secrets.json")

# Token file path for storing OAuth tokens.
# Stored in the user config directory so it survives uvx updates (which replace SCRIPT_DIR).
# Override with GSC_CONFIG_DIR env var for Docker/power users.
_CONFIG_DIR = os.environ.get("GSC_CONFIG_DIR") or user_config_dir("mcp-gsc")
os.makedirs(_CONFIG_DIR, exist_ok=True)
TOKEN_FILE = os.path.join(_CONFIG_DIR, "token.json")

# Silently migrate token from old location (SCRIPT_DIR) on first run after upgrade.
# Existing users never need to re-authenticate.
_OLD_TOKEN = os.path.join(SCRIPT_DIR, "token.json")
if os.path.exists(_OLD_TOKEN) and not os.path.exists(TOKEN_FILE):
    shutil.move(_OLD_TOKEN, TOKEN_FILE)

# Environment variable to skip OAuth authentication
SKIP_OAUTH = os.environ.get("GSC_SKIP_OAUTH", "").lower() in ("true", "1", "yes")

# Data state for search analytics queries.
# "all"   → includes fresh/unconfirmed data, matches the GSC dashboard (default)
# "final" → only confirmed data, which lags 2-3 days behind the dashboard
_raw_data_state = os.environ.get("GSC_DATA_STATE", "all").lower().strip()
if _raw_data_state not in ("all", "final"):
    raise ValueError(
        f"Invalid GSC_DATA_STATE value '{_raw_data_state}'. "
        "Accepted values are 'all' (default, matches GSC dashboard) or 'final' (2-3 day lag)."
    )
DATA_STATE = _raw_data_state

# Default site URL — set this to avoid passing site_url on every prompt.
# Example: GSC_DEFAULT_SITE=sc-domain:example.com
GSC_DEFAULT_SITE = os.environ.get("GSC_DEFAULT_SITE", "")

# Read-only scope — limits access to analytics and inspection, no property management.
SCOPES = ["https://www.googleapis.com/auth/webmasters.readonly"]

def get_gsc_service():
    """
    Returns an authorized Search Console service object.
    First tries OAuth authentication, then falls back to service account.
    """
    # Try OAuth authentication first if not skipped
    if not SKIP_OAUTH:
        try:
            return get_gsc_service_oauth()
        except Exception as e:
            # If OAuth fails, try service account
            logging.warning("OAuth authentication failed: %s", e)
            pass

    # Try service account authentication
    for cred_path in POSSIBLE_CREDENTIAL_PATHS:
        if cred_path and os.path.exists(cred_path):
            try:
                creds = service_account.Credentials.from_service_account_file(
                    cred_path, scopes=SCOPES
                )
                return build("searchconsole", "v1", credentials=creds, cache_discovery=False)
            except Exception as e:
                continue  # Try the next path if this one fails

    # If we get here, none of the authentication methods worked
    raise FileNotFoundError(
        f"Authentication failed. Please either:\n"
        f"1. Set up OAuth by placing a client_secrets.json file in the script directory, or\n"
        f"2. Set the GSC_CREDENTIALS_PATH environment variable or place a service account credentials file in one of these locations: "
        f"{', '.join([p for p in POSSIBLE_CREDENTIAL_PATHS[1:] if p])}"
    )

def get_gsc_service_oauth():
    """
    Returns an authorized Search Console service object using OAuth.
    """
    creds = None

    # Check if token file exists
    if os.path.exists(TOKEN_FILE):
        try:
            creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
        except Exception as e:
            # If token file is corrupted, delete it
            if os.path.exists(TOKEN_FILE):
                os.remove(TOKEN_FILE)
            creds = None

    # If credentials don't exist or are invalid, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                # Save the refreshed credentials
                with open(TOKEN_FILE, 'w') as token:
                    token.write(creds.to_json())
                os.chmod(TOKEN_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0o600 — owner read/write only
            except Exception as e:
                # If refresh fails, delete the bad token and trigger new OAuth flow
                if os.path.exists(TOKEN_FILE):
                    os.remove(TOKEN_FILE)
                # Fall through to the OAuth flow below
                creds = None

        # Start new OAuth flow if we don't have valid credentials
        if not creds or not creds.valid:
            # IMPORTANT: When running as MCP server (stdio), run_local_server() blocks
            # forever because no browser can open. Only allow interactive OAuth when
            # running directly from terminal (stdin is a TTY).
            if not sys.stdin.isatty():
                raise RuntimeError(
                    "OAuth token is missing or expired and cannot be refreshed. "
                    "Run the OAuth flow manually first:\n"
                    "  Run: python gsc_server.py\n"
                    "Then restart Claude Code."
                )

            # Check if client secrets file exists
            if not os.path.exists(OAUTH_CLIENT_SECRETS_FILE):
                raise FileNotFoundError(
                    f"OAuth client secrets file not found. Please place a client_secrets.json file in the script directory "
                    f"or set the GSC_OAUTH_CLIENT_SECRETS_FILE environment variable."
                )

            # Start OAuth flow (only when running interactively — isatty guard above prevents
            # reaching this point in MCP stdio context).
            flow = InstalledAppFlow.from_client_secrets_file(OAUTH_CLIENT_SECRETS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)

            # Save the credentials for future use
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())
            os.chmod(TOKEN_FILE, stat.S_IRUSR | stat.S_IWUSR)  # 0o600 — owner read/write only

    # Build and return the service
    return build("searchconsole", "v1", credentials=creds, cache_discovery=False)


def _site_not_found_error(site_url: str) -> str:
    """Return a helpful message when a GSC property returns 404."""
    lines = [f"Property '{site_url}' not found (404). Possible causes:\n"]
    lines.append(
        "1. The site_url doesn't exactly match what is in GSC. "
        "Run list_properties to get the exact string to use."
    )
    if site_url.startswith("sc-domain:"):
        lines.append(
            "2. Domain properties require the service account to be explicitly added "
            "under GSC Settings > Users and permissions for that specific domain property. "
            "OAuth users must also have verified access to it."
        )
    else:
        lines.append(
            "2. If your property is a domain property (covers all subdomains), "
            "the correct format is 'sc-domain:example.com', not a full URL."
        )
    lines.append(
        "3. The authenticated account may not have access to this property."
    )
    return "\n".join(lines)


@mcp.tool()
async def list_properties() -> str:
    """
    Retrieves and returns the user's Search Console properties.
    """
    try:
        service = get_gsc_service()
        site_list = service.sites().list().execute()

        sites = site_list.get("siteEntry", [])

        if not sites:
            return "No Search Console properties found."

        return json.dumps({
            "count": len(sites),
            "properties": [
                {
                    "site_url": site.get("siteUrl", "Unknown"),
                    "permission_level": site.get("permissionLevel", "Unknown"),
                }
                for site in sites
            ],
        })
    except FileNotFoundError as e:
        return (
            "Error: Service account credentials file not found.\n\n"
            "To access Google Search Console, please:\n"
            "1. Create a service account in Google Cloud Console\n"
            "2. Download the JSON credentials file\n"
            "3. Save it as 'service_account_credentials.json' in the same directory as this script\n"
            "4. Share your GSC properties with the service account email"
        )
    except Exception as e:
        logger.debug("Error in list_properties: %s", e)
        return "Error retrieving properties. Check logs for details."

@mcp.tool()
async def get_search_analytics(site_url: str = None, days: int = 28, dimensions: str = "query", row_limit: int = 20) -> str:
    """
    Get search analytics data for a specific property.

    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
        days: Number of days to look back (default: 28)
        dimensions: Dimensions to group by (default: query). Options: query, page, device, country, date
                   You can provide multiple dimensions separated by comma (e.g., "query,page")
        row_limit: Number of rows to return (default: 20, max: 500). Use 5-20 for quick overviews,
                   50-200 for deeper analysis, up to 500 for comprehensive reports. For bulk exports
                   beyond 500 rows, use get_advanced_search_analytics which supports pagination.
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Calculate date range
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        # Parse dimensions
        dimension_list = [d.strip() for d in dimensions.split(",")]

        # Build request
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": dimension_list,
            "rowLimit": min(max(1, row_limit), 500),
            "dataState": DATA_STATE
        }

        # Execute request
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()

        if not response.get("rows"):
            return f"No search analytics data found for {site_url} in the last {days} days."

        rows = []
        for row in response.get("rows", []):
            entry = {}
            for i, dim in enumerate(dimension_list):
                entry[dim] = row.get("keys", [])[i] if i < len(row.get("keys", [])) else None
            entry["clicks"] = row.get("clicks", 0)
            entry["impressions"] = row.get("impressions", 0)
            entry["ctr"] = round(row.get("ctr", 0), 4)
            entry["position"] = round(row.get("position", 0), 1)
            rows.append(entry)

        return json.dumps({
            "site_url": site_url,
            "date_range": {
                "start": start_date.strftime("%Y-%m-%d"),
                "end": end_date.strftime("%Y-%m-%d"),
                "days": days,
            },
            "dimensions": dimension_list,
            "row_count": len(rows),
            "rows": rows,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        logger.debug("Error in get_search_analytics: %s", e)
        return "Error retrieving search analytics. Check logs for details."

@mcp.tool()
async def get_site_details(site_url: str = None) -> str:
    """
    Get detailed information about a specific Search Console property.

    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Get site details
        site_info = service.sites().get(siteUrl=site_url).execute()

        result = {
            "site_url": site_url,
            "permission_level": site_info.get("permissionLevel", "Unknown"),
        }

        if "siteVerificationInfo" in site_info:
            verify_info = site_info["siteVerificationInfo"]
            result["verification"] = {
                "state": verify_info.get("verificationState", "Unknown"),
                "verified_user": verify_info.get("verifiedUser"),
                "method": verify_info.get("verificationMethod"),
            }

        if "ownershipInfo" in site_info:
            owner_info = site_info["ownershipInfo"]
            result["ownership"] = {
                "owner": owner_info.get("owner", "Unknown"),
                "verification_method": owner_info.get("verificationMethod"),
            }

        return json.dumps(result)
    except Exception as e:
        logger.debug("Error in get_site_details: %s", e)
        return "Error retrieving site details. Check logs for details."

@mcp.tool()
async def get_sitemaps(site_url: str = None) -> str:
    """
    List all sitemaps for a specific Search Console property.

    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Get sitemaps list
        sitemaps = service.sitemaps().list(siteUrl=site_url).execute()

        if not sitemaps.get("sitemap"):
            return f"No sitemaps found for {site_url}."

        sitemap_list = []
        for sitemap in sitemaps.get("sitemap", []):
            last_downloaded = sitemap.get("lastDownloaded")
            if last_downloaded:
                try:
                    dt = datetime.fromisoformat(last_downloaded.replace("Z", "+00:00"))
                    last_downloaded = dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    pass

            errors = int(sitemap.get("errors", 0))
            warnings = int(sitemap.get("warnings", 0))

            status = "Valid"
            if errors > 0:
                status = "Has errors"
            elif warnings > 0:
                status = "Has warnings"

            indexed_urls = None
            if "contents" in sitemap:
                for content in sitemap["contents"]:
                    if content.get("type") == "web":
                        indexed_urls = content.get("submitted")
                        break

            sitemap_list.append({
                "path": sitemap.get("path", "Unknown"),
                "last_downloaded": last_downloaded,
                "status": status,
                "indexed_urls": indexed_urls,
                "errors": errors,
                "warnings": warnings,
            })

        return json.dumps({
            "site_url": site_url,
            "count": len(sitemap_list),
            "sitemaps": sitemap_list,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        logger.debug("Error in get_sitemaps: %s", e)
        return "Error retrieving sitemaps. Check logs for details."

@mcp.tool()
async def inspect_url_enhanced(page_url: str, site_url: str = None) -> str:
    """
    Enhanced URL inspection to check indexing status and rich results in Google.

    Args:
        page_url: The specific URL to inspect
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Build request
        request = {
            "inspectionUrl": page_url,
            "siteUrl": site_url
        }

        # Execute request
        response = service.urlInspection().index().inspect(body=request).execute()

        if not response or "inspectionResult" not in response:
            return f"No inspection data found for {page_url}."

        inspection = response["inspectionResult"]
        index_status = inspection.get("indexStatusResult", {})

        last_crawled = None
        if "lastCrawlTime" in index_status:
            try:
                crawl_time = datetime.fromisoformat(index_status["lastCrawlTime"].replace("Z", "+00:00"))
                last_crawled = crawl_time.strftime("%Y-%m-%d %H:%M")
            except Exception:
                last_crawled = index_status["lastCrawlTime"]

        rich_results = None
        if "richResultsResult" in inspection:
            rich = inspection["richResultsResult"]
            rich_results = {
                "verdict": rich.get("verdict", "UNKNOWN"),
                "detected_types": [
                    item.get("richResultType", "Unknown")
                    for item in rich.get("detectedItems", [])
                ],
                "issues": [
                    {"severity": issue.get("severity"), "message": issue.get("message")}
                    for issue in rich.get("richResultsIssues", [])
                ],
            }

        return json.dumps({
            "page_url": page_url,
            "site_url": site_url,
            "inspection_result_link": inspection.get("inspectionResultLink"),
            "verdict": index_status.get("verdict", "UNKNOWN"),
            "coverage_state": index_status.get("coverageState"),
            "last_crawled": last_crawled,
            "page_fetch_state": index_status.get("pageFetchState"),
            "robots_txt_state": index_status.get("robotsTxtState"),
            "indexing_state": index_status.get("indexingState"),
            "google_canonical": index_status.get("googleCanonical"),
            "user_canonical": index_status.get("userCanonical"),
            "crawled_as": index_status.get("crawledAs"),
            "referring_urls": index_status.get("referringUrls", [])[:5],
            "rich_results": rich_results,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        logger.debug("Error in inspect_url_enhanced: %s", e)
        return "Error inspecting URL. Check logs for details."

@mcp.tool()
async def batch_url_inspection(urls: str, site_url: str = None) -> str:
    """
    Inspect multiple URLs in batch (within API limits).

    Args:
        urls: List of URLs to inspect, one per line
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Parse URLs
        url_list = [url.strip() for url in urls.split('\n') if url.strip()]

        if not url_list:
            return "No URLs provided for inspection."

        if len(url_list) > 10:
            return f"Too many URLs provided ({len(url_list)}). Please limit to 10 URLs per batch to avoid API quota issues."

        # Process each URL
        results = []

        for page_url in url_list:
            # Build request
            request = {
                "inspectionUrl": page_url,
                "siteUrl": site_url
            }

            try:
                # Execute request with a small delay to avoid rate limits
                response = service.urlInspection().index().inspect(body=request).execute()

                if not response or "inspectionResult" not in response:
                    results.append(f"{page_url}: No inspection data found")
                    continue

                inspection = response["inspectionResult"]
                index_status = inspection.get("indexStatusResult", {})

                # Get key information
                verdict = index_status.get("verdict", "UNKNOWN")
                coverage = index_status.get("coverageState", "Unknown")
                last_crawl = "Never"

                if "lastCrawlTime" in index_status:
                    try:
                        crawl_time = datetime.fromisoformat(index_status["lastCrawlTime"].replace('Z', '+00:00'))
                        last_crawl = crawl_time.strftime('%Y-%m-%d')
                    except Exception:
                        last_crawl = index_status["lastCrawlTime"]

                # Check for rich results
                rich_results = "None"
                if "richResultsResult" in inspection:
                    rich = inspection["richResultsResult"]
                    if rich.get("verdict") == "PASS" and "detectedItems" in rich and rich["detectedItems"]:
                        rich_types = [item.get("richResultType", "Unknown") for item in rich["detectedItems"]]
                        rich_results = ", ".join(rich_types)

                results.append({
                    "url": page_url,
                    "verdict": verdict,
                    "coverage_state": coverage,
                    "last_crawled": last_crawl,
                    "rich_results": rich_results,
                })

            except Exception as e:
                results.append({"url": page_url, "error": str(e)})

        return json.dumps({
            "site_url": site_url,
            "count": len(results),
            "results": results,
        })

    except Exception as e:
        logger.debug("Error in batch_url_inspection: %s", e)
        return "Error performing batch inspection. Check logs for details."

@mcp.tool()
async def check_indexing_issues(urls: str, site_url: str = None) -> str:
    """
    Check for specific indexing issues across multiple URLs.

    Args:
        urls: List of URLs to check, one per line
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Parse URLs
        url_list = [url.strip() for url in urls.split('\n') if url.strip()]

        if not url_list:
            return "No URLs provided for inspection."

        if len(url_list) > 10:
            return f"Too many URLs provided ({len(url_list)}). Please limit to 10 URLs per batch to avoid API quota issues."

        # Track issues by category
        issues_summary = {
            "not_indexed": [],
            "canonical_issues": [],
            "robots_blocked": [],
            "fetch_issues": [],
            "indexed": []
        }

        # Process each URL
        for page_url in url_list:
            # Build request
            request = {
                "inspectionUrl": page_url,
                "siteUrl": site_url
            }

            try:
                # Execute request
                response = service.urlInspection().index().inspect(body=request).execute()

                if not response or "inspectionResult" not in response:
                    issues_summary["not_indexed"].append(f"{page_url} - No inspection data found")
                    continue

                inspection = response["inspectionResult"]
                index_status = inspection.get("indexStatusResult", {})

                # Check indexing status
                verdict = index_status.get("verdict", "UNKNOWN")
                coverage = index_status.get("coverageState", "Unknown")

                if verdict != "PASS" or "not indexed" in coverage.lower() or "excluded" in coverage.lower():
                    issues_summary["not_indexed"].append(f"{page_url} - {coverage}")
                else:
                    issues_summary["indexed"].append(page_url)

                # Check canonical issues
                google_canonical = index_status.get("googleCanonical", "")
                user_canonical = index_status.get("userCanonical", "")

                if google_canonical and user_canonical and google_canonical != user_canonical:
                    issues_summary["canonical_issues"].append(
                        f"{page_url} - Google chose: {google_canonical} instead of user-declared: {user_canonical}"
                    )

                # Check robots.txt status
                robots_state = index_status.get("robotsTxtState", "")
                if robots_state == "BLOCKED":
                    issues_summary["robots_blocked"].append(page_url)

                # Check fetch issues
                fetch_state = index_status.get("pageFetchState", "")
                if fetch_state != "SUCCESSFUL":
                    issues_summary["fetch_issues"].append(f"{page_url} - {fetch_state}")

            except Exception as e:
                issues_summary["not_indexed"].append(f"{page_url} - Error: {str(e)}")

        return json.dumps({
            "site_url": site_url,
            "summary": {
                "total_checked": len(url_list),
                "indexed": len(issues_summary["indexed"]),
                "not_indexed": len(issues_summary["not_indexed"]),
                "canonical_issues": len(issues_summary["canonical_issues"]),
                "robots_blocked": len(issues_summary["robots_blocked"]),
                "fetch_issues": len(issues_summary["fetch_issues"]),
            },
            "issues": {
                "not_indexed": issues_summary["not_indexed"],
                "canonical_issues": issues_summary["canonical_issues"],
                "robots_blocked": issues_summary["robots_blocked"],
                "fetch_issues": issues_summary["fetch_issues"],
            },
            "indexed_urls": issues_summary["indexed"],
        })

    except Exception as e:
        logger.debug("Error in check_indexing_issues: %s", e)
        return "Error checking indexing issues. Check logs for details."

@mcp.tool()
async def get_performance_overview(site_url: str = None, days: int = 28) -> str:
    """
    Get a performance overview for a specific property.

    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
        days: Number of days to look back (default: 28)
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Calculate date range
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        # Get total metrics
        total_request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": [],  # No dimensions for totals
            "rowLimit": 1,
            "dataState": DATA_STATE
        }

        total_response = service.searchanalytics().query(siteUrl=site_url, body=total_request).execute()

        # Get by date for trend
        date_request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": ["date"],
            "rowLimit": days,
            "dataState": DATA_STATE
        }

        date_response = service.searchanalytics().query(siteUrl=site_url, body=date_request).execute()

        if not total_response.get("rows"):
            return f"No performance data available for {site_url} in the last {days} days."

        totals_row = total_response["rows"][0]
        totals = {
            "clicks": totals_row.get("clicks", 0),
            "impressions": totals_row.get("impressions", 0),
            "ctr": round(totals_row.get("ctr", 0), 4),
            "position": round(totals_row.get("position", 0), 1),
        }

        daily_trend = []
        if date_response.get("rows"):
            sorted_rows = sorted(date_response["rows"], key=lambda x: x["keys"][0])
            for row in sorted_rows:
                daily_trend.append({
                    "date": row["keys"][0],
                    "clicks": row.get("clicks", 0),
                    "impressions": row.get("impressions", 0),
                    "ctr": round(row.get("ctr", 0), 4),
                    "position": round(row.get("position", 0), 1),
                })

        return json.dumps({
            "site_url": site_url,
            "date_range": {
                "start": start_date.strftime("%Y-%m-%d"),
                "end": end_date.strftime("%Y-%m-%d"),
                "days": days,
            },
            "totals": totals,
            "daily_trend": daily_trend,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        logger.debug("Error in get_performance_overview: %s", e)
        return "Error retrieving performance overview. Check logs for details."

@mcp.tool()
async def get_advanced_search_analytics(
    site_url: str = None,
    start_date: str = None,
    end_date: str = None,
    dimensions: str = "query",
    search_type: str = "WEB",
    row_limit: int = 1000,
    start_row: int = 0,
    sort_by: str = "clicks",
    sort_direction: str = "descending",
    filter_dimension: str = None,
    filter_operator: str = "contains",
    filter_expression: str = None,
    filters: str = None,
    data_state: str = None
) -> str:
    """
    Get advanced search analytics data with sorting, filtering, and pagination.

    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
        start_date: Start date in YYYY-MM-DD format (defaults to 28 days ago)
        end_date: End date in YYYY-MM-DD format (defaults to today)
        dimensions: Dimensions to group by, comma-separated (e.g., "query,page,device")
        search_type: Type of search results (WEB, IMAGE, VIDEO, NEWS, DISCOVER)
        row_limit: Maximum number of rows to return (max 25000)
        start_row: Starting row for pagination
        sort_by: Metric to sort by (clicks, impressions, ctr, position)
        sort_direction: Sort direction (ascending or descending)
        filter_dimension: Single filter dimension (query, page, country, device). Use 'filters' instead for multiple filters.
        filter_operator: Single filter operator (contains, equals, notContains, notEquals)
        filter_expression: Single filter expression value
        filters: JSON array of filter objects for AND logic across multiple dimensions. Overrides
                 filter_dimension/filter_operator/filter_expression when provided. Each object must
                 have 'dimension', 'operator', and 'expression' keys. Valid dimensions: query, page,
                 country, device. Valid operators: contains, equals, notContains, notEquals.
                 Example: [{"dimension":"country","operator":"equals","expression":"usa"},
                           {"dimension":"device","operator":"equals","expression":"MOBILE"}]
        data_state: Data freshness — "all" (default, matches GSC dashboard) or "final" (confirmed data only, 2-3 day lag)
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Calculate date range if not provided
        if not end_date:
            end_date = datetime.now().date().strftime("%Y-%m-%d")
        if not start_date:
            start_date = (datetime.now().date() - timedelta(days=28)).strftime("%Y-%m-%d")

        # Resolve and validate data_state (per-call override or fall back to global setting)
        resolved_data_state = (data_state or DATA_STATE).lower().strip()
        if resolved_data_state not in ("all", "final"):
            return (
                f"Invalid data_state value '{data_state}'. "
                "Accepted values are 'all' (matches GSC dashboard) or 'final' (2-3 day lag)."
            )

        # Parse dimensions
        dimension_list = [d.strip() for d in dimensions.split(",")]

        # Build request
        request = {
            "startDate": start_date,
            "endDate": end_date,
            "dimensions": dimension_list,
            "rowLimit": min(row_limit, 25000),  # Cap at API maximum
            "startRow": start_row,
            "searchType": search_type.upper(),
            "dataState": resolved_data_state
        }

        # Add sorting
        if sort_by:
            metric_map = {
                "clicks": "CLICK_COUNT",
                "impressions": "IMPRESSION_COUNT",
                "ctr": "CTR",
                "position": "POSITION"
            }

            if sort_by in metric_map:
                request["orderBy"] = [{
                    "metric": metric_map[sort_by],
                    "direction": sort_direction.lower()
                }]

        # Build filter groups — multi-filter JSON takes priority over single-filter params
        active_filters = []
        if filters:
            try:
                filter_list = json.loads(filters)
            except json.JSONDecodeError:
                return "Invalid filters JSON. Please provide a valid JSON array of filter objects."
            if not isinstance(filter_list, list) or len(filter_list) == 0:
                return "Invalid filters value. Expected a non-empty JSON array of filter objects."
            for f in filter_list:
                if not all(k in f for k in ("dimension", "operator", "expression")):
                    return (
                        "Each filter object must have 'dimension', 'operator', and 'expression' keys. "
                        f"Invalid filter: {f}"
                    )
            request["dimensionFilterGroups"] = [{"filters": filter_list}]
            active_filters = filter_list
        elif filter_dimension and filter_expression:
            single_filter = {
                "dimension": filter_dimension,
                "operator": filter_operator,
                "expression": filter_expression
            }
            request["dimensionFilterGroups"] = [{"filters": [single_filter]}]
            active_filters = [single_filter]

        # Execute request
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()

        if not response.get("rows"):
            no_data_msg = (
                f"No search analytics data found for {site_url} with the specified parameters.\n\n"
                f"Parameters used:\n"
                f"- Date range: {start_date} to {end_date}\n"
                f"- Dimensions: {dimensions}\n"
                f"- Search type: {search_type}\n"
            )
            if active_filters:
                no_data_msg += "- Filters:\n"
                for f in active_filters:
                    no_data_msg += f"    {f['dimension']} {f['operator']} '{f['expression']}'\n"
            else:
                no_data_msg += "- No filter applied\n"
            return no_data_msg

        rows = []
        for row in response.get("rows", []):
            entry = {}
            for i, dim in enumerate(dimension_list):
                entry[dim] = row.get("keys", [])[i] if i < len(row.get("keys", [])) else None
            entry["clicks"] = row.get("clicks", 0)
            entry["impressions"] = row.get("impressions", 0)
            entry["ctr"] = round(row.get("ctr", 0), 4)
            entry["position"] = round(row.get("position", 0), 1)
            rows.append(entry)

        has_more = len(response.get("rows", [])) == row_limit
        return json.dumps({
            "site_url": site_url,
            "date_range": {"start": start_date, "end": end_date},
            "search_type": search_type,
            "dimensions": dimension_list,
            "filters_applied": active_filters,
            "pagination": {
                "start_row": start_row,
                "row_count": len(rows),
                "has_more": has_more,
                "next_start_row": start_row + row_limit if has_more else None,
            },
            "rows": rows,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        logger.debug("Error in get_advanced_search_analytics: %s", e)
        return "Error retrieving advanced search analytics. Check logs for details."

@mcp.tool()
async def compare_search_periods(
    period1_start: str,
    period1_end: str,
    period2_start: str,
    period2_end: str,
    dimensions: str = "query",
    limit: int = 10,
    site_url: str = None,
) -> str:
    """
    Compare search analytics data between two time periods.

    Args:
        period1_start: Start date for period 1 (YYYY-MM-DD)
        period1_end: End date for period 1 (YYYY-MM-DD)
        period2_start: Start date for period 2 (YYYY-MM-DD)
        period2_end: End date for period 2 (YYYY-MM-DD)
        dimensions: Dimensions to group by (default: query)
        limit: Number of top results to compare (default: 10)
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Parse dimensions
        dimension_list = [d.strip() for d in dimensions.split(",")]

        # Build requests for both periods
        period1_request = {
            "startDate": period1_start,
            "endDate": period1_end,
            "dimensions": dimension_list,
            "rowLimit": 1000,  # Get more to ensure we can match items between periods
            "dataState": DATA_STATE
        }

        period2_request = {
            "startDate": period2_start,
            "endDate": period2_end,
            "dimensions": dimension_list,
            "rowLimit": 1000,
            "dataState": DATA_STATE
        }

        # Execute requests
        period1_response = service.searchanalytics().query(siteUrl=site_url, body=period1_request).execute()
        period2_response = service.searchanalytics().query(siteUrl=site_url, body=period2_request).execute()

        period1_rows = period1_response.get("rows", [])
        period2_rows = period2_response.get("rows", [])

        if not period1_rows and not period2_rows:
            return f"No data found for either period for {site_url}."

        # Create dictionaries for easy lookup
        period1_data = {tuple(row.get("keys", [])): row for row in period1_rows}
        period2_data = {tuple(row.get("keys", [])): row for row in period2_rows}

        # Find common keys and calculate differences
        all_keys = set(period1_data.keys()) | set(period2_data.keys())
        comparison_data = []

        for key in all_keys:
            p1_row = period1_data.get(key, {"clicks": 0, "impressions": 0, "ctr": 0, "position": 0})
            p2_row = period2_data.get(key, {"clicks": 0, "impressions": 0, "ctr": 0, "position": 0})

            # Calculate differences
            click_diff = p2_row.get("clicks", 0) - p1_row.get("clicks", 0)
            click_pct = (click_diff / p1_row.get("clicks", 1)) * 100 if p1_row.get("clicks", 0) > 0 else float('inf')

            imp_diff = p2_row.get("impressions", 0) - p1_row.get("impressions", 0)
            imp_pct = (imp_diff / p1_row.get("impressions", 1)) * 100 if p1_row.get("impressions", 0) > 0 else float('inf')

            ctr_diff = p2_row.get("ctr", 0) - p1_row.get("ctr", 0)
            pos_diff = p1_row.get("position", 0) - p2_row.get("position", 0)  # Note: lower position is better

            comparison_data.append({
                "key": key,
                "p1_clicks": p1_row.get("clicks", 0),
                "p2_clicks": p2_row.get("clicks", 0),
                "click_diff": click_diff,
                "click_pct": click_pct,
                "p1_impressions": p1_row.get("impressions", 0),
                "p2_impressions": p2_row.get("impressions", 0),
                "imp_diff": imp_diff,
                "imp_pct": imp_pct,
                "p1_ctr": p1_row.get("ctr", 0),
                "p2_ctr": p2_row.get("ctr", 0),
                "ctr_diff": ctr_diff,
                "p1_position": p1_row.get("position", 0),
                "p2_position": p2_row.get("position", 0),
                "pos_diff": pos_diff
            })

        # Sort by absolute click difference
        comparison_data.sort(key=lambda x: abs(x["click_diff"]), reverse=True)

        serialisable = []
        for item in comparison_data[:limit]:
            click_pct = item["click_pct"] if item["click_pct"] != float("inf") else None
            imp_pct = item["imp_pct"] if item["imp_pct"] != float("inf") else None
            serialisable.append({
                "key": list(item["key"]),
                "p1_clicks": item["p1_clicks"],
                "p2_clicks": item["p2_clicks"],
                "click_diff": item["click_diff"],
                "click_pct": round(click_pct, 1) if click_pct is not None else None,
                "p1_impressions": item["p1_impressions"],
                "p2_impressions": item["p2_impressions"],
                "imp_diff": item["imp_diff"],
                "imp_pct": round(imp_pct, 1) if imp_pct is not None else None,
                "p1_ctr": round(item["p1_ctr"], 4),
                "p2_ctr": round(item["p2_ctr"], 4),
                "ctr_diff": round(item["ctr_diff"], 4),
                "p1_position": round(item["p1_position"], 1),
                "p2_position": round(item["p2_position"], 1),
                "position_diff": round(item["pos_diff"], 1),
            })

        return json.dumps({
            "site_url": site_url,
            "period1": {"start": period1_start, "end": period1_end},
            "period2": {"start": period2_start, "end": period2_end},
            "dimensions": dimension_list,
            "total_items": len(comparison_data),
            "showing": len(serialisable),
            "comparison": serialisable,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        logger.debug("Error in compare_search_periods: %s", e)
        return "Error comparing search periods. Check logs for details."

@mcp.tool()
async def get_search_by_page_query(
    page_url: str,
    days: int = 28,
    row_limit: int = 20,
    site_url: str = None,
) -> str:
    """
    Get search analytics data for a specific page, broken down by query.

    Args:
        page_url: The specific page URL to analyze
        days: Number of days to look back (default: 28)
        row_limit: Number of rows to return (default: 20, max: 500). Use 5-20 for quick overviews,
                   50-200 for deeper analysis, up to 500 for comprehensive reports. For bulk exports
                   beyond 500 rows, use get_advanced_search_analytics which supports pagination.
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Calculate date range
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)

        # Build request with page filter
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": ["query"],
            "dimensionFilterGroups": [{
                "filters": [{
                    "dimension": "page",
                    "operator": "equals",
                    "expression": page_url
                }]
            }],
            "rowLimit": min(max(1, row_limit), 500),
            "orderBy": [{"metric": "CLICK_COUNT", "direction": "descending"}],
            "dataState": DATA_STATE
        }

        # Execute request
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()

        if not response.get("rows"):
            return f"No search data found for page {page_url} in the last {days} days."

        rows = []
        for row in response.get("rows", []):
            rows.append({
                "query": row.get("keys", ["Unknown"])[0],
                "clicks": row.get("clicks", 0),
                "impressions": row.get("impressions", 0),
                "ctr": round(row.get("ctr", 0), 4),
                "position": round(row.get("position", 0), 1),
            })

        total_clicks = sum(r["clicks"] for r in rows)
        total_impressions = sum(r["impressions"] for r in rows)

        return json.dumps({
            "site_url": site_url,
            "page_url": page_url,
            "date_range": {
                "start": start_date.strftime("%Y-%m-%d"),
                "end": end_date.strftime("%Y-%m-%d"),
                "days": days,
            },
            "totals": {
                "clicks": total_clicks,
                "impressions": total_impressions,
                "avg_ctr": round(total_clicks / total_impressions, 4) if total_impressions > 0 else 0,
            },
            "row_count": len(rows),
            "rows": rows,
        })
    except Exception as e:
        logger.debug("Error in get_search_by_page_query: %s", e)
        return "Error retrieving page query data. Check logs for details."

@mcp.tool()
async def list_sitemaps_enhanced(site_url: str = None, sitemap_index: str = None) -> str:
    """
    List all sitemaps for a specific Search Console property with detailed information.

    Args:
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
        sitemap_index: Optional sitemap index URL to list child sitemaps
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Get sitemaps list
        if sitemap_index:
            sitemaps = service.sitemaps().list(siteUrl=site_url, sitemapIndex=sitemap_index).execute()
        else:
            sitemaps = service.sitemaps().list(siteUrl=site_url).execute()

        if not sitemaps.get("sitemap"):
            return f"No sitemaps found for {site_url}" + (f" in index {sitemap_index}" if sitemap_index else ".")

        def _fmt_date(raw):
            if not raw:
                return None
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
            except Exception:
                return raw

        sitemap_list = []
        for sitemap in sitemaps.get("sitemap", []):
            errors = int(sitemap.get("errors", 0))
            warnings = int(sitemap.get("warnings", 0))
            url_count = None
            if "contents" in sitemap:
                for content in sitemap["contents"]:
                    if content.get("type") == "web":
                        url_count = content.get("submitted")
                        break
            sitemap_list.append({
                "path": sitemap.get("path", "Unknown"),
                "last_submitted": _fmt_date(sitemap.get("lastSubmitted")),
                "last_downloaded": _fmt_date(sitemap.get("lastDownloaded")),
                "type": "Index" if sitemap.get("isSitemapsIndex", False) else "Sitemap",
                "is_pending": sitemap.get("isPending", False),
                "url_count": url_count,
                "errors": errors,
                "warnings": warnings,
            })

        pending_count = sum(1 for s in sitemap_list if s["is_pending"])

        return json.dumps({
            "site_url": site_url,
            "sitemap_index": sitemap_index,
            "count": len(sitemap_list),
            "pending_count": pending_count,
            "sitemaps": sitemap_list,
        })
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        logger.debug("Error in list_sitemaps_enhanced: %s", e)
        return "Error retrieving sitemaps. Check logs for details."

@mcp.tool()
async def get_sitemap_details(sitemap_url: str, site_url: str = None) -> str:
    """
    Get detailed information about a specific sitemap.

    Args:
        sitemap_url: The full URL of the sitemap to inspect
        site_url: Exact GSC property URL from list_properties (e.g. "https://example.com/" or
                  "sc-domain:example.com"). Falls back to GSC_DEFAULT_SITE env var if not provided.
    """
    site_url = site_url or GSC_DEFAULT_SITE
    if not site_url:
        return "Error: site_url is required. Set GSC_DEFAULT_SITE env var or pass site_url explicitly."
    try:
        service = get_gsc_service()

        # Get sitemap details
        details = service.sitemaps().get(siteUrl=site_url, feedpath=sitemap_url).execute()

        if not details:
            return f"No details found for sitemap {sitemap_url}."

        def _fmt_date(raw):
            if not raw:
                return None
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
            except Exception:
                return raw

        is_index = details.get("isSitemapsIndex", False)
        content_breakdown = [
            {
                "type": content.get("type", "unknown").upper(),
                "submitted": content.get("submitted", 0),
                "indexed": content.get("indexed"),
            }
            for content in details.get("contents", [])
        ]

        return json.dumps({
            "sitemap_url": sitemap_url,
            "site_url": site_url,
            "type": "Index" if is_index else "Sitemap",
            "status": "pending" if details.get("isPending", False) else "processed",
            "last_submitted": _fmt_date(details.get("lastSubmitted")),
            "last_downloaded": _fmt_date(details.get("lastDownloaded")),
            "errors": int(details.get("errors", 0)),
            "warnings": int(details.get("warnings", 0)),
            "content_breakdown": content_breakdown,
            "is_index": is_index,
        })
    except Exception as e:
        logger.debug("Error in get_sitemap_details: %s", e)
        return "Error retrieving sitemap details. Check logs for details."


def main():
    """Entry point for the MCP server. Runs over stdio only."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
