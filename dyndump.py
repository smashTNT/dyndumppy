#!/usr/bin/env python3
"""
dyndump - Dump Microsoft Dynamics CRM data
Python implementation of the Rust tool by Irate-Walrus
"""

import argparse
import json
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


API_ENDPOINT = "/api/data/"


class DynamicsClient:
    """Client for interacting with Microsoft Dynamics CRM"""

    def __init__(
        self,
        target: str,
        headers: Optional[Dict[str, str]] = None,
        proxy: Optional[str] = None,
        api_version: str = "v9.2",
        insecure: bool = False,
        page_size: int = 1000,
    ):
        self.target = target.rstrip("/")
        self.api_version = api_version
        self.page_size = page_size
        self.base_url = f"{self.target}{API_ENDPOINT}{self.api_version}"

        # Setup session
        self.session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Add custom headers
        if headers:
            self.session.headers.update(headers)

        # Configure proxy
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})

        # Configure TLS verification
        if insecure:
            self.session.verify = False
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def whoami(self) -> Dict[str, Any]:
        """Get current user information via WhoAmI endpoint"""
        url = f"{self.base_url}/WhoAmI"
        logging.debug(f"Requesting /WhoAmI from {url}")

        response = self.session.get(url, timeout=30)
        response.raise_for_status()

        data = response.json()
        logging.debug(f"Received response {response.status_code}")
        return data

    def get_entity(self, entity_set_name: str, entity_id: str) -> Dict[str, Any]:
        """Get a single entity by ID"""
        url = f"{self.base_url}/{entity_set_name}({entity_id})"
        response = self.session.get(url, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_systemuser_privileges(self, systemuser_id: str) -> Dict[str, Any]:
        """Retrieve user privileges for a system user"""
        url = (
            f"{self.base_url}/systemusers({systemuser_id})"
            "/Microsoft.Dynamics.CRM.RetrieveUserPrivileges"
        )
        response = self.session.get(url, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_record_access_info(
        self, entity_schema_name: str, entity_id: str, systemuser_id: str
    ) -> Dict[str, Any]:
        """Retrieve principal access info for a record"""
        url = (
            f"{self.base_url}/systemusers({systemuser_id})"
            "/Microsoft.Dynamics.CRM.RetrievePrincipalAccessInfo"
            f"(ObjectId={entity_id},EntityName='{entity_schema_name}')"
        )
        response = self.session.get(url, timeout=30)
        response.raise_for_status()
        return response.json()

    def get_entity_set(self, entity_set_name: str) -> Dict[str, Any]:
        """Get all records from an entity set with pagination"""
        url = f"{self.base_url}/{entity_set_name}?$count=true"

        entity_set = {
            "@odata.context": "",
            "@odata.count": -1,
            "@odata.nextLink": url,
            "value": [],
        }

        page_num = 0
        while entity_set.get("@odata.nextLink"):
            next_url = entity_set["@odata.nextLink"]
            logging.debug(f"Dumping page {page_num} of entityset {entity_set_name}")

            response = self.session.get(
                next_url,
                headers={"Prefer": f"odata.maxpagesize={self.page_size}"},
                timeout=30,
            )
            response.raise_for_status()

            page = response.json()
            logging.debug(
                f"Dumped page {page_num} of entityset {entity_set_name} "
                f"[page_size={len(page['value'])}]"
            )

            entity_set["value"].extend(page["value"])
            entity_set["@odata.count"] = len(entity_set["value"])
            entity_set["@odata.nextLink"] = page.get("@odata.nextLink")
            entity_set["@odata.context"] = page.get("@odata.context", "")

            page_num += 1

        return entity_set

    def download_file(self, url: str, output_path: Path) -> None:
        """Download a file from a URL to the specified path"""
        response = self.session.get(url, stream=True, timeout=30)
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)


class DynDump:
    """Microsoft Dynamics CRM dumper"""

    def __init__(
        self,
        client: DynamicsClient,
        output_dir: str = "dump",
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
        threads: int = 4,
    ):
        self.client = client
        self.output_dir = Path(output_dir)
        self.include = include or []
        self.exclude = exclude or ["webresources", "audits"]
        self.threads = threads
        self.systemuser_id = None
        self.entity_map = {}  # Add this: LogicalName -> EntitySetName mapping

        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def authenticate(self):
        """Authenticate and get current user info"""
        # Get current user via WhoAmI
        whoami = self.client.whoami()
        user_id = whoami["UserId"]

        # Get systemuser details
        systemuser = self.client.get_entity("systemusers", user_id)
        self.systemuser_id = systemuser["systemuserid"]

        logging.info(
            f"systemuser [windowsliveid={systemuser.get('windowsliveid')}, "
            f"systemuserid={systemuser['systemuserid']}, "
            f"title={systemuser.get('title')}]"
        )

        # Get and display user privileges (only if not using --include)
        if not self.include:
            try:
                userprivs = self.client.get_systemuser_privileges(self.systemuser_id)
                for privilege in userprivs.get("RolePrivileges", []):
                    logging.info(
                        f"roleprivilege [name={privilege['PrivilegeName']}, "
                        f"depth={privilege['Depth']}, "
                        f"privilegeid={privilege['PrivilegeId']}]"
                    )
            except Exception as e:
                logging.warning(f"Failed to retrieve user privileges: {e}")

    def get_entity_definitions(self) -> List[Dict[str, Any]]:
        """Get all entity definitions"""
        definitions_set = self.client.get_entity_set("EntityDefinitions")
        return definitions_set["value"]

    def get_unique_filename(self, directory: Path, objecttypecode: str, original_filename: str) -> str:
        """
        Generate a unique filename with objecttypecode prefix and (num) suffix if needed.
        Preserves file extension.
        """
        # Split filename and extension
        name_parts = original_filename.rsplit('.', 1)
        if len(name_parts) == 2:
            base_name, extension = name_parts
            extension = f".{extension}"
        else:
            base_name = original_filename
            extension = ""
        
        # Construct prefixed filename
        prefixed_name = f"{objecttypecode}_{base_name}{extension}"
        
        # Check for conflicts and add (num) if needed
        if not (directory / prefixed_name).exists():
            return prefixed_name
        
        counter = 1
        while True:
            new_name = f"{objecttypecode}_{base_name}({counter}){extension}"
            if not (directory / new_name).exists():
                return new_name
            counter += 1

    def handle_fileattachment(self, record: Dict[str, Any], files_dir: Path) -> None:
        """Handle fileattachment records by downloading the actual file"""
        try:
            # Extract required fields
            objecttypecode = record.get('objecttypecode')
            objectid_value = record.get('_objectid_value')
            regardingfieldname = record.get('regardingfieldname')
            filename = record.get('filename')
            
            # Validate required fields
            if not all([objecttypecode, objectid_value, regardingfieldname, filename]):
                logging.warning(
                    f"Missing required fields in fileattachment: {record.get('fileattachmentid')}"
                )
                return
            
            # Map objecttypecode (LogicalName) to EntitySetName
            entity_set_name = self.entity_map.get(objecttypecode)
            if not entity_set_name:
                logging.warning(
                    f"Unknown objecttypecode '{objecttypecode}' for file {filename}"
                )
                return
            
            # Construct the download URL using the correct EntitySetName
            download_url = (
                f"{self.client.target}{API_ENDPOINT}{self.client.api_version}/"
                f"{entity_set_name}({objectid_value})/{regardingfieldname}/$value"
            )
            
            # Generate deduplicated filename
            safe_filename = self.get_unique_filename(files_dir, objecttypecode, filename)
            output_path = files_dir / safe_filename
            
            # Download the file
            logging.debug(f"Downloading: {filename} -> {safe_filename}")
            self.client.download_file(download_url, output_path)
            
            logging.info(f"Downloaded file: {safe_filename}")
            
        except requests.exceptions.RequestException as e:
            logging.warning(f"Error downloading {filename}: {e}")
        except Exception as e:
            logging.warning(f"Unexpected error processing {filename}: {e}")

    def dump_entity_set(self, definition: Dict[str, Any]) -> None:
        """Dump a single entity set to file"""
        entity_set_name = definition["EntitySetName"]

        try:
            # Get all records for this entity set
            entity_set = self.client.get_entity_set(entity_set_name)

            logging.info(
                f"dumped entityset {entity_set_name} [count={len(entity_set['value'])}]"
            )

            # Special handling for fileattachments
            if entity_set_name == "fileattachments":
                files_dir = self.output_dir / "files"
                files_dir.mkdir(parents=True, exist_ok=True)
                
                logging.info(f"Processing {len(entity_set['value'])} file attachments...")
                for record in entity_set["value"]:
                    self.handle_fileattachment(record, files_dir)

            # Try to get access info for the first record
            if entity_set["value"] and self.systemuser_id:
                try:
                    record = entity_set["value"][0]
                    primary_id_attr = definition["PrimaryIdAttribute"]
                    record_id = record.get(primary_id_attr)

                    if record_id:
                        access_info = self.client.get_record_access_info(
                            definition["LogicalName"],
                            record_id,
                            self.systemuser_id,
                        )

                        # Parse inner access info
                        inner_access = json.loads(access_info["AccessInfo"])
                        logging.info(
                            f"recordprivilege {entity_set_name} "
                            f"[{inner_access.get('GrantedAccessRights', 'Unknown')}]"
                        )
                except Exception as e:
                    logging.debug(
                        f"Failed to get access info for {entity_set_name}: {e}"
                    )

            # Save to file
            output_file = self.output_dir / f"{entity_set_name}.json"
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(entity_set, f, indent=2, ensure_ascii=False)

        except Exception as e:
            logging.warning(f"entityset failed {entity_set_name} with {e}")

    def run(self):
        """Run the dump process"""
        # Authenticate and get user info
        self.authenticate()

        # Get entity definitions
        definitions = self.get_entity_definitions()
        
        # Build mapping from LogicalName to EntitySetName
        self.entity_map = {
            d["LogicalName"]: d["EntitySetName"] 
            for d in definitions
        }
        logging.debug(f"Built entity map with {len(self.entity_map)} entries")

        # Filter definitions based on include/exclude
        filtered_definitions = [
            d
            for d in definitions
            if (not self.include or d["EntitySetName"] in self.include)
            and d["EntitySetName"] not in self.exclude
        ]

        logging.info(f"Dumping {len(filtered_definitions)} entity sets")

        # Dump entity sets in parallel
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.dump_entity_set, definition): definition
                for definition in filtered_definitions
            }

            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logging.error(f"Exception in thread: {e}")


def parse_http_headers(header_list: List[str]) -> Dict[str, str]:
    """Parse list of header strings into dictionary"""
    headers = {}

    for header_str in header_list:
        if ":" not in header_str:
            logging.error(f"Invalid header format (missing colon): {header_str[:32]}")
            sys.exit(1)

        name, value = header_str.split(":", 1)
        headers[name.strip()] = value.strip()

    return headers


def main():
    parser = argparse.ArgumentParser(
        description="Dump Microsoft Dynamics CRM",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "target", help='Dynamics instance e.g. "https://example.crm6.dynamics.com"'
    )

    parser.add_argument(
        "-H",
        "--headers",
        action="append",
        default=[],
        help='HTTP headers e.g. "Cookie: CrmOwinAuth ...;"',
    )

    parser.add_argument(
        "-p",
        "--proxy",
        help='HTTP/SOCKS proxy e.g. "http://localhost:8080"',
    )

    parser.add_argument(
        "-a",
        "--api",
        default="v9.2",
        help="API version (default: v9.2)",
    )

    parser.add_argument(
        "-i",
        "--include",
        action="append",
        default=[],
        help="Include specified entitysets only",
    )

    parser.add_argument(
        "-e",
        "--exclude",
        action="append",
        default=["webresources", "audits"],
        help="Exclude specified entitysets (default: webresources audits)",
    )

    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Disable TLS checks",
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default="dump",
        help="Output directory (default: dump)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="count",
        default=0,
        help="Decrease verbosity",
    )

    parser.add_argument(
        "--page-size",
        type=int,
        default=1000,
        help="Page size preference (default: 1000)",
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=4,
        help="Threads, one thread per entity set (default: 4)",
    )

    args = parser.parse_args()

    # Configure logging
    verbosity = args.verbose - args.quiet
    log_levels = {
        -2: logging.CRITICAL,
        -1: logging.ERROR,
        0: logging.WARNING,
        1: logging.INFO,
        2: logging.DEBUG,
    }
    log_level = log_levels.get(verbosity, logging.DEBUG if verbosity > 2 else logging.CRITICAL)

    logging.basicConfig(
        level=log_level,
        format="%(message)s",
        stream=sys.stdout,
    )

    # Parse headers
    headers = parse_http_headers(args.headers) if args.headers else None

    # Build client
    try:
        client = DynamicsClient(
            target=args.target,
            headers=headers,
            proxy=args.proxy,
            api_version=args.api,
            insecure=args.insecure,
            page_size=args.page_size,
        )
    except Exception as e:
        logging.error("Failed to build HTTP client")
        logging.error(str(e))
        sys.exit(1)

    # Create dumper and run
    dumper = DynDump(
        client=client,
        output_dir=args.output_dir,
        include=args.include if args.include else None,
        exclude=args.exclude if not args.include else [],
        threads=args.threads,
    )

    try:
        dumper.run()
    except KeyboardInterrupt:
        logging.info("\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
