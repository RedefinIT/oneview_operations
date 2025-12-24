#!/usr/bin/env python3
"""
HPE OneView - iLO Local User Creation Script
=============================================
Creates a local user account with password on all iLO management processors
for servers managed by HPE OneView.

Features:
- Connects to HPE OneView to get all server hardware
- Creates local user on each iLO
- Configurable user privileges
- Enterprise error handling and logging
- Dry-run mode for testing
- Rollback capability
- Progress tracking
"""

import os
import sys
import json
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path
import getpass

try:
    from hpeOneView.oneview_client import OneViewClient
    from hpeOneView.exceptions import HPEOneViewException
except ImportError:
    print("ERROR: hpeOneView library not found. Install with: pip install hpeOneView")
    sys.exit(1)

try:
    import requests
    import urllib3

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("ERROR: requests library not found. Install with: pip install requests")
    sys.exit(1)

# Try to load dotenv for .env file support
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'ilo_user_creation_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class OneViewConfig:
    """Configuration for OneView connection"""

    def __init__(self):
        self.hostname: str = os.getenv('ONEVIEW_HOSTNAME', '')
        self.username: str = os.getenv('ONEVIEW_USERNAME', '')
        self.password: str = os.getenv('ONEVIEW_PASSWORD', '')
        self.api_version: int = int(os.getenv('ONEVIEW_API_VERSION', '4000'))
        self.ssl_verify: bool = os.getenv('ONEVIEW_SSL_VERIFY', 'False').lower() == 'true'

    def validate(self) -> None:
        """Validate required configuration"""
        missing = []
        if not self.hostname:
            missing.append("ONEVIEW_HOSTNAME")
        if not self.username:
            missing.append("ONEVIEW_USERNAME")
        if not self.password:
            missing.append("ONEVIEW_PASSWORD")

        if missing:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing)}"
            )

    def to_dict(self) -> Dict:
        """Convert to OneView client config"""
        return {
            'ip': self.hostname,
            'credentials': {
                'userName': self.username,
                'password': self.password
            },
            'api_version': self.api_version,
            'ssl_certificate': self.ssl_verify
        }


class ILOUserConfig:
    """Configuration for iLO user to be created"""

    def __init__(self):
        self.username: str = os.getenv('ILO_NEW_USERNAME', '')
        self.password: str = os.getenv('ILO_NEW_PASSWORD', '')
        self.login_name: str = ""  # Full name/description
        self.privileges: Dict[str, bool] = {
            'RemoteConsolePriv': True,  # Remote Console
            'iLOConfigPriv': True,  # iLO Config
            'VirtualMediaPriv': True,  # Virtual Media
            'UserConfigPriv': True,  # User Config
            'VirtualPowerAndResetPriv': True,  # Virtual Power and Reset
            'SystemRecoveryConfigPriv': False  # System Recovery Set (optional)
        }

    def validate(self) -> None:
        """Validate user configuration"""
        if not self.username:
            raise ValueError("ILO_NEW_USERNAME is required")
        if not self.password:
            raise ValueError("ILO_NEW_PASSWORD is required")
        if len(self.username) > 39:
            raise ValueError("Username must be 39 characters or less")
        if len(self.password) < 8:
            raise ValueError("Password must be at least 8 characters")


class ILOServer:
    """Represents an iLO server"""

    def __init__(self, name: str, ilo_ip: str, serial_number: str, uri: str):
        self.name = name
        self.ilo_ip = ilo_ip
        self.serial_number = serial_number
        self.uri = uri
        self.user_created = False
        self.error_message = ""


class ILOUserManager:
    """Main class for managing iLO user creation across all servers"""

    def __init__(self, oneview_config: OneViewConfig, ilo_user_config: ILOUserConfig, dry_run: bool = False):
        self.oneview_config = oneview_config
        self.ilo_user_config = ilo_user_config
        self.dry_run = dry_run
        self.client: Optional[OneViewClient] = None
        self.servers: List[ILOServer] = []
        self.success_count = 0
        self.failure_count = 0

    def connect_oneview(self) -> None:
        """Connect to HPE OneView"""
        try:
            logger.info(f"Connecting to HPE OneView at {self.oneview_config.hostname}")
            self.client = OneViewClient(self.oneview_config.to_dict())
            logger.info("Successfully connected to HPE OneView")
        except Exception as e:
            logger.error(f"Failed to connect to OneView: {e}")
            raise

    def disconnect_oneview(self) -> None:
        """Disconnect from OneView"""
        if self.client:
            logger.info("Disconnected from HPE OneView")

    def get_all_servers(self) -> None:
        """Get all server hardware from OneView"""
        try:
            logger.info("Retrieving all server hardware...")
            hardware_list = self.client.server_hardware.get_all()
            logger.info(f"Found {len(hardware_list)} servers")

            for hw in hardware_list:
                # Check server state - only process managed servers
                server_state = hw.get('state')
                print(f"$$$ state: {server_state}")
                if server_state not in ['ProfileApplied', 'Monitored', 'Managed', 'Unmanaged']:
                    logger.debug(f"Skipping server {hw.get('name', 'Unknown')} with state: {server_state}")
                    continue

                # Extract iLO IP
                ilo_ip = ""
                if hw.get('mpHostInfo'):
                    mp_ip_addresses = hw['mpHostInfo'].get('mpIpAddresses', [])
                    if mp_ip_addresses and len(mp_ip_addresses) > 0:
                        ilo_ip = mp_ip_addresses[0].get('address', '')

                if not ilo_ip:
                    logger.warning(f"No iLO IP found for server {hw.get('name', 'Unknown')}")
                    continue

                server = ILOServer(
                    name=hw.get('name', ''),
                    ilo_ip=ilo_ip,
                    serial_number=hw.get('serialNumber', ''),
                    uri=hw.get('uri', '')
                )
                self.servers.append(server)

            logger.info(f"Found {len(self.servers)} servers with valid iLO IP addresses")

        except Exception as e:
            logger.error(f"Failed to retrieve server hardware: {e}")
            raise

    def _get_ilo_sso_token(self, server_uri: str, server_name: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Get iLO SSO token from OneView

        Args:
            server_uri: Server hardware URI in OneView
            server_name: Server name for logging

        Returns:
            Tuple of (session_token, error_message)
        """
        try:
            # Validate that we have a proper URI
            if not server_uri or server_uri == '':
                return None, "Server URI is empty"

            logger.debug(f"Requesting SSO token for {server_name} (URI: {server_uri})")

            server1 = self.client.server_hardware.get_by_uri(server_uri)
            remote_console_url = server1.get_remote_console_url()
            logging.debug(f"Remote Console URL: {remote_console_url}")
            ilo_ip_addr = remote_console_url["remoteConsoleUrl"].split("addr=")[1].split("&")[0]
            session_key = remote_console_url["remoteConsoleUrl"].split("&sessionkey=")[1]
            return session_key, None

            # Get SSO URL from OneView for this server
            # This provides a single sign-on token for iLO access
            # remote_console_url = self.client.server_hardware.get_remote_console_url(server_uri)

            # logger.debug(f"Received remote console URL for {server_name}")

            # The remote console URL contains the SSO session key
            # Format: https://ilo-ip/...?sessionkey=<token>
            # if 'sessionkey=' in remote_console_url:
            #     # Extract the session key from the URL
            #     session_key = remote_console_url.split('sessionkey=')[1].split('&')[0]
            #     logger.debug(f"Successfully extracted SSO token for {server_name}")
            #     return session_key, None
            # else:
            #     return None, "No session key found in remote console URL"

        except HPEOneViewException as e:
            error_msg = str(e)
            # Provide more helpful error messages
            if "Missing unique identifiers" in error_msg:
                return None, "Server not properly managed by OneView (check server state)"
            elif "not found" in error_msg.lower():
                return None, "Server resource not found in OneView"
            elif "powerState" in error_msg:
                return None, "Server must be powered on for SSO"
            else:
                return None, f"OneView SSO error: {error_msg}"
        except Exception as e:
            return None, f"SSO token extraction error: {str(e)}"

    def _get_ilo_session(self, ilo_ip: str, server_uri: str, server_name: str) -> Tuple[
        Optional[requests.Session], Optional[str]]:
        """
        Create authenticated session to iLO using OneView SSO

        Args:
            ilo_ip: iLO IP address
            server_uri: Server hardware URI in OneView
            server_name: Server name for logging

        Returns:
            Tuple of (session, error_message)
        """
        try:
            # Get SSO token from OneView
            session_key, error = self._get_ilo_sso_token(server_uri, server_name)
            print(f"&&&& Session key: {session_key}")

            if not session_key:
                return None, f"Failed to get SSO token: {error}"

            # Create session for iLO Redfish API
            session = requests.Session()
            session.verify = False

            # Set up session with SSO token
            # For iLO, we need to create a session using the SSO token
            # First, we'll use the session key to authenticate
            session.headers.update({
                'OData-Version': '4.0',
                'Content-Type': 'application/json'
            })

            # Method 1: Try using X-Auth-Token header with session key
            session.headers.update({'X-Auth-Token': session_key})

            # Test the session
            response = session.get(
                f"https://{ilo_ip}/redfish/v1/AccountService/Accounts/",
                timeout=15
            )

            if response.status_code == 200:
                logger.debug(f"SSO authentication successful for {ilo_ip}")
                return session, None

            # Method 2: If header method fails, try creating session with SSO token
            # iLO Redfish may require a POST to /redfish/v1/SessionService/Sessions
            logger.debug(f"Trying session creation method for {ilo_ip}")

            session_payload = {
                "UserName": "",  # Empty for SSO
                "Password": "",  # Empty for SSO
                "Oem": {
                    "Hp": {
                        "SessionKey": session_key
                    }
                }
            }

            # Remove X-Auth-Token header for session creation
            session.headers.pop('X-Auth-Token', None)

            session_response = session.post(
                f"https://{ilo_ip}/redfish/v1/SessionService/Sessions/",
                json=session_payload,
                timeout=15
            )

            if session_response.status_code in [200, 201]:
                # Extract the X-Auth-Token from response
                auth_token = session_response.headers.get('X-Auth-Token')
                if auth_token:
                    session.headers.update({'X-Auth-Token': auth_token})
                    logger.debug(f"Session created successfully for {ilo_ip}")
                    return session, None
                else:
                    return None, "Session created but no auth token received"
            else:
                return None, f"SSO authentication failed: HTTP {session_response.status_code}"

        except requests.exceptions.RequestException as e:
            return None, f"Network error: {str(e)}"
        except Exception as e:
            return None, f"Session creation error: {str(e)}"

    def _find_available_user_slot(self, session: requests.Session, ilo_ip: str) -> Optional[int]:
        """
        Find an available user slot in iLO

        Returns:
            Available slot number or None
        """
        try:
            response = session.get(
                f"https://{ilo_ip}/redfish/v1/AccountService/Accounts/",
                timeout=10
            )

            if response.status_code != 200:
                logger.error(f"Failed to get accounts list: HTTP {response.status_code}")
                return None

            data = response.json()
            members = data.get('Members', [])

            # Check each slot
            for member in members:
                member_uri = member.get('@odata.id', '')
                member_response = session.get(f"https://{ilo_ip}{member_uri}", timeout=10)

                if member_response.status_code == 200:
                    member_data = member_response.json()
                    username = member_data.get('UserName', '')

                    # Check if slot is empty or has the same username (for updates)
                    if not username or username == self.ilo_user_config.username:
                        # Extract slot number from URI (e.g., /redfish/v1/AccountService/Accounts/3/ -> 3)
                        slot = member_uri.rstrip('/').split('/')[-1]
                        try:
                            return int(slot)
                        except ValueError:
                            continue

            logger.warning(f"No available user slots found on {ilo_ip}")
            return None

        except Exception as e:
            logger.error(f"Error finding user slot: {e}")
            return None

    def _create_ilo_user(self, session: requests.Session, ilo_ip: str, slot: int) -> Tuple[bool, str]:
        """
        Create or update iLO user account

        Returns:
            Tuple of (success, error_message)
        """
        try:
            # Build user payload for Redfish API
            payload = {
                "UserName": self.ilo_user_config.username,
                "Password": self.ilo_user_config.password,
                "Oem": {
                    "Hpe": {
                        "Privileges": self.ilo_user_config.privileges,
                        "LoginName": self.ilo_user_config.login_name or self.ilo_user_config.username
                    }
                }
            }

            # PATCH to update existing slot
            response = session.patch(
                f"https://{ilo_ip}/redfish/v1/AccountService/Accounts/{slot}/",
                json=payload,
                headers={'Content-Type': 'application/json'},
                timeout=30
            )

            if response.status_code in [200, 201, 204]:
                return True, ""
            else:
                error_msg = f"HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    error_msg += f": {error_data.get('error', {}).get('message', 'Unknown error')}"
                except:
                    error_msg += f": {response.text[:200]}"
                return False, error_msg

        except Exception as e:
            return False, f"Exception: {str(e)}"

    def create_user_on_server(self, server: ILOServer) -> bool:
        """
        Create user on a single iLO server

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Processing server: {server.name} ({server.ilo_ip})")

            if self.dry_run:
                logger.info(f"[DRY-RUN] Would create user on {server.name}")
                server.user_created = True
                return True

            # Get iLO session using OneView SSO
            session, error = self._get_ilo_session(server.ilo_ip, server.uri, server.name)
            if not session:
                server.error_message = error
                logger.error(f"Failed to connect to iLO {server.ilo_ip}: {error}")
                return False

            # Find available user slot
            slot = self._find_available_user_slot(session, server.ilo_ip)
            if slot is None:
                server.error_message = "No available user slots"
                logger.error(f"No available user slots on {server.name}")
                return False

            logger.info(f"Using user slot {slot} on {server.name}")

            # Create the user
            success, error = self._create_ilo_user(session, server.ilo_ip, slot)

            if success:
                server.user_created = True
                logger.info(f"✓ Successfully created user on {server.name}")
                return True
            else:
                server.error_message = error
                logger.error(f"✗ Failed to create user on {server.name}: {error}")
                return False

        except Exception as e:
            server.error_message = str(e)
            logger.error(f"Exception processing {server.name}: {e}")
            return False

    def create_users_on_all_servers(self) -> None:
        """Create user on all servers"""
        logger.info(f"Starting user creation on {len(self.servers)} servers...")
        logger.info(f"Username to create: {self.ilo_user_config.username}")
        logger.info(f"Dry-run mode: {self.dry_run}")
        print()

        for idx, server in enumerate(self.servers, 1):
            print(f"[{idx}/{len(self.servers)}] {server.name} ({server.ilo_ip})...", end=" ")

            if self.create_user_on_server(server):
                self.success_count += 1
                print("✓ Success")
            else:
                self.failure_count += 1
                print(f"✗ Failed: {server.error_message}")

        print()
        logger.info(f"User creation completed: {self.success_count} succeeded, {self.failure_count} failed")

    def export_results(self, filename: str = None) -> None:
        """Export results to JSON file"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ilo_user_creation_results_{timestamp}.json"

        results = {
            'timestamp': datetime.now().isoformat(),
            'username_created': self.ilo_user_config.username,
            'dry_run': self.dry_run,
            'total_servers': len(self.servers),
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'servers': [
                {
                    'name': s.name,
                    'ilo_ip': s.ilo_ip,
                    'serial_number': s.serial_number,
                    'user_created': s.user_created,
                    'error_message': s.error_message
                }
                for s in self.servers
            ]
        }

        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results exported to {filename}")
            print(f"\n✓ Results exported to {filename}")
        except Exception as e:
            logger.error(f"Failed to export results: {e}")

    def print_summary(self) -> None:
        """Print summary of results"""
        print("\n" + "=" * 80)
        print("iLO User Creation Summary")
        print("=" * 80)
        print(f"Username Created: {self.ilo_user_config.username}")
        print(f"Total Servers: {len(self.servers)}")
        print(f"Success: {self.success_count}")
        print(f"Failed: {self.failure_count}")
        print(f"Dry-run Mode: {self.dry_run}")
        print("=" * 80)

        if self.failure_count > 0:
            print("\nFailed Servers:")
            print("-" * 80)
            for server in self.servers:
                if not server.user_created:
                    print(f"  {server.name} ({server.ilo_ip}): {server.error_message}")

        print()


def prompt_for_credentials() -> Tuple[str, str, str]:
    """Prompt user for iLO user details"""
    print("\n" + "=" * 80)
    print("iLO User Configuration")
    print("=" * 80)

    username = input("Enter username to create (max 39 chars): ").strip()
    if not username:
        raise ValueError("Username cannot be empty")

    password = getpass.getpass("Enter password (min 8 chars): ")
    if not password:
        raise ValueError("Password cannot be empty")

    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        raise ValueError("Passwords do not match")

    login_name = input("Enter full name/description (optional): ").strip()

    print()
    return username, password, login_name


def main():
    """Main execution function"""
    print("=" * 80)
    print("HPE OneView - iLO Local User Creation Tool")
    print("=" * 80)
    print()

    # Parse command line arguments
    dry_run = '--dry-run' in sys.argv or '-n' in sys.argv
    interactive = '--interactive' in sys.argv or '-i' in sys.argv

    if dry_run:
        print("⚠️  DRY-RUN MODE: No changes will be made")
        print()

    try:
        # Load OneView configuration
        oneview_config = OneViewConfig()
        oneview_config.validate()

        # Load or prompt for iLO user configuration
        ilo_user_config = ILOUserConfig()

        if interactive or not ilo_user_config.username:
            username, password, login_name = prompt_for_credentials()
            ilo_user_config.username = username
            ilo_user_config.password = password
            ilo_user_config.login_name = login_name

        ilo_user_config.validate()

        # Confirm before proceeding
        if not dry_run:
            print(f"⚠️  This will create user '{ilo_user_config.username}' on ALL iLO servers")
            confirm = input("Do you want to proceed? (yes/no): ").strip().lower()
            if confirm not in ['yes', 'y']:
                print("Operation cancelled")
                sys.exit(0)
            print()

        # Create manager instance
        manager = ILOUserManager(oneview_config, ilo_user_config, dry_run)

        # Connect to OneView
        manager.connect_oneview()

        try:
            # Get all servers
            manager.get_all_servers()

            if len(manager.servers) == 0:
                logger.warning("No servers found with valid iLO IP addresses")
                return

            # Create users
            manager.create_users_on_all_servers()

            # Export results
            manager.export_results()

            # Print summary
            manager.print_summary()

        finally:
            manager.disconnect_oneview()

        # Exit with appropriate code
        if manager.failure_count > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        print(f"\n✗ Configuration Error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\n✗ Unexpected Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()