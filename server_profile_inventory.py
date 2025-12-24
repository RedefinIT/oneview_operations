#!/usr/bin/env python3
"""
HPE OneView Server Profile Data Extraction Script (Enhanced)
=============================================================
Enhanced version with .env file support and improved error handling
"""

import os
import sys
import json
import csv
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path

# Try to load dotenv for .env file support
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass  # dotenv is optional

try:
    from hpeOneView.oneview_client import OneViewClient
    from hpeOneView.resources.resource import Resource, ResourceHelper
    from hpeOneView.exceptions import HPEOneViewException
except ImportError:
    print("ERROR: hpeOneView library not found.")
    print("Install with: pip install hpeOneView")
    print("Or install all dependencies: pip install -r requirements.txt")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(f'oneview_extraction_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class OneViewConfig:
    """Configuration management for OneView connection"""

    def __init__(self):
        self.hostname: str = os.getenv('ONEVIEW_HOSTNAME', '')
        self.username: str = os.getenv('ONEVIEW_USERNAME', '')
        self.password: str = os.getenv('ONEVIEW_PASSWORD', '')
        self.api_version: int = int(os.getenv('ONEVIEW_API_VERSION', '4000'))
        self.ssl_verify: bool = os.getenv('ONEVIEW_SSL_VERIFY', 'False').lower() == 'true'

    def validate(self) -> None:
        """Validate required configuration parameters"""
        missing = []
        if not self.hostname:
            missing.append("ONEVIEW_HOSTNAME")
        if not self.username:
            missing.append("ONEVIEW_USERNAME")
        if not self.password:
            missing.append("ONEVIEW_PASSWORD")

        if missing:
            raise ValueError(
                f"Missing required environment variables: {', '.join(missing)}\n"
                f"Please set them in your environment or create a .env file"
            )

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to OneView client dictionary"""
        return {
            'ip': self.hostname,
            'credentials': {
                'userName': self.username,
                'password': self.password
            },
            'api_version': self.api_version,
            'ssl_certificate': self.ssl_verify
        }


class ServerProfileData:
    """Data class for server profile information"""

    def __init__(self):
        self.profile_name: str = ""
        self.server_hardware_name: str = ""
        self.ilo_ip: str = ""
        self.serial_number: str = ""
        self.mac_addresses: List[Dict[str, str]] = []
        self.profile_uri: str = ""
        self.server_hardware_uri: str = ""
        self.power_state: str = ""
        self.profile_state: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for export"""
        return {
            'profile_name': self.profile_name,
            'server_hardware_name': self.server_hardware_name,
            'ilo_ip': self.ilo_ip,
            'serial_number': self.serial_number,
            'power_state': self.power_state,
            'profile_state': self.profile_state,
            'mac_addresses': self.mac_addresses,
        }

    def to_flat_dict(self) -> Dict[str, str]:
        """Convert to flat dictionary for CSV export"""
        mac_str = "; ".join([
            f"{conn['network_name'] or conn['connection_name']}={conn['mac_address']}"
            for conn in self.mac_addresses if conn['mac_address']
        ])
        return {
            'Profile Name': self.profile_name,
            'Server Hardware': self.server_hardware_name,
            'iLO IP Address': self.ilo_ip,
            'Serial Number': self.serial_number,
            'Power State': self.power_state,
            'Profile State': self.profile_state,
            'MAC Addresses': mac_str,
        }


class OneViewServerProfileExtractor:
    """Main class for extracting server profile data from HPE OneView"""

    def __init__(self, config: OneViewConfig):
        self.config = config
        self.client: Optional[OneViewClient] = None
        self.profiles_data: List[ServerProfileData] = []
        self.network = []
        self.network_sets = []

    def connect(self) -> None:
        """Establish connection to OneView"""
        try:
            logger.info(f"Connecting to HPE OneView at {self.config.hostname}")
            logger.info(f"API Version: {self.config.api_version}")
            self.client = OneViewClient(self.config.to_dict())
            self.eth_networks = self.client.ethernet_networks.get_all()
            self.fc_networks = self.client.fc_networks.get_all()
            # self.fcoe_networks = self.client.fcoe_networks.get_all()
            self.network_sets = self.client.network_sets.get_all()
            logger.info("Successfully connected to HPE OneView")
        except HPEOneViewException as e:
            logger.error(f"Failed to connect to OneView: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during connection: {e}")
            raise

    def disconnect(self) -> None:
        """Close OneView connection"""
        if self.client:
            try:
                logger.info("Disconnected from HPE OneView")
            except Exception as e:
                logger.warning(f"Error during disconnect: {e}")

    def _get_server_hardware_details(self, hardware_uri: str) -> Dict[str, str]:
        """
        Get server hardware details including iLO IP, serial number, and power state

        Args:
            hardware_uri: URI of the server hardware

        Returns:
            Dictionary with server hardware details
        """
        try:
            hardware = self.client.server_hardware.get_by_uri(hardware_uri)

            server_name = hardware.data['name']
            serial_number = hardware.data['serialNumber']
            power_state = hardware.data['powerState']
            # Extract iLO IP (mpHostInfo contains management processor info)
            ilo_ip = hardware.data['mpHostInfo']['mpIpAddresses'][0]['address']

            return {
                'ilo_ip': ilo_ip,
                'serial_number': serial_number,
                'server_name': server_name,
                'power_state': power_state
            }
        except HPEOneViewException as e:
            logger.error(f"Failed to get hardware details for {hardware_uri}: {e}")
            return {
                'ilo_ip': '',
                'serial_number': '',
                'server_name': '',
                'power_state': 'Unknown'
            }
        except Exception as e:
            logger.error(f"Unexpected error getting hardware details: {e}")
            return {
                'ilo_ip': '',
                'serial_number': '',
                'server_name': '',
                'power_state': 'Unknown'
            }

    def _extract_mac_addresses(self, connections: List[Dict]) -> List[Dict[str, str]]:
        """
        Extract MAC addresses from profile connections

        Args:
            connections: List of connection dictionaries from profile

        Returns:
            List of dictionaries with connection details
        """
        mac_list = []

        for conn in connections:
            if not conn:
                continue


            print(f"conn: {conn}")

            mac_info = {
                'connection_id': str(conn.get('id', '')),
                'connection_name': conn.get('name', ''),
                'network_name': '',
                'mac_address': conn.get('mac', ''),
                'mac_type': conn.get('macType', ''),
                'port_id': conn.get('portId', ''),
                'function_type': conn.get('functionType', '')
            }

            # Get network name if available
            network_uri = conn.get('networkUri', '')
            if network_uri:
                try:
                    if 'ethernet-networks' in network_uri:
                        network = self.client.ethernet_networks.get_by_uri(network_uri)
                        mac_info['network_name'] = network.get('name', '')
                    elif 'fc-networks' in network_uri:
                        network = self.client.fc_networks.get_by_uri(network_uri)
                        mac_info['network_name'] = network.get('name', '')
                    elif 'network-sets' in network_uri:
                        # Find the network-set name
                        network_set_name = next((ns['name'] for ns in self.network_sets if ns['uri'] == network_uri), None)
                        mac_info['network_name'] = network_set_name
                except Exception as e:
                    logger.debug(f"Could not retrieve network name for {network_uri}: {e}")

            mac_list.append(mac_info)

        return mac_list

    def extract_all_profiles(self) -> None:
        """Extract all server profiles with their details"""
        try:
            logger.info("Retrieving all server profiles...")
            profiles = self.client.server_profiles.get_all()
            logger.info(f"Found {len(profiles)} server profiles")

            for idx, profile in enumerate(profiles, 1):
                try:
                    logger.info(f"Processing profile {idx}/{len(profiles)}: {profile.get('name', 'Unknown')}")

                    profile_data = ServerProfileData()

                    # Basic profile information
                    profile_data.profile_name = profile.get('name', '')
                    profile_data.profile_uri = profile.get('uri', '')
                    profile_data.profile_state = profile.get('state', 'Unknown')

                    # Server hardware URI
                    hardware_uri = profile.get('serverHardwareUri', '')
                    profile_data.server_hardware_uri = hardware_uri

                    # Get server hardware details
                    if hardware_uri:
                        hw_details = self._get_server_hardware_details(hardware_uri)
                        profile_data.server_hardware_name = hw_details['server_name']
                        profile_data.ilo_ip = hw_details['ilo_ip']
                        profile_data.serial_number = hw_details['serial_number']
                        profile_data.power_state = hw_details['power_state']
                    else:
                        logger.warning(f"Profile '{profile_data.profile_name}' has no assigned server hardware")

                    # Extract MAC addresses from connections
                    connections = profile.get('connectionSettings', {}).get('connections', [])
                    profile_data.mac_addresses = self._extract_mac_addresses(connections)

                    self.profiles_data.append(profile_data)

                except Exception as e:
                    logger.error(f"Error processing profile {profile.get('name', 'Unknown')}: {e}", exc_info=True)
                    continue

            logger.info(f"Successfully extracted data for {len(self.profiles_data)} profiles")

        except HPEOneViewException as e:
            logger.error(f"Failed to retrieve server profiles: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during profile extraction: {e}", exc_info=True)
            raise

    def export_to_json(self, output_file: str = 'server_profiles.json') -> None:
        """
        Export profile data to JSON file

        Args:
            output_file: Path to output JSON file
        """
        try:
            output_path = Path(output_file)
            data = [profile.to_dict() for profile in self.profiles_data]

            with output_path.open('w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Exported JSON data to {output_path.absolute()}")
            print(f"\n✓ JSON export: {output_path.absolute()}")
        except Exception as e:
            logger.error(f"Failed to export JSON: {e}")
            raise

    def export_to_csv(self, output_file: str = 'server_profiles.csv') -> None:
        """
        Export profile data to CSV file

        Args:
            output_file: Path to output CSV file
        """
        try:
            output_path = Path(output_file)

            if not self.profiles_data:
                logger.warning("No data to export")
                return

            with output_path.open('w', newline='') as f:
                fieldnames = [
                    'Profile Name', 'Server Hardware', 'iLO IP Address',
                    'Serial Number', 'Power State', 'Profile State',
                    'MAC Addresses'
                ]
                writer = csv.DictWriter(f, fieldnames=fieldnames)

                writer.writeheader()
                for profile in self.profiles_data:
                    writer.writerow(profile.to_flat_dict())

            logger.info(f"Exported CSV data to {output_path.absolute()}")
            print(f"✓ CSV export: {output_path.absolute()}")
        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")
            raise

    def print_summary(self) -> None:
        """Print summary of extracted data"""
        print("\n" + "=" * 80)
        print("HPE OneView Server Profile Summary")
        print("=" * 80)
        print(f"Total Profiles: {len(self.profiles_data)}")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80 + "\n")

        for profile in self.profiles_data:
            print(f"Profile: {profile.profile_name}")
            print(f"  Server Hardware: {profile.server_hardware_name or 'Not Assigned'}")
            print(f"  iLO IP: {profile.ilo_ip or 'N/A'}")
            print(f"  Serial Number: {profile.serial_number or 'N/A'}")
            print(f"  Power State: {profile.power_state}")
            print(f"  Profile State: {profile.profile_state}")
            if profile.mac_addresses:
                print(f"  Network Connections:")
                for mac in profile.mac_addresses:
                    print(f"Mac: {mac}")
                    network = mac['network_name'] or mac['connection_name'] or 'Unknown'
                    mac_addr = mac['mac_address'] or 'Not Assigned'
                    print(f"    - {network}: {mac_addr} (Port: {mac['port_id']}, Type: {mac['function_type']})")
            else:
                print(f"  Network Connections: None")
            print()


def main():
    """Main execution function"""
    print("=" * 80)
    print("HPE OneView Server Profile Data Extraction Tool")
    print("=" * 80)
    print()

    try:
        # Load configuration
        config = OneViewConfig()
        config.validate()

        print(f"Target: {config.hostname}")
        print(f"API Version: {config.api_version}")
        print(f"SSL Verify: {config.ssl_verify}")
        print()

        # Create extractor instance
        extractor = OneViewServerProfileExtractor(config)

        # Connect to OneView
        extractor.connect()

        try:
            # Extract all profiles
            extractor.extract_all_profiles()

            # Export data
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            json_file = f'server_profiles_{timestamp}.json'
            csv_file = f'server_profiles_{timestamp}.csv'

            extractor.export_to_json(json_file)
            extractor.export_to_csv(csv_file)

            # Print summary
            extractor.print_summary()

            print("=" * 80)
            print("✓ Data extraction completed successfully")
            print("=" * 80)
            logger.info("Data extraction completed successfully")

        finally:
            # Ensure disconnect
            extractor.disconnect()

    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        print(f"\n✗ Configuration Error: {e}")
        print("\nPlease ensure all required environment variables are set.")
        print("You can create a .env file based on .env.example")
        sys.exit(1)
    except HPEOneViewException as e:
        logger.error(f"OneView API error: {e}")
        print(f"\n✗ OneView API Error: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        print(f"\n✗ Unexpected Error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()