# -*- coding: utf-8 -*-

from fortiosapi import FortiOSAPI
from fortiosapi.exceptions import InvalidLicense, NotLogged
from fortigaterepr.devicedata import (
    ForitgateDetectedDevices,
    FortigateActiveIpsecVpns,
    FortigateFirewallPolicy,
    FortigateInterfaceDetails,
    FortigateManagedAps,
    FortigateRouteTable,
    FortigateWlanConnectedClients,
    FortigateWlanRogueAps,
    ForitgateDetectedDevices,
    FortigateArpTable,
    FortigateDhcpClientLeases,
)
import textfsm
import logging
import urllib3
from io import StringIO
from typing import Optional
import pandas as pd

ARP_TEXT_FSM = StringIO(
    """Value ADDRESS (\\d+\\.\\d+\\.\\d+\\.\\d+)
Value AGE (\\d+)
Value MAC (\\S+)
Value INTERFACE (.*)

Start
  ^${ADDRESS}\\s+${AGE}\\s+${MAC}\\s+${INTERFACE} -> Record
"""
)

# create logger:
FORTIGATEREPR_LOGGER = logging.getLogger("fortigaterepr")


class FortigateDevice:
    """
    Class for a Fortigate Device.  Used to more easily store and reference data pulled from FortiOS API calls

    looking at using the 'fortiosapi' python library for the API call functionality.  This class will store
    and parse the results to something hopefully more useful, or perhaps expose more simplified methods
    like get_rt_table() that then leverages the fortios library

    TODO:  Add some simple type hints where makes sense
    TODO:  methods to abstract data gathering activities and parse into more usable / normalized format.
    """

    def __init__(
        self, host, username=None, password=None, apitoken=None, verify=True, debug="on"
    ):
        """
        must specify hostname / IP address of device
        verify set to true as a proper secure default, however expect often to be set to False for practicality

        some parameters such as timeout, cert, url_prefix exposed so they can be passed through to FortiOSAPI library
        if required.

        vdom_login used for login operations if logging into global (Default) or particular vdom as a device
        vdom is used to pass through to FortiOSAPI library for API calls that can take a VDOM parameter.
        """
        # hide the URLLIB3 SSL warnings if verify set to False
        if not verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.host = host
        self.username = username
        self.password = password
        self.apitoken = apitoken
        self.verify = verify
        self.timeout = 120
        self.cert = None
        self.url_prefix = None
        self.vdom_login = "global"
        self.vdom = None
        # devapi stores the context for the FortiOSAPI class for a given device.
        self.devapi = FortiOSAPI()
        # set debug mode -- for now defaults to "on":
        if debug == "on":
            self.devapi.debug(debug)

        self.facts = {}
        self.route_table = None
        self.route_table_size = {}
        self.active_ipsec_vpns = None
        self.detected_devices = None
        self.interfaces = None
        self.arp_table = None
        self.fw_policy_ipv4 = None
        self.fw_policy_ipv6 = None
        self.managed_aps = None
        self.wlan_connected_clients = None
        self.wlan_rogue_aps = None
        self.dhcp_client_leases = None

    def rest_monitor_check_resp(self, resp) -> bool:
        """
        helper method to check Monitor API Call responses

        returns True if response is success, False otherwise
        """
        if resp.get("status") != "success":
            # TODO:  Clean up this error and message handling
            status = resp.get("status", "ERROR NO STATUS MESSAGE")
            http_status = resp.get("http_status", "ERROR NO HTTP STATUS CODE!")
            FORTIGATEREPR_LOGGER.error(
                f"Error retrieving data:  status: {status}.  http_status: {http_status}"
            )
            FORTIGATEREPR_LOGGER.error(f"response was: {resp}")
            return False

        return True

    def rest_check_session(self):
        """
        helper wrapper for the FortiOSAPI.check_session() method
        """
        try:
            self.devapi.check_session()
        except NotLogged:
            if self.apitoken:
                FORTIGATEREPR_LOGGER.info(
                    "Not currently logged in but apitoken set -- attempting rest api login"
                )
                return self.restapilogin()
        except InvalidLicense:
            FORTIGATEREPR_LOGGER.warning("License is invalid - raising exception")
            raise InvalidLicense()

    def clilogin(self, timeout: int = 12):
        """
        MIGHT NOT BE NEEDED AS I THINK IS JUST DIFF AUTH METHOD TO WEB API!
        wrapper method for the fortiosapi login method -- uses similar defaults, exposes other options such as vdom specification
        """
        FORTIGATEREPR_LOGGER.debug(f"UN: {self.username}")
        FORTIGATEREPR_LOGGER.debug(f"PW: {self.password}")
        if not self.username or self.password is None:
            FORTIGATEREPR_LOGGER.error("ERROR:  Username or Password not set!")
            return False
        try:
            r = self.devapi.login(
                host=self.host,
                username=self.username,
                password=self.password,
                verify=self.verify,
                cert=self.cert,
                timeout=timeout,
                vdom=self.vdom_login,
            )
            return r
        except Exception as e:
            FORTIGATEREPR_LOGGER.error(f"UNKNOWN EXCEPTION: {str(e)}")
            return False

    def restapilogin(self, timeout: int = 12):
        """
        wrapper method for the fortiosapi tokenlogin method -- uses similar defaults, exposes other options
        such as vdom specification
        """
        # if API token is specified, then initiate tokenlogin, otherwise for now just print message and pass
        if not self.apitoken:
            FORTIGATEREPR_LOGGER.warning(
                "API Token not set, not performing token login."
            )
            return False
        else:
            try:
                self.devapi.tokenlogin(
                    self.host,
                    self.apitoken,
                    verify=self.verify,
                    cert=self.cert,
                    timeout=timeout,
                    vdom=self.vdom_login,
                )
                FORTIGATEREPR_LOGGER.info("API session creation success.")
                return True
            except TypeError:
                # error handling of fortiosapi library not the best in some cases.  when API token is wrong it seems to encounter TypeError
                # because it can't find the 'version' key in the response, since obviously the expected response was not returned.
                FORTIGATEREPR_LOGGER.warning("Error logging into device with API.")
                return False

    def ssh(self, commands):
        """
        wrapper method for fortiosapi ssh method.  Returns False if an error occurred.
        """
        try:
            r = self.devapi.ssh(commands, self.host, self.username, self.password)
            return r
        except Exception as e:
            FORTIGATEREPR_LOGGER.error(f"UNKNOWN EXCEPTION: {str(e)}")
            return False

    def get_facts(self, exclude_columns=None):
        """
        get device facts

        TODO:  Review what facts return from NAPALM and try to get all of these same things.
        NAPALM get_facts() method returns dictionary of the following:
        * uptime -- no REST API call??
        * vendor -- set to Fortinet
        * model -- no REST API call??
        * hostname -- no REST API call??
        * fqdn -- no REST API call??
        * os_version -- can be retrieved as part of api login
        * serial_number -- can be retrieved as part of api login
        * interface_list -- retrieved via /system/available-interfaces/select -- can populate device interface table at same time
        """
        # TODO: Set each self.facts[VARIABLE]
        # NOTE:  Some facts can get set during the API login

        self.facts["vendor"] = "Fortinet"
        self.facts["model"] = "Fortigate Model TBD"
        self.facts["uptime"] = None
        self.facts["hostname"] = None
        self.facts["fqdn"] = None
        self.facts["os_version"] = None
        self.facts["serial_number"] = None
        # if interface_list has not been populated, set to None.
        if not self.facts.get("interface_list"):
            self.facts["interface_list"] = None

        self.rest_check_session()

        if self.interfaces is None:
            self.get_interfaces()

        self.facts["interface_list"] = self.interfaces["name"].tolist()

        basic_facts = self.devapi.monitor("system/status", "select")
        if not self.rest_monitor_check_resp(basic_facts):
            FORTIGATEREPR_LOGGER.warning("Response encountered error, returning None.")
            return None
        self.facts["serial_number"] = basic_facts.get("serial")
        self.facts[
            "os_version"
        ] = f"{basic_facts.get('version')} build {basic_facts.get('build')}"

        # FORTIGATEREPR_LOGGER.debug(basic_facts)
        # as of now facts are a dict, to normalize to a simple DataFrame...
        # self.facts = pd.DataFrame.from_dict(self.facts, orient='index')
        return self.facts

    def get_arp_table(self, exclude_columns=None):
        """
        gets ARP table from device -- currently only available via SSH command, then parses it using TextFSM
        """
        # get arp table via SSH:
        command = "get system arp"
        arp_table = self.devapi.ssh(command, self.host, self.username, self.password)
        # successful response is a tuple where 0 position is the result, and 1 position is stderr response from paramiko
        # 0 position success is a list of strings, first line is prompt + header of cmd output, next lines are output itself,
        # then usually a blank line, followed by prompt
        # TestFSM is able to parse it properly if we convert it properly
        template = None
        # this needs error handling if file not found??
        template = textfsm.TextFSM(ARP_TEXT_FSM)
        COLUMNS = ["Address", "Age(min)", "MAC Address", "Interface"]

        # either Paramiko or the fortiosapi ssh command escapes the new line characters, so we have to replace them back
        # in order for TextFSM to parse correctly
        arp_table = arp_table[0].replace("\\n", "\n")
        parsed_data = template.ParseText(arp_table)
        data = FortigateArpTable(columns=COLUMNS, data=parsed_data)
        data.clean_data()
        self.arp_table = data
        return self.arp_table

    def get_active_ipsec_vpns(self, exclude_columns=None):
        self.rest_check_session()
        vpn_info = self.devapi.monitor("vpn/ipsec", "select")
        if not self.rest_monitor_check_resp(vpn_info):
            FORTIGATEREPR_LOGGER.error("Response encountered error, returning None.")
            return None

        data = FortigateActiveIpsecVpns(vpn_info.get("results"))
        data.clean_data()
        # data = data.get(exclude_columns=exclude_columns)
        self.active_ipsec_vpns = data
        return self.active_ipsec_vpns

    def get_route_table(self, exclude_columns=None):
        """
        queries API and sets device object's route_table parameter and returns the value
        """
        self.rest_check_session()
        route_table_info = self.devapi.monitor("router/ipv4", "select")
        if not self.rest_monitor_check_resp(route_table_info):
            FORTIGATEREPR_LOGGER.error("Response encountered error, returning None.")
            return None
        data = FortigateRouteTable(route_table_info.get("results"))
        data.clean_data()
        # data = data.get(exclude_columns=exclude_columns)
        self.route_table = data

        # get route table size info and store in Object (not returned):
        route_table_size = self.devapi.monitor("router/statistics", "select")
        if not self.rest_monitor_check_resp(route_table_size):
            FORTIGATEREPR_LOGGER.error("Response encountered error, returning None.")
            return None
        data = route_table_size.get("results")
        self.route_table_size["total_routes"] = data.get("total_lines")
        self.route_table_size["ipv4_routes"] = data.get("total_lines_ipv4")
        self.route_table_size["ipv6_routes"] = data.get("total_lines_ipv6")

        return self.route_table

    def get_detected_devices(self, exclude_columns=None):
        self.rest_check_session()
        result = self.devapi.monitor("user/detected-device", "select")
        if not self.rest_monitor_check_resp(result):
            FORTIGATEREPR_LOGGER.error("Response encountered error, returning None.")
            return None
        data = ForitgateDetectedDevices(result.get("results"))
        data.clean_data()
        self.detected_devices = data
        return self.detected_devices

    def get_interfaces(self, exclude_columns=None):
        self.rest_check_session()
        # if interfaces not already populated from get_facts, then get the interface data:
        if self.interfaces is None:
            result = self.devapi.monitor("system/available-interfaces", "select")
            if not self.rest_monitor_check_resp(result):
                FORTIGATEREPR_LOGGER.error(
                    "Response encountered error, returning None."
                )
                return None
            data = FortigateInterfaceDetails(result.get("results"))
            data.clean_data()
            self.interfaces = data
        return self.interfaces

    def get_fw_policy_ipv4(self):
        """
        get Firewall's configured ipv4 security policy
        """
        self.rest_check_session()
        # if interfaces not already populated from get_facts, then get the interface data:
        if self.fw_policy_ipv4 is None:
            result = self.devapi.get("firewall", "policy")
            if not self.rest_monitor_check_resp(result):
                FORTIGATEREPR_LOGGER.error(
                    "Response encountered error, returning None."
                )
                return None
            data = FortigateFirewallPolicy(result.get("results"))
            data.clean_data()
            self.fw_policy_ipv4 = data
        return self.fw_policy_ipv4

    def get_fw_policy_ipv6(self):
        """
        get Firewall's configured ipv6 security policy
        """
        self.rest_check_session()
        # if interfaces not already populated from get_facts, then get the interface data:
        if self.fw_policy_ipv6 is None:
            result = self.devapi.get("firewall6", "policy")
            if not self.rest_monitor_check_resp(result):
                FORTIGATEREPR_LOGGER.error(
                    "Response encountered error, returning None."
                )
                return None
            data = FortigateFirewallPolicy(result.get("results"))
            data.clean_data()
            self.fw_policy_ipv6 = data
        return self.fw_policy_ipv6

    def get_managed_aps(self):
        """
        get Firewall's managed AP Details
        """
        self.rest_check_session()
        # if interfaces not already populated from get_facts, then get the interface data:
        if self.managed_aps is None:
            result = self.devapi.monitor("wifi/managed_ap", "select")
            if not self.rest_monitor_check_resp(result):
                FORTIGATEREPR_LOGGER.error(
                    "Response encountered error, returning None."
                )
                return None
            data = FortigateManagedAps(result.get("results"))
            data.clean_data()
            self.managed_aps = data
        return self.managed_aps

    def get_wlan_connected_clients(self):
        """
        get Firewall's managed AP Details
        """
        self.rest_check_session()
        # if interfaces not already populated from get_facts, then get the interface data:
        if self.wlan_connected_clients is None:
            result = self.devapi.monitor("wifi/client", "select")
            if not self.rest_monitor_check_resp(result):
                FORTIGATEREPR_LOGGER.error(
                    "Response encountered error, returning None."
                )
                return None
            data = FortigateWlanConnectedClients(result.get("results"))
            data.clean_data()
            self.wlan_connected_clients = data
        return self.wlan_connected_clients

    def get_wlan_rogue_aps(self):
        """
        get Firewall's managed AP Details
        """
        self.rest_check_session()
        # if interfaces not already populated from get_facts, then get the interface data:
        if self.wlan_rogue_aps is None:
            result = self.devapi.monitor("wifi/rogue_ap", "select")
            if not self.rest_monitor_check_resp(result):
                FORTIGATEREPR_LOGGER.error(
                    "Response encountered error, returning None."
                )
                return None
            data = FortigateWlanRogueAps(result.get("results"))
            data.clean_data()
            self.wlan_rogue_aps = data
        return self.wlan_rogue_aps

    def get_dhcp_client_leases(self) -> Optional[pd.DataFrame]:
        """
        get Firewall's managed AP Details
        """
        self.rest_check_session()
        # if interfaces not already populated from get_facts, then get the interface data:
        if self.dhcp_client_leases is None:
            result = self.devapi.monitor("system/dhcp", "select")
            if not self.rest_monitor_check_resp(result):
                FORTIGATEREPR_LOGGER.error(
                    "Response encountered error, returning None."
                )
                return None
            data = FortigateDhcpClientLeases(result.get("results"))
            data.clean_data()
            self.dhcp_client_leases = data
        return self.dhcp_client_leases
