import ipaddress
import logging

import pandas as pd

from typing import List, Tuple


# subclassing Pandas seems way too complicated to then also add exclude_columns or other properties.  instead, factoring out the get() method logic from each subclass to a
# generic method that takes the dataframe data, the list of exclude_columns, and returns the dataframe without those columns
# that are present in the original frame


def get_helper(df: pd.DataFrame, exclude_columns: List = None) -> pd.DataFrame:
    """
    returns copy of data itself, with optionally removed columns.  effectively a wrapper for the DataFrame drop method, with some specific defaults
    """
    if isinstance(exclude_columns, list):
        exclude_columns = [c for c in exclude_columns if c in df.columns]
    else:
        logging.info(
            f"excluded_columns parameter is type {type(exclude_columns)}, should be list.  Returning data as-is"
        )
        exclude_columns = []

    return df.drop(exclude_columns, axis=1)


def clean_columns_helper(
    df: pd.DataFrame, clean_columns: List[Tuple[str, str]]
) -> pd.DataFrame:
    """
    helper method to clean up column data that would otherwise be an NaN value or similar.

    Takes the original dataframe and a list of tuples defining the column name and NA value

    Returns cleaned up dataframe
    """
    if len(clean_columns) == 0:
        # empty list of clean_columns, return df dataframe unchanged
        return df

    for c in clean_columns:
        try:
            df[c[0]].fillna(c[1], inplace=True)
        except KeyError:
            logging.info(f"Column {c[0]} not found in data, skipping.")
    return df


class FortigateServices(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.

    initiliazation will require additional cleanup due to how we have to gather the data at this time, with CLI command that is returned
    as list of data rather than raw text response.
    """

    base_drop_columns = [
        "q_origin_key",
        "proxy",
        "helper",
        "iprange",
        "tcp-halfclose-timer",
        "tcp-halfopen-timer",
        "udp-idle-timer",
        "session-ttl",
        "check-reset-range",
        "color",
        "visibility",
    ]

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        clean_columns = []
        self = clean_columns_helper(self, clean_columns)
        # below enables sorting by column...not sure how to expose this.  leaving commented out for now
        # self.sort_values(by=['category'], inplace=True)

        # need to add column 'protocol-name' or something based on protocol-number, for friendlier output
        # create protocol-name column and re-order to be right after protocol-number
        # self['protocol-name'] = 'Not Specified'
        self.insert(9, "protocol-name", "Not Specified")
        protocol_names = {
            1: "icmp",
            6: "tcp",
            17: "udp",
            89: "ospf",
            47: "gre",
            50: "esp",
            51: "ah",
            58: "icmp6",
        }
        for idx, item in self.iterrows():
            if isinstance(item.get("protocol-number"), int):
                protocol_number = item.get("protocol-number")
                self.at[idx, "protocol-name"] = protocol_names.get(
                    protocol_number, "Not specified"
                )

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of DataFrame itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateManagedAps(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.

    initiliazation will require additional cleanup due to how we have to gather the data at this time, with CLI command that is returned
    as list of data rather than raw text response.
    """

    # TODO:  Add helper methods to get specific details of APs, like wired interface stats, SSID or Radio info, etc.
    base_drop_columns = [
        "region_code",
        "mgmt_vlanid",
        "mesh_uplink",
        "mesh_hop_count",
        "mesh_uplink_intf",
        "join_time_raw",
        "reboot_last_day",
        "image_download_progress",
        "override_profile",
        "wired",
        "country_code_conflict",
        "cli_enabled",
        "wtp_mode",
    ]

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        clean_columns = []
        self = clean_columns_helper(self, clean_columns)

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of DataFrame itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateWlanConnectedClients(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.

    initiliazation will require additional cleanup due to how we have to gather the data at this time, with CLI command that is returned
    as list of data rather than raw text response.
    """

    base_drop_columns = [
        "captive_portal_authenticated",
        "data_rate",
        "lan_authenticated",
        "host",
        "security",
        "encrypt",
        "signal_bar",
        "mac",
        "vlan_id",
    ]

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        clean_columns = []
        self = clean_columns_helper(self, clean_columns)

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of DataFrame itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateWlanRogueAps(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.

    initiliazation will require additional cleanup due to how we have to gather the data at this time, with CLI command that is returned
    as list of data rather than raw text response.
    """

    base_drop_columns = [
        "is_wired",
        "capinfo",
        "rate",
        "is_fake",
        "signal_strength",
        "noise",
        "rate",
        "first_seen",
        "last_seen",
        "sta_mac",
        "wtp_count",
    ]

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """

        clean_columns = [
            ("manufacturer", "Unknown"),
            ("encryption", "None / Unknown"),
            ("ssid", "None / Unknown"),
        ]

        self = clean_columns_helper(self, clean_columns)

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of DataFrame itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateArpTable(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.

    initiliazation will require additional cleanup due to how we have to gather the data at this time, with CLI command that is returned
    as list of data rather than raw text response.
    """

    base_drop_columns = []

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        clean_columns = []
        self = clean_columns_helper(self, clean_columns)

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of DataFrame itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateInterfaceDetails(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.
    """

    base_drop_columns = [
        "real_interface_name",
        "is_system_interface",
        "dynamic_addressing",
        "dhcp4_client_count",
        "dhcp6_client_count",
        "role",
        "estimated_upstream_bandwidth",
        "estimated_downstream_bandwidth",
        "is_ipsecable",
        "supports_device_id",
        "device_id_enabled",
        "valid_in_policy",
        "supports_fortitelemetry",
        "fortitelemetry",
        "compliance_enforced",
        "is_ipsec_static",
        "managed_devices",
        "is_used",
        "is_hardware_switch",
        "members",
        "is_zone_member",
        "is_routable",
        "tagging",
        "type",
        "is_physical",
        "used_by_composite",
        "is_hardware_switch_member",
        "hardware_switch",
        "icon",
        "load_balance_mode",
        "sd_wan_settings",
        "is_sslvpn",
        "is_tunnel",
        "is_zone",
        "is_virtual_wan_link",
        "is_modem",
        "is_modem_hidden",
        "is_wifi",
        "ssid",
        "is_local_bridge",
        "is_software_switch",
        "used_by_aggregate_or_switch",
        "vlan_interface",
    ]

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        clean_columns = [
            ("vdom", "N/A"),
            ("status", "N/A"),
            ("mac_address", "N/A"),
            ("alias", "N/A"),
            ("zone", "N/A"),
            ("ipv4_addresses", "None"),
            ("link", "N/A"),
            ("speed", "N/A"),
            ("media", "N/A"),
            ("Description", "None"),
            ("duplex", "N/A"),
            ("is_software_switch", False),
            ("used_by_aggregate_or_switch", False),
            ("is_vlan", False),
            ("vlan_interface", "None"),
            ("vlan_id", "N/A"),
            ("ipv6_addresses", "None"),
        ]

        self = clean_columns_helper(self, clean_columns)

        # for now going to convert the IP representation to CIDR notation.
        # also presumes no multi-netting at this time...
        for idx, item in self.iterrows():
            if isinstance(item.get("ipv4_addresses"), list):
                ip_addr = str(
                    ipaddress.ip_interface(
                        f"{item['ipv4_addresses'][0]['ip']}/{item['ipv4_addresses'][0]['netmask']}"
                    )
                )
                self.at[idx, "ipv4_addresses"] = ip_addr
            if isinstance(item.get("ipv6_addresses"), list):
                ip6_addr = str(
                    ipaddress.ip_interface(
                        f"{item['ipv6_addresses'][0]['ip']}/{item['ipv6_addresses'][0]['cidr_netmask']}"
                    )
                )
                self.at[idx, "ipv6_addresses"] = ip6_addr
            if isinstance(item.get("vlan_id"), float):
                self.at[idx, "vlan_id"] = int(item.get("vlan_id"))

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of DataFrame itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class ForitgateDetectedDevices(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.
    """

    base_drop_columns = [
        "type",
        "master_mac",
        "category",
        "hostname_source",
        "os_source",
        "is_master_device",
        "other_macs",
        "other_devices",
        "interfaces",
    ]

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        clean_columns = [
            ("hostname", "Unknown"),
            ("os_name", "Unknown"),
            ("os_version", "Unknown"),
            ("ipv6_address", "Unknown"),
        ]
        self = clean_columns_helper(self, clean_columns)

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of DataFrame itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateActiveIpsecVpns(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.
    """

    base_drop_columns = ["proxyid", "wizard-type"]

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        clean_columns = []
        self = clean_columns_helper(self, clean_columns)

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of DataFrame itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateRouteTable(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.
    """

    base_drop_columns = []

    def clean_data(self):
        """
        method to clean / normalize data in the route table DataFrame
        """
        clean_columns = [
            ("uptime", 0),
            ("install_date", 0),
            ("tunnel_parent", "N/A"),
            ("is_tunnel_route", "N/A"),
        ]
        self = clean_columns_helper(self, clean_columns)

        # this column, if present, requires special processing, so outside the for loop above
        if "install_date" in self:
            self["install_date"] = pd.to_datetime(
                self["install_date"], errors="coerce", unit="s"
            )

        # self["uptime"].fillna(0, inplace=True)
        # self["install_date"].fillna(0, inplace=True)
        # self["tunnel_parent"].fillna("N/A", inplace=True)
        # self["is_tunnel_route"].fillna("N/A", inplace=True)

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of DataFrame itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateFirewallPolicy(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.
    """

    base_drop_columns = []
    simple_view_columns = [
        "policyid",
        "name",
        "srcintf",
        "srcaddr",
        "dstintf",
        "dstaddr",
        "service",
        "action",
        "application",
        "comments",
        "logtraffic",
    ]

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        clean_columns = []
        self = clean_columns_helper(self, clean_columns)

        for idx, rule in self.iterrows():
            new_values = rule["srcintf"]
            for i, item in enumerate(new_values):
                new_values[i] = item.get("name")
            self.at[idx, "srcintf"] = new_values

            new_values = rule["srcaddr"]
            for i, item in enumerate(new_values):
                new_values[i] = item.get("name")
            self.at[idx, "srcaddr"] = new_values

            new_values = rule["dstintf"]
            for i, item in enumerate(new_values):
                new_values[i] = item.get("name")
            self.at[idx, "dstintf"] = new_values

            new_values = rule["dstaddr"]
            for i, item in enumerate(new_values):
                new_values[i] = item.get("name")
            self.at[idx, "dstaddr"] = new_values

            new_values = rule["service"]
            for i, item in enumerate(new_values):
                new_values[i] = item.get("name")
            self.at[idx, "service"] = new_values

    def get_simple_output(self):
        """
        helper method to return simple table with small number of columns
        """
        cols = [c for c in self.simple_view_columns if c in self.columns]
        return self[cols]

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of itself, with optionally removed columns.  effectively a wrapper for the DataFrame drop method
        """
        # if no exclude_columns specified, then we return the same as get_simple_output:
        if exclude_columns is None:
            return self.get_simple_output()

        return get_helper(self, exclude_columns)


class FortigateDhcpClientLeases(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful manipulation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.

    initiliazation will require additional cleanup due to how we have to gather the data at this time, with CLI command that is returned
    as list of data rather than raw text response.
    """

    base_drop_columns = ["server_mkey"]

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        clean_columns = [("vci", "N/A"), ("hostname", "None / Unknown")]
        self = clean_columns_helper(self, clean_columns)

        if "expire_time" in self:
            self["expire_time"] = pd.to_datetime(
                self["expire_time"], errors="coerce", unit="s"
            )

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy of DataFrame itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)
