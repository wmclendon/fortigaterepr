import ipaddress
import logging

import pandas as pd

# TODO:  Should each class have an attribute for storing the original raw output when its created, that way if it
# ever needs to be used to feed back into a FortigateDevice it can have the exact same format, structure, etc apart
# from the clean_data() operation.
# Believe this would require a new __init__() method to set a self.raw variable.  not sure how to do this as extension
# to a Pandas DataFrame -- need to call super() first I think.  or could potentially as a first step of clean_data()
# where it checks if self.raw is None, and if yes, copy over the data first, then initiate cleanup.  I think it needs
# to be done as part of an __init__ though because then can have __init__(self, raw_data) as the constructor, and then
# have self.raw = raw_data for storing it as it came in -- would not be a dataframe though, but could save it as one.

# subclassing Pandas seems way too complicated.  instead, factoring out the get() method logic from each subclass to a
# generic method that takes the dataframe data, the list of exclude_columns, and returns the dataframe without those columns
# that are present in the original frame
def get_helper(df: pd.DataFrame, exclude_columns: list = None):
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


class FortigateManagedAps(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful maniuplation capabilities natively and can be passed on to user, with a handful of helper methods and
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
        pass

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy Route Table itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateWlanConnectedClients(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful maniuplation capabilities natively and can be passed on to user, with a handful of helper methods and
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
        pass

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy Route Table itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateWlanRogueAps(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful maniuplation capabilities natively and can be passed on to user, with a handful of helper methods and
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

        for c in clean_columns:
            try:
                self[c[0]].fillna(c[1], inplace=True)
            except KeyError:
                logging.info(f"Column {c[0]} not found in data, skipping.")

        # if "manufacturer" in self:
        #     self["manufacturer"].fillna("Unknown", inplace=True)
        # if "encryption" in self:
        #     self["encryption"].fillna("None / Unknown", inplace=True)
        # if "ssid" in self:
        #     self["ssid"].fillna("None / Unknown", inplace=True)

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy Route Table itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateArpTable(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful maniuplation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.

    initiliazation will require additional cleanup due to how we have to gather the data at this time, with CLI command that is returned
    as list of data rather than raw text response.
    """

    base_drop_columns = []

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        pass

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy Route Table itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateInterfaceDetails(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful maniuplation capabilities natively and can be passed on to user, with a handful of helper methods and
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
        ]

        for c in clean_columns:
            try:
                self[c[0]].fillna(c[1], inplace=True)
            except KeyError:
                logging.info(f"Column {c[0]} not found in data, skipping.")

        # TODO:  Iterate over list of tuples containing column names and fillna values!
        # try:
        #     self["vdom"].fillna("N/A", inplace=True)
        # except KeyError:
        #     logging.info("Key not found!")
        # self["status"].fillna("N/A", inplace=True)
        # self["mac_address"].fillna("N/A", inplace=True)
        # self["alias"].fillna("None", inplace=True)
        # self["zone"].fillna("N/A", inplace=True)
        # self["ipv4_addresses"].fillna("None", inplace=True)
        # self["link"].fillna("N/A", inplace=True)
        # self["speed"].fillna("N/A", inplace=True)
        # self["media"].fillna("N/A", inplace=True)
        # try:
        #     self["description"].fillna("None", inplace=True)
        # except KeyError:
        #     logging.info("Key not found!")

        # self["duplex"].fillna("N/A", inplace=True)

        # for now going to convert the IP representation to CIDR notation.
        # also presumes no multi-netting at this time...
        for idx, item in self.iterrows():
            if isinstance(item["ipv4_addresses"], list):
                ip_addr = str(
                    ipaddress.ip_interface(
                        f"{item['ipv4_addresses'][0]['ip']}/{item['ipv4_addresses'][0]['netmask']}"
                    )
                )
                # ip_addr = f"{item['ipv4_addresses'][0]['ip']}/{item['ipv4_addresses'][0]['netmask']}"

                self.at[idx, "ipv4_addresses"] = ip_addr

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy Route Table itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class ForitgateDetectedDevices(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful maniuplation capabilities natively and can be passed on to user, with a handful of helper methods and
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
        pass

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy Route Table itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateActiveIpsecVpns(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful maniuplation capabilities natively and can be passed on to user, with a handful of helper methods and
    domain specific tooling.
    """

    base_drop_columns = ["proxyid", "wizard-type"]

    def clean_data(self):
        """
        method to clean / normalize data, if necessary
        """
        pass

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy Route Table itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateRouteTable(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful maniuplation capabilities natively and can be passed on to user, with a handful of helper methods and
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

        for c in clean_columns:
            try:
                self[c[0]].fillna(c[1], inplace=True)
            except KeyError:
                logging.info(f"Column {c[0]} not found in data, skipping.")

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
        returns copy Route Table itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)


class FortigateFirewallPolicy(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful maniuplation capabilities natively and can be passed on to user, with a handful of helper methods and
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
        returns copy Route Table itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        # if no exclude_columns specified, then we return the same as get_simple_output:
        if exclude_columns is None:
            return self.get_simple_output()

        return get_helper(self, exclude_columns)


class FortigateDhcpClientLeases(pd.DataFrame):
    """
    subclass of Pandas DataFrame that has powerful maniuplation capabilities natively and can be passed on to user, with a handful of helper methods and
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

        for c in clean_columns:
            try:
                self[c[0]].fillna(c[1], inplace=True)
            except KeyError:
                logging.info(f"Column {c[0]} not found in data, skipping.")

        if "expire_time" in self:
            self["expire_time"] = pd.to_datetime(
                self["expire_time"], errors="coerce", unit="s"
            )

        # if "vci" in self:
        #     self["vci"].fillna("N/A", inplace=True)
        # if "hostname" in self:
        #     self["hostname"].fillna("None / Unknown", inplace=True)

    def get(self, exclude_columns=base_drop_columns):
        """
        returns copy Route Table itself, with optionally removed columns.  effectively a wrapper for the DataFrae drop method
        """
        return get_helper(self, exclude_columns)
