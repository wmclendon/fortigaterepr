import base64
import copy
import json
import logging
import os
import tempfile
from unittest import mock

import pandas as pd
import pytest
import requests

from fortigaterepr.devicedata import (
    FortigateArpTable,
    FortigateInterfaceDetails,
    FortigateRouteTable,
)

from .example_data import INTERFACE_DETAILS_RESULT, ROUTE_TABLE_RESULT


class Test_TEMPLATE:
    """Class for testing TEMPLATE functionality
    """

    def test_basic_data(self):
        pass

    def test_get_method(self):
        pass


class Test_FortigateArpTable:
    """Class for testing FortigateArpTable functionality
    """

    FSM_PARSED_ARP_DATA = [
        ["10.104.164.2", "1", "3e:27:eb:f8:ee:bd", "internal"],
        ["10.110.3.250", "1", "00:04:96:b9:fb:aa", "wan1"],
        ["10.110.0.1", "0", "4c:96:14:f3:5e:60", "wan1"],
        ["10.110.0.75", "1", "54:4b:8c:ff:13:20", "wan1"],
    ]
    ARP_COLUMNS = ["Address", "Age(min)", "MAC Address", "Interface"]

    def test_basic_data(self):
        example_arp_entry = "10.110.0.1"
        example_mac_entry = "4c:96:14:f3:5e:60"
        example_intf_name = "wan1"
        arp_table = FortigateArpTable(
            columns=self.ARP_COLUMNS, data=self.FSM_PARSED_ARP_DATA
        )
        assert arp_table["Address"].str.contains(example_arp_entry).any()
        assert arp_table["MAC Address"].str.contains(example_mac_entry).any()
        assert arp_table["Interface"].str.contains(example_intf_name).any()
        assert isinstance(arp_table, pd.DataFrame)

    def test_get_method(self):
        data = FortigateArpTable(
            columns=self.ARP_COLUMNS, data=copy.deepcopy(self.FSM_PARSED_ARP_DATA)
        )
        data.clean_data()
        data2 = data.get()
        assert data2.equals(data)
        data_filtered = data.get(exclude_columns=["Interface"])
        assert "Interface" not in data_filtered.columns


class Test_FortigateInterfaceDetails:
    """Class for testing FortigateInterfaceDetails functionality
    """

    def test_basic_data(self):
        example_name = "wan1"
        example_vdom = "root"
        example_status = "up"
        example_ipv4_addr = "10.110.1.128/22"
        example_mac_addr = "e8:1c:ba:4f:d7:4e"
        example_link = "up"
        example_duplex = "full"
        example_speed = 1000
        example_media = "rj45"

        data = FortigateInterfaceDetails(copy.deepcopy(INTERFACE_DETAILS_RESULT))
        assert isinstance(data, pd.DataFrame)

        assert "name" in data.columns
        assert "vdom" in data.columns
        assert "status" in data.columns
        assert "ipv4_addresses" in data.columns
        assert "mac_address" in data.columns
        assert "link" in data.columns
        assert "duplex" in data.columns
        assert "speed" in data.columns
        assert "media" in data.columns
        assert "alias" in data.columns
        assert "zone" in data.columns
        assert "description" in data.columns
        assert data["name"].str.contains(example_name).any()
        # TODO:  add more assertions to validate data

    def test_get_method(self):
        clean_ipv4_addr = "10.110.1.128/22"
        example_name = "wan1"
        data = FortigateInterfaceDetails(copy.deepcopy(INTERFACE_DETAILS_RESULT))
        data.clean_data()
        assert data["name"].str.contains(example_name).any()
        assert data["ipv4_addresses"].str.contains(clean_ipv4_addr).any()
        data_filtered = data.get(exclude_columns=["Invalid"])
        assert data_filtered.equals(data)


class Test_FortigateRouteTable:
    """Class for testing FortigateRouteTable functionality
    """

    def test_basic_data(self):
        example_ip_mask = "10.0.0.0/8"
        example_distance = 200
        example_gateway = "192.0.2.100"
        example_interface = "dc1_hub"

        data = FortigateRouteTable(copy.deepcopy(ROUTE_TABLE_RESULT))
        assert isinstance(data, pd.DataFrame)

        assert "ip_version" in data.columns
        assert "type" in data.columns
        assert "ip_mask" in data.columns
        assert "distance" in data.columns
        assert "metric" in data.columns
        assert "gateway" in data.columns
        assert "interface" in data.columns
        assert "is_tunnel_route" in data.columns
        assert "tunnel_parent" in data.columns
        assert "install_date" in data.columns
        assert "uptime" in data.columns
        assert data["ip_mask"].str.contains(example_ip_mask).any()
        assert data["gateway"].str.contains(example_gateway).any()
        assert data["interface"].str.contains(example_interface).any()
        assert example_distance in data["distance"].values

    def test_get_method(self):
        example_ip_mask = "10.0.0.0/8"
        example_distance = 200
        example_gateway = "192.0.2.100"
        example_interface = "dc1_hub"
        data = FortigateRouteTable(copy.deepcopy(ROUTE_TABLE_RESULT))
        data.clean_data()
        assert data["ip_mask"].str.contains(example_ip_mask).any()
        assert data["gateway"].str.contains(example_gateway).any()
        assert data["interface"].str.contains(example_interface).any()
        assert example_distance in data["distance"].values
        data_filtered = data.get(exclude_columns=["Invalid"])
        assert data_filtered.equals(data)
