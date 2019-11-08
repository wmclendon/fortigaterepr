import base64
import copy
import json
import logging
import os
import tempfile
from unittest import mock

import numpy
import pandas as pd
import pytest
import requests

from fortigaterepr.devicedata import FortigateActiveIpsecVpns, FortigateFirewallPolicy

from .example_data import ACTIVE_VPN_RESULT, FW_POLICY_RESULT


class Test_TEMPLATE:
    """Class for testing TEMPLATE functionality
    """

    def test_basic_data(self):
        pass

    def test_get_method(self):
        pass


class Test_FortigateFirewallPolicy:
    """Class for testing FortigateFirewallPolicy functionality
    """

    def test_basic_data(self):
        # tests basic construction of the dataframe -- before any data clean occurs
        example_name = "FW_POLICY02"
        example_srcaddr = [
            {"q_origin_key": "GROUP_OBJECT_NETWORKS", "name": "GROUP_OBJECT_NETWORKS"}
        ]
        example_dstaddr = [
            {"q_origin_key": "NET_OBJ_192.0.2.0_25", "name": "NET_OBJ_192.0.2.0_25"}
        ]
        data = FortigateFirewallPolicy(copy.deepcopy(FW_POLICY_RESULT))
        assert isinstance(data, pd.DataFrame)

        expected_columns = [
            "policyid",
            "name",
            "logtraffic",
            "application",
            "action",
            "service",
            "dstaddr",
            "dstintf",
            "srcaddr",
            "srcintf",
            "comments",
        ]
        for col in expected_columns:
            assert col in data.columns
        assert data["name"].str.contains(example_name).any()
        numpy.testing.assert_array_equal(data["srcaddr"][1], example_srcaddr)
        numpy.testing.assert_array_equal(data["dstaddr"][1], example_dstaddr)

    def test_get_method(self):
        example_name = "FW_POLICY02"
        example_srcaddr = ["GROUP_OBJECT_NETWORKS"]
        example_dstaddr = ["NET_OBJ_192.0.2.0_25"]
        data = FortigateFirewallPolicy(copy.deepcopy(FW_POLICY_RESULT))
        data.clean_data()
        assert isinstance(data, pd.DataFrame)
        assert data["name"].str.contains(example_name).any()
        numpy.testing.assert_array_equal(data["srcaddr"][1], example_srcaddr)
        numpy.testing.assert_array_equal(data["dstaddr"][1], example_dstaddr)
        # test get() where exclude_columns=None
        data_test = data.get(exclude_columns=None)
        assert data_test.equals(data.get_simple_output())
        data_get = data.get()
        assert isinstance(data_get, pd.DataFrame)
        assert data_get.equals(data)

    def test_get_simple_output(self):
        example_name = "FW_POLICY02"
        example_srcaddr = ["GROUP_OBJECT_NETWORKS"]
        example_dstaddr = ["NET_OBJ_192.0.2.0_25"]
        data = FortigateFirewallPolicy(copy.deepcopy(FW_POLICY_RESULT))
        data.clean_data()
        data = data.get_simple_output()
        assert isinstance(data, pd.DataFrame)
        assert data["name"].str.contains(example_name).any()
        numpy.testing.assert_array_equal(data["srcaddr"][1], example_srcaddr)
        numpy.testing.assert_array_equal(data["dstaddr"][1], example_dstaddr)


class Test_FortigateActiveIpsecVpns:
    """Class for testing FortigateActiveIpsecVpns functionality
    """

    def test_basic_data(self):
        example_name = "dc1_hub"
        example_rgwy = "192.0.2.198"
        example_creation_time = 643815
        data = FortigateActiveIpsecVpns(copy.deepcopy(ACTIVE_VPN_RESULT))
        assert "name" in data.columns
        assert "comments" in data.columns
        assert "creation_time" in data.columns
        assert "rgwy" in data.columns
        assert "incoming_bytes" in data.columns
        assert "outgoing_bytes" in data.columns
        assert "proxyid" in data.columns
        assert "wizard-type" in data.columns
        assert data["name"].str.contains(example_name).any()
        assert data["rgwy"].str.contains(example_rgwy).any()
        assert example_creation_time in data["creation_time"].values
        assert isinstance(data, pd.DataFrame)

    def test_get_method(self):
        example_name = "dc1_hub"
        example_rgwy = "192.0.2.198"
        example_creation_time = 643816
        data = FortigateActiveIpsecVpns(copy.deepcopy(ACTIVE_VPN_RESULT))
        data.clean_data()
        data = data.get()
        # assert some columns still there, and the default columns NOT in response:
        assert "name" in data.columns
        assert "comments" in data.columns
        assert "creation_time" in data.columns
        assert "rgwy" in data.columns
        assert "incoming_bytes" in data.columns
        assert "outgoing_bytes" in data.columns
        assert "proxyid" not in data.columns
        assert "wizard-type" not in data.columns
        assert data["name"].str.contains(example_name).any()
        assert data["rgwy"].str.contains(example_rgwy).any()
        assert example_creation_time in data["creation_time"].values
        assert isinstance(data, pd.DataFrame)

        # now assert column specified to not be returned is not returned:
        data = FortigateActiveIpsecVpns(copy.deepcopy(ACTIVE_VPN_RESULT))
        data.clean_data()
        data = data.get(exclude_columns=["name", "rgwy"])
        # assert some columns still there, and the default columns NOT in response:
        assert "name" not in data.columns
        assert "rgwy" not in data.columns
        assert "comments" in data.columns
        assert "creation_time" in data.columns
        assert "incoming_bytes" in data.columns
        assert "outgoing_bytes" in data.columns
        assert "proxyid" in data.columns
        assert "wizard-type" in data.columns
        # assert data["name"].str.contains(example_name).any()
        # assert data["rgwy"].str.contains(example_rgwy).any()
        assert example_creation_time in data["creation_time"].values
        assert isinstance(data, pd.DataFrame)

        # assert KeyError processing works -- returns the full DataFrame if KeyError occurs:
        data = FortigateActiveIpsecVpns(copy.deepcopy(ACTIVE_VPN_RESULT))
        data2 = data.get(exclude_columns=["not_valid"])
        assert data.equals(data2)
