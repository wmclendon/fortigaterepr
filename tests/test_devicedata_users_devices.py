import base64
import copy
import json
import logging
import os
import tempfile
from unittest import mock

import pandas as pd
import pandas.api.types as ptypes
import pytest
import requests

from fortigaterepr.devicedata import (
    ForitgateDetectedDevices,
    FortigateDhcpClientLeases,
    FortigateManagedAps,
    FortigateWlanConnectedClients,
    FortigateWlanRogueAps,
)

from .example_data import DETECTED_DEVICES, DHCP_LEASES


class Test_TEMPLATE:
    """Class for testing TEMPLATE functionality
    """

    def test_basic_data(self):
        pass

    def test_get_method(self):
        pass


class Test_DhcpClientLeases:
    """Class for testing DhcpClientLeases functionality
    """

    def test_basic_data(self):
        base_cols = [
            "ip",
            "mac",
            "hostname",
            "expire_time",
            "status",
            "interface",
            "type",
            "reserved",
            "vci",
        ]
        data = FortigateDhcpClientLeases(DHCP_LEASES)
        assert isinstance(data, pd.DataFrame)
        for col in FortigateDhcpClientLeases.base_drop_columns:
            assert col in data.columns
        for col in base_cols:
            assert col in data.columns

    def test_get_method(self):
        data = FortigateDhcpClientLeases(DHCP_LEASES)
        data.clean_data()
        assert isinstance(data, pd.DataFrame)
        # verifies clean_data() properly sets value to datetime
        assert ptypes.is_datetime64_any_dtype(data["expire_time"])
        # verifies the clean_data() properly cleans up NaN values
        assert data["vci"].str.contains("N/A").any()
        assert data["hostname"].str.contains("None / Unknown").any()
        data_get = data.get()
        for col in FortigateDhcpClientLeases.base_drop_columns:
            assert col not in data_get


class Test_DetectedDevices:
    """Class for testing DetectedDevices functionality
    """

    def test_basic_data(self):
        data = ForitgateDetectedDevices(copy.deepcopy(DETECTED_DEVICES))
        assert isinstance(data, pd.DataFrame)
        # assert expected values are present before any cleanup:
        for col in ForitgateDetectedDevices.base_drop_columns:
            assert col in data.columns

    def test_clean_data(self):
        cleaned_value = "Unknown"
        data = ForitgateDetectedDevices(copy.deepcopy(DETECTED_DEVICES))
        data.clean_data()
        assert isinstance(data, pd.DataFrame)
        assert data["hostname"].str.contains(cleaned_value).any()
        assert data["os_name"].str.contains(cleaned_value).any()
        assert data["os_version"].str.contains(cleaned_value).any()
        assert data["ipv6_address"].str.contains(cleaned_value).any()

    def test_get_method(self):
        data = ForitgateDetectedDevices(copy.deepcopy(DETECTED_DEVICES))
        data.clean_data()
        data = data.get()
        assert isinstance(data, pd.DataFrame)
        # assert dropped columns are NOT present in the returned data:
        for col in ForitgateDetectedDevices.base_drop_columns:
            assert col not in data.columns
