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

from fortigaterepr.devicedata import get_helper, clean_columns_helper

from .example_data import INTERFACE_DETAILS_RESULT

# TODO:  Module scoped fixture for dataframe to pass to get_helper() ??


class Test_TEMPLATE:
    """Class for testing TEMPLATE functionality
    """

    def test_basic_data(self):
        pass

    def test_get_method(self):
        pass


class Test_clean_columns_helper:
    """Class for testing clean_columns_helper() method
    """

    intf_test_tuple = [
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

    def test_empty_list(self):
        """test empty list passed to helper function returns the original dataframe
        """
        test_list = []
        df = pd.DataFrame(INTERFACE_DETAILS_RESULT)
        result = clean_columns_helper(df, test_list)
        assert isinstance(result, pd.DataFrame)
        assert result.equals(df)

    def test_list_tuples(self):
        """test passing proper list of tuples cleans the data properly
        """
        df = pd.DataFrame(INTERFACE_DETAILS_RESULT)
        result = clean_columns_helper(df, self.intf_test_tuple)
        assert isinstance(result, pd.DataFrame)
        # TODO: need to assert one or more of the values were set properly

    def test_list_tuples_missing_key(self):
        """test passing proper list of tuples but where one of the columns does not exist in the dataframe
        verify that it returns DataFrame with the columns that were specified cleaned as expected
        """
        test_list = [("vdom", "N/A"), ("status", "N/A"), ("Non-Existing-Column", "N/A")]
        df = pd.DataFrame(INTERFACE_DETAILS_RESULT)
        result = clean_columns_helper(df, test_list)
        assert isinstance(result, pd.DataFrame)
        # TODO: need to assert one or more of the values were set properly


class Test_get_helper:
    """Class for testing get_helper() functionality
    """

    def test_get_helper_with_list(self):
        """tests get_helper() with proper list passed as exclude_columns parameter
        """
        df = pd.DataFrame(INTERFACE_DETAILS_RESULT)
        exclude_list = ["media", "is_system_interface"]
        # first make sure columns are present in the dataframe:
        for col in exclude_list:
            assert col in df.columns

        result = get_helper(df, exclude_list)
        for col in exclude_list:
            assert col not in result.columns
        assert isinstance(result, pd.DataFrame)

    def test_get_helper_with_none(self):
        """tests get_helper() with None passed as exclude_columns parameter
        """
        df = pd.DataFrame(INTERFACE_DETAILS_RESULT)
        exclude_list = None
        # first make sure columns are present in the dataframe:

        result = get_helper(df, exclude_list)
        assert result.equals(df)

    def test_get_helper_with_non_list(self):
        """test to validate get_helper() when passed invalid type for exclude_columns returns the original dataframe
        """
        df = pd.DataFrame(INTERFACE_DETAILS_RESULT)
        exclude_list = 500
        # first make sure columns are present in the dataframe:

        result = get_helper(df, exclude_list)
        assert result.equals(df)
