import pytest
import logging
import os
import tempfile
import json
import base64
import requests
import pandas as pd
from unittest import mock

from fortigaterepr.devicedata import (
    FortigateDhcpClientLeases,
    FortigateManagedAps,
    FortigateWlanConnectedClients,
    FortigateWlanRogueAps,
    ForitgateDetectedDevices,
)


class Test_TEMPLATE:
    """Class for testing TEMPLATE functionality
    """

    def test_basic_data(self):
        pass

    def test_get_method(self):
        pass
