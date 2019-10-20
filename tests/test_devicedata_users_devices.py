import base64
import json
import logging
import os
import tempfile
from unittest import mock

import pandas as pd
import pytest
import requests

from fortigaterepr.devicedata import (
    ForitgateDetectedDevices,
    FortigateDhcpClientLeases,
    FortigateManagedAps,
    FortigateWlanConnectedClients,
    FortigateWlanRogueAps,
)


class Test_TEMPLATE:
    """Class for testing TEMPLATE functionality
    """

    def test_basic_data(self):
        pass

    def test_get_method(self):
        pass
