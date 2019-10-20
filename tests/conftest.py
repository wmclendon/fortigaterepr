import datetime
import os
import tempfile
from pathlib import Path

import pytest

## EXAMPLES BELOW FROM ANOTHER PROJECT:

# TEST_CONF_FILNAME = "tests/test_vars.ini"

# @pytest.fixture
# def test_config_file():
#     config_file = Path(TEST_CONF_FILNAME)
#     return config_file

# @pytest.fixture()
# def config_vars():
#     """returns config vars from ini file for unit tests
#     """
#     config_vars = e3_alert_helpers.verify_env_vars(TEST_CONF_FILNAME)
#     return config_vars

# @pytest.fixture()
# def valid_token():
#     """returns a valid JWT token
#     """
#     one_hour_later = datetime.datetime.utcnow() + datetime.timedelta(seconds=3600)
#     encoded_jwt = jwt.encode(
#         {"some": "payload", "present": "true", "exp": one_hour_later},
#         key="secret",
#         algorithm="HS256",
#     )
#     return encoded_jwt

# @pytest.fixture
# def invalid_token():
#     """returns an invalid JWT token
#     """
#     one_hour_ago = datetime.datetime.utcnow() - datetime.timedelta(seconds=3600)
#     encoded_jwt = jwt.encode(
#         {"some": "payload", "present": "true", "exp": one_hour_ago},
#         key="secret",
#         algorithm="HS256",
#     )
#     return encoded_jwt

# @pytest.fixture
# def credential_file():
#     """tempfile contianing previously stored credentials
#     """
#     try:
#         f = tempfile.NamedTemporaryFile(delete=False)
#         f.write(
#             b"""{"status": "success", "message": "login success", "auth_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1NjM0MDQ1NjMsImlhdCI6MTU2MzQwMDk2Mywic3ViIjoidGVzdGFwaWFjY3QiLCJyb2xlIjoicmVhZHdyaXRlIn0.4RspBKznsEqH5oh9cKcvfgrrlfxGKK6g4fFFFg0kcic"}"""
#         )
#         f.close()
#         yield f
#     finally:
#         os.unlink(f.name)

# @pytest.fixture
# def base_alert():
#     """fixture for an E3BaseAlert to be used in unit tests
#     """

#     alert = E3Alerts.E3BaseAlert(
#         customer=1,
#         device_serial="testdev01",
#         alert_profile_id=1,
#         customer_name="test customer",
#     )
#     return alert

# @pytest.fixture
# def base_alert_with_email_actions():
#     """fixture for an E3BaseAlert with email actions to be used in unit tests
#     """

#     alert = E3Alerts.E3BaseAlert(
#         customer=1,
#         device_serial="testdev02",
#         alert_profile_id=1,
#         customer_name="test customer",
#     )
#     alert.alert_id = 10
#     action1 = E3Alerts.E3EmailAction("email action 1", "test1@example.com", 1)
#     action2 = E3Alerts.E3EmailAction("email action 2", "test2@example.com", 1)
#     alert.add_action(action1)
#     alert.add_action(action2)

#     return alert
