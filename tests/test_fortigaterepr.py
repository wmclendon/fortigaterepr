#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for `fortigaterepr` package."""

import pytest

from fortigaterepr import fortigaterepr
from .example_data import FW_FACTS


@pytest.fixture
def response():
    """Sample pytest fixture.

    See more at: http://doc.pytest.org/en/latest/fixture.html
    """
    # import requests
    # return requests.get('https://github.com/audreyr/cookiecutter-pypackage')


def test_content(response):
    """Sample pytest test function with the pytest fixture as an argument."""
    # from bs4 import BeautifulSoup
    # assert 'GitHub' in BeautifulSoup(response.content).title.string


class Test_Fortigaterepr:
    """tests for fortigaterepr class"""

    # TODO:  Add tests for facts, and other helper methods etc. -- requires lots of mocking
    pass
