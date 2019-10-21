#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open("README.md") as readme_file:
    readme = readme_file.read()

with open("HISTORY.rst") as history_file:
    history = history_file.read()

requirements = ["fortiosapi", "pandas", "textfsm"]

setup_requirements = ["pytest-runner"]

test_requirements = ["pytest"]

setup(
    author="Will McLendon",
    author_email="wimclend@gmail.com",
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    description="Library to interact with and create representation of operational state data of a Fortigate device.",
    install_requires=requirements,
    license="Apache Software License 2.0",
    long_description=readme + "\n\n" + history,
    long_description_content_type="text/markdown",
    include_package_data=True,
    keywords="fortigaterepr",
    name="fortigaterepr",
    packages=find_packages(include=["fortigaterepr"]),
    setup_requires=setup_requirements,
    test_suite="tests",
    tests_require=test_requirements,
    url="https://github.com/wmclendon/fortigaterepr",
    version="version='0.1.1'",
    zip_safe=False,
)
