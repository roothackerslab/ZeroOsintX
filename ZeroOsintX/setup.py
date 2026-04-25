#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="zeroosinx",
    version="1.0.0",
    author="ZeroTraceX (ahsan)",
    author_email="roothackerslab@example.com",
    description="Professional OSINT & Reconnaissance Tool by ZeroTraceX",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/roothackerslab/ZeroOsintX",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8+",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "dnspython>=2.3.0",
        "python-whois>=0.8.0",
        "rich>=13.0.0",
    ],
    entry_points={
        "console_scripts": [
            "zeroosinx=zeroosinx:main",
        ],
    },
)
