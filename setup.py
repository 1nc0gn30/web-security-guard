#!/usr/bin/env python3
"""Setup script for web-security-guard package."""

from setuptools import setup, find_packages

setup(
    name="web-security-guard",
    version="1.0.0",
    description="Zero-dependency web security auditing, strict CSP generator, SRI hasher, WCAG contrast analyzer, and MCP server.",
    long_description=open("README.md", "r", encoding="utf-8").read() if __import__("os").path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="Zoth Security Architecture Team",
    author_email="security@zoth.io",
    license="MIT",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={
        "dev": ["pytest>=7.0.0", "pytest-cov>=4.0.0"],
    },
    entry_points={
        "console_scripts": [
            "sec-guard=web_security_guard.cli:main",
            "web-security-guard=web_security_guard.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
