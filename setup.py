"""Setup for editable install."""
from setuptools import find_packages, setup

setup(
    name="gitexpose",
    version="1.0.0",
    description="Advanced Git Directory Exposure Exploitation Framework",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "aiohttp>=3.9",
        "aiofiles>=23.0",
        "rich>=13.0",
        "dulwich>=0.21",
    ],
    entry_points={
        "console_scripts": [
            "gitexpose=gitexpose.cli:main",
        ],
    },
)
