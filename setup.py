from setuptools import setup, find_packages

setup(
    name="posframework",
    version="2.1.0",
    packages=find_packages(),
    install_requires=[
        "scapy",
        "manuf",
        "pyyaml",
    ],
    entry_points={
        "console_scripts": [
            "posframework=posframework.__main__:main",
        ],
    },
)
