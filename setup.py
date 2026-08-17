from setuptools import setup, find_packages

setup(
    name='posframework',
    version='2.2.0',
    packages=find_packages(),
    python_requires='>=3.9',
    install_requires=[
        'scapy>=2.5.0',
        'manuf',
    ],
    extras_require={
        'gui': ['tkinter'],
        'config': ['pyyaml'],
    },
    entry_points={
        'console_scripts': [
            'posfw=posframework.__main__:main',
        ],
    },
)
