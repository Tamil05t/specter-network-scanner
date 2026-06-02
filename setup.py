from setuptools import setup, find_packages

setup(
    name="specter",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "aiofiles>=23.2.1",
        "aiohttp>=3.9.5",
        "aiodns>=3.2.0",
        "jinja2>=3.1.4",
        "networkx>=3.3",
        "pydantic>=2.7.1",
        "pysnmp>=4.4.12",
        "pyvis>=0.3.2",
        "python-nmap>=0.7.1",
        "pyyaml>=6.0.1",
        "rapidfuzz>=3.9.1",
        "rich>=13.7.1",
        "rich-click>=1.7.4",
        "scapy>=2.5.0",
        "tqdm>=4.66.4",
    ],
    python_requires=">=3.9",
)
