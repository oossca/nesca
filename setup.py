from setuptools import setup, find_packages

setup(
    name="nesca",
    version="1.0.0",
    description="The legendary netstalking NEtwork SCAnner - Python CLI version",
    author="Converted from pantyusha/nesca",
    author_email="",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "paramiko>=3.0.0",
        "python-nmap>=0.7.1",
        "colorama>=0.4.4",
        "tqdm>=4.64.0",
        "urllib3>=1.26.0",
        "beautifulsoup4>=4.11.0",
        "lxml>=4.9.0",
    ],
    entry_points={
        "console_scripts": [
            "nesca=nesca.main:main",
        ],
    },
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)