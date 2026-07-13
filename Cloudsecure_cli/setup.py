# setup.py
from setuptools import setup, find_packages
import os

def get_version():
    with open(os.path.join("cloudsecure", "__init__.py")) as f:
        for line in f:
            if line.startswith("__version__"):
                return line.split("=")[1].strip().replace('"', '').replace("'", "")
            

setup(
    name="cloudsecure-kaalitopi",  
    version=get_version(),
    author="Team Kaali Topi",
    description="Intelligent IaC Security Auditing for Modern Infrastructure",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/janithashri/cloud-secure-kaalitopi", 
    packages=find_packages(),
    install_requires=[
        "click",
        "rich",
        "reportlab",
        "requests"
    ],
    entry_points={
        'console_scripts': [
            'cloudsecure=cloudsecure.cli:main',
            'cloudsecure-kaalitopi=cloudsecure.cli:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.7',
)