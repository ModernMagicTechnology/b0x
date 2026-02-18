#!/usr/bin/env python
from setuptools import (
    find_packages,
    setup,
)

extras_require = {}

with open("./README.md") as readme:
    long_description = readme.read()


setup(
    name="web3b0x",
    version="0.2",
    description="""b0x: Tiny crypto key lockbox for chat based AI agent such as OpenClaw or Nanobot""",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="0xKJ",
    author_email="kernel1983@gmail.com",
    url="https://github.com/w3connect/b0x",
    include_package_data=True,
    install_requires=[
        "web3>=6.0.0",
        "tornado>=6.0.0",
        "pyotp>=2.9.0",
        "qrcode>=8.2",
    ],
    python_requires=">=3.8, <4",
    extras_require=extras_require,
    py_modules=["b0x", "web3b0x"],
    license="MIT",
    zip_safe=False,
    keywords="ethereum",
    packages=find_packages(exclude=["scripts", "scripts.*", "tests", "tests.*"]),
)