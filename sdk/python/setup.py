from setuptools import setup, find_packages

setup(
    name="synthegria",
    version="1.0.0",
    description="Official Python SDK for the Synthegria SIEM log ingestion API.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Synthegria Platform Team",
    author_email="platform@synthegria.io",
    url="https://github.com/haskopavol-hash/synthegria-siem",
    packages=find_packages(),
    python_requires=">=3.11",
    install_requires=[],
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: System :: Logging",
        "Intended Audience :: Developers",
    ],
    keywords=["siem", "security", "logging", "anomaly-detection", "synthegria"],
)
