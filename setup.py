from setuptools import setup

setup(
    name="daclsearch",
    version="1.0.0",
    description="Exhaustive search and flexible filtering of Active Directory ACEs",
    author="Maxime AWOUKOU",
    maintainer="Maxime AWOUKOU",
    python_requires=">=3.10",
    packages=[
        "filters",
        "filters.custom",
        "filters.merge",
        "filters.search",
        "daclsearch",
        "daclsearch.dump",
    ],
    package_data={"filters.custom": ["*.yaml"], "filters.merge": ["*.yaml"], "filters.search": ["*.yaml"]},
    install_requires=[
        "impacket>=0.12.0",
        "rich>=14.0.0",
        "PyYAML>=6.0.3",
        "winacl>=0.1.9",
        "InquirerPy>=0.3.4",
    ],
    entry_points={"console_scripts": ["daclsearch=daclsearch:main"]},
)
