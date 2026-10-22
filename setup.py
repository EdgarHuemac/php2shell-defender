from setuptools import setup, find_packages

setup(
    name="php2shell-defender",
    version="1.0.0",
    description=(
        "Defensive hardening auditor and passive version fingerprinter "
        "for the PHP2Shell advisory. No exploit or probing logic."
    ),
    packages=find_packages(include=["php2shell_defender", "php2shell_defender.*"]),
    python_requires=">=3.10",
    install_requires=[
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "php2shell-defender=php2shell_defender.cli:main",
            "php2shell-defender-fleet=php2shell_defender.fleet:main",
        ],
    },
)
