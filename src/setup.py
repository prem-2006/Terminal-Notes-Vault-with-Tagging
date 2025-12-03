from setuptools import setup, find_packages

setup(
    name="terminal_vault",
    version="0.1.0",
    description="A local password tool and policy checker (Demo)",
    author="Antigravity",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "vault=terminal_vault.cli.main:main",
        ],
    },
    python_requires=">=3.8",
)
