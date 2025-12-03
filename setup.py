from setuptools import setup, find_packages

setup(
    name="terminal-notes-vault",
    version="0.1.0",
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'vault=src.cli:main',
        ],
    },
    install_requires=[
        # No external dependencies as per requirements
    ],
    author="adnan, prem",
    description="A terminal-based secure notes vault (Demo)",
)
