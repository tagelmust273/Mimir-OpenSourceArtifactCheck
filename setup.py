from setuptools import setup, find_packages

setup(
    name="osint-bot",
    version="1.0.0",
    description="OSINT Artifact Analyzer Telegram Bot",
    author="TamirTarchokov aka tagelmust",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.11",
    install_requires=[
        line.strip() for line in open("requirements.txt").readlines()
    ],
)
