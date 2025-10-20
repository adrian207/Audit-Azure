from setuptools import setup, find_packages

setup(
    name="azure-audit",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.119.1",
        "pydantic>=2.12.3",
        "sqlalchemy>=2.0.44",
        "pyyaml>=6.0.3",
        "pytest>=8.4.2",
        "uvicorn>=0.38.0",
    ],
)