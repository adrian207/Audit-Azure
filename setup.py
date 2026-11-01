from setuptools import setup, find_packages

setup(
    name="azure-audit",
    version="1.0.0",
    author="Adrian Johnson",
    author_email="adrian207@gmail.com",
    description="Azure security benchmark compliance checks with an API and dashboard",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/adrian207/Audit-Azure",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",


        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.11",
    install_requires=[
        "fastapi>=0.119.1",
        "pydantic>=2.12.3",
        "sqlalchemy>=2.0.44",
        "pyyaml>=6.0.3",
        "pytest>=9.0.3",
        "uvicorn>=0.38.0",
    ],
    extras_require={
        "dev": [
            "black>=23.11.0",
            "flake8>=6.1.0",
            "mypy>=1.7.1",
            "pytest-asyncio>=0.21.1",
            "pytest-cov>=4.1.0",
            "httpx>=0.25.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "audit-azure=api.main:main",
        ],
    },
    project_urls={
        "Documentation": "https://github.com/adrian207/Audit-Azure/tree/main/docs",
        "Source": "https://github.com/adrian207/Audit-Azure",
        "Bug Reports": "https://github.com/adrian207/Audit-Azure/issues",
    },
)