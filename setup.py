from setuptools import setup, find_packages

setup(
    name="sea-otter",
    version="1.0.0",
    description="面向新一代 AI 编程工具与 Agent CLI 的精细化清理与体检工具",
    author="Sea-Otter Contributors",
    author_email="dev@sea-otter.dev",
    url="https://github.com/milong/sea-otter",
    packages=find_packages(),
    package_data={
        "sea_otter": [
            "rules/*.yaml",
            "schema/*.json"
        ]
    },
    include_package_data=True,
    install_requires=[
        "pyyaml>=5.3"
    ],
    entry_points={
        "console_scripts": [
            "sea-otter=sea_otter.cli:main",
        ],
    },
    python_requires=">=3.8",
)
