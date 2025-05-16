from setuptools import setup, find_packages

setup(
    name="ddos_protection_mvp",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        'flask>=3.0.0',
        'numpy>=1.26.0',
        'scikit-learn>=1.3.0',
        'scapy>=2.5.0',
        'pyyaml>=6.0.0',
    ],
    entry_points={
        'console_scripts': [
            'ddos-protect=app.main:main',
        ],
    },
    include_package_data=True,
    package_data={
        'app': ['web/templates/*.html', 'web/static/*'],
    },
    python_requires='>=3.13.0',
)