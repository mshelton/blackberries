from setuptools import setup, find_packages

setup(
    name='ThreatCentral',
    author='Bart Otten',
    version='1.0',
    author_email='bart.otten@hp.com',
    description='Threat Central',
    license='Apache 2.0',
    packages=find_packages('src'),
    package_dir={ '' : 'src' },
    zip_safe=False,
    package_data={
        '' : [ '*.gif', '*.png', '*.conf', '*.mtz', '*.machine' ] # list of resources
    },
    install_requires=[
        'canari',
        'requests',
        'tldextract',
    ],
    dependency_links=[
        # custom links for the install_requires
    ]
)
