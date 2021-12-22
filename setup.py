from setuptools import setup

setup(name='ADExplorerSnapshot',
      version='1.0.0',
      description='AD Explorer Snapshot ingestor for BloodHound',
      author='Cedric Van Bockhaven, Marat Nigmatullin',
      author_email='cvanbockhaven@deloitte.nl, mnigmatullin@deloitte.nl',
      maintainer='Cedric Van Bockhaven',
      maintainer_email='cvanbockhaven@deloitte.nl',
      url='https://github.com/c3c/ADExplorerSnapshot.py',
      packages=['adexpsnapshot',
                'adexpsnapshot.parser',
      ],
      license='MIT',
      install_requires=['bloodhound>=1.1.1','dissect.cstruct>=2.0','frozendict'],
      classifiers=[
        'Intended Audience :: Information Technology',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
      ],
      entry_points= {
        'console_scripts': ['ADExplorerSnapshot.py=adexpsnapshot:main']
      }
)
