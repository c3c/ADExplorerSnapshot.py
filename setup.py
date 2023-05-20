from setuptools import setup
import site, sys

site.ENABLE_USER_SITE = "--user" in sys.argv[1:]

setup(name='ADExplorerSnapshot',
      version='1.0.0',
      description='ADExplorerSnapshot.py is an AD Explorer snapshot parser. It is made as an ingestor for BloodHound, and also supports full-object dumping to NDJSON.',
      author='Cedric Van Bockhaven',
      author_email='cedric@cedric.ninja',
      maintainer='Cedric Van Bockhaven',
      maintainer_email='cedric@cedric.ninja',
      url='https://github.com/c3c/ADExplorerSnapshot.py',
      packages=['adexpsnapshot',
                'adexpsnapshot.parser',
      ],
      license='MIT',
      install_requires=['bloodhound>=1.6.1','dissect.cstruct>=2.0','frozendict','requests','pwntools>=4.5.0','certipy-ad>=4.4.0'],
      classifiers=[
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: Science/Research',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Topic :: Security'
      ],
      entry_points= {
        'console_scripts': ['ADExplorerSnapshot.py=adexpsnapshot:main']
      },
      python_requires='>=3.6'
)
