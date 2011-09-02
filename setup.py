from setuptools import setup, find_packages

from treestatus import version

setup(name='treestatus',
      version=".".join(map(str, version)),
      description="Mozilla Tree Status App",
      classifiers=[
      ],
      keywords='',
      author='Chris AtLee',
      author_email='chris@atlee.ca',
      packages=find_packages(exclude=['ez_setup']),
      install_requires=[
          'setuptools',
          'simplejson',
          'SQLAlchemy',
          'repoze.who',
          'pastescript',
          'python-memcached',
          'flask',
          ],
      entry_points="""
            # -*- Entry points: -*-
            [paste.app_factory]
            main = treestatus.app:wsgiapp

            [paste.app_install]
            main = paste.script.appinstall:Installer
            """,
      )
