# setup.py
from setuptools import find_packages, setup


def read_requirements():
    with open("requirements.txt", "r") as fh:
        return [line.strip() for line in fh.readlines() if not (line.startswith("#") or len(line) == 0)]


setup(
  name='authlier-flask',
  version='1.0',
  py_modules=['authlier'],
)