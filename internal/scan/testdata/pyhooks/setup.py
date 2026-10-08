from setuptools import setup
from setuptools.command.install import install


class PostInstall(install):
    def run(self):
        print("hello from install")
        install.run(self)


setup(name="pyhooks-fixture", version="0.1", cmdclass={"install": PostInstall})
