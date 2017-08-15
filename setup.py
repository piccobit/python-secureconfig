from setuptools import setup, find_packages

cmdclass = {}
ext_modules = []


setup(
    name="secureconfigparser",
    version="0.1.3a0",
    description="Configuration-oriented encryption toolkit to make "
                "secure config files simple",
    url="https://github.com/piccobit/secureconfigparser/",
    author="Naomi Most",
    author_email="naomi@nthmost.net",
    maintainer="HD Stich",
    maintainer_email="hd@stich.io",
    cmdclass=cmdclass,
    ext_modules=ext_modules,
    license="MIT",
    zip_safe=True,
    packages=find_packages(),
    install_requires=['cryptography', 'configparser'],
    )
