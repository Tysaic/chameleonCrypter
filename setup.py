from setuptools import setup, find_packages

setup(

    name="Encrypter Cowboy",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'cryptography'
    ],
    entry_points={
        'console_scripts':[
            'one_crypter = crypter.one_crypter:main'
        ]
    },
    author="Isaac Valentino Méndez Linares",
    author_email="mendezlinaresi@protonmail.com",
    description="Encrypter cowboy is one line encrypte/decrypter tool to hidden and protect your files and folder easily",
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/Tysaic/encrypterCowboy/',
    license='MIT',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: Linux & Windows',
    ],
    python_requires='>=3.8',
)

