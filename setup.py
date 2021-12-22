import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

# 设置包的属性. 其他的就是一些引用的问题了.
# whois被别人使用了. 没有办法了. 改个名字.
setuptools.setup(
    name="qwhois",
    version="0.0.1",
    author="adolph",
    auth_email="yuan13036395508@gmail.com",
    descrition="whois lookup >>> 查询域名的whois信息",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cqqgsafe/qwhois",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=['future', 'netaddr']
)