import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

# 设置包的属性. 其他的就是一些引用的问题了.
# whois被别人使用了. 没有办法了. 改个名字.
setuptools.setup(
    # 扩展包名
    name="qwhois",
    # 版本.
    version="1.0.0",
    # 作者
    author="adolph",
    # 作者邮箱
    auth_email="yuan13036395508@gmail.com",
    # 简单描述
    descrition="whois lookup >>> 查询域名的whois信息",
    # 长描述
    long_description=long_description,
    # 描述文件格式
    long_description_content_type="text/markdown",
    # 指定对应的git仓库地址
    url="https://github.com/cqqgsafe/qwhois",
    # 指定包
    packages=setuptools.find_packages(),
    # 指定语言. 指定开源协议
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    # 指定python版本.
    python_requires='>=3.6',
    # 安装时. 安装依赖包.
    install_requires=['future', 'netaddr'],
    # 引入非python文件.
    include_package_data=True
)