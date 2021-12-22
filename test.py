from qwhois import whois
import sys

if __name__ == '__main__':
    url = sys.argv[1]
    ret = whois(url)
    print(ret)
