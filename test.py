import requests
from bs4 import BeautifulSoup
import ipaddress
import re

# page=requests.get('https://siterankdata.com/shazilss')
# soup=BeautifulSoup(page.content,'html.parser')
# try:
#    res=soup.find('h1',class_="font-extra-bold m-t-xl m-b-xs text-success")
#    if res is None:
#
# print(int(soup.find('h1',class_="font-extra-bold m-t-xl m-b-xs text-success").string.strip()))
y = [[]]
url_for_rank = "https://siterankdata.com/google.net"
page = requests.get(url_for_rank)
soup = BeautifulSoup(page.content, 'html.parser')
rank = ''
# try:
#    frank=soup.find('h1',class_="font-extra-bold m-t-xl m-b-xs text-success").string.split(',')
#    for ra in frank:
#       rank=rank+ra
# except Exception:
#    rank='10000000'
# rank=int(rank)
# count = 0
# dn="192.168.1.5"
# flag=1
# try:
#     ipaddress.ip_address(dn)
# except ValueError:
#     flag=0
dn="yahoo.com.edu/hak@ma@kas"
count=dn.count('.')
y[0].append(count)
print(y)
