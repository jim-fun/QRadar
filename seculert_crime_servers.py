#!/usr/bin/python
# J. Meyer - 5/21/2015
# J. Meyer - 10/29/2018
# Description: Seculert import into reference lists

#imports
import csv, urllib, urllib2, json
from IPy import IP

#variables
qradar_ca_pem = 'path to CA PEM for QRadar'
qradar_fqdn = 'hostname.example.com'
seculert_key = "insert your seculert key"
url="https://api.seculert.com/CrimeServers?api_key=" + seculert_key
qradar_api = 'https://' + qradar_fqdn + '/api/reference_data/sets/bulk_load/seculert_'
api_key = 'QRadar API key'
file_out_dir = '/var/www/lists/'
types = {'urls':[],'ips':[]}

#pull data
data = json.load(urllib2.urlopen(url))

#create full file
with open(file_out_dir+"seculert.csv", "wb") as file:
	csv_file = csv.writer(file)
	csv_file.writerow(["threat-type-id","threat-type-name","url","name","ip-address","first-seen","last-seen"])
	for item in data['crime-servers']:
		csv_file.writerow([item['threat-type-id'],item['threat-type-name'],item['url'],item['name'],item['ip-address'],item['first-seen'],item['last-seen']])

#prepare data for reference set
for item in data['crime-servers']:
	if item['url'] is not None:
		types['urls'].append([item['url']])
	if item['ip-address'] is not None:
		types['ips'].append([item['ip-address']])

for x in types.keys():
	a = []
	i = 0
	z = 0
	for y in types[x]:
		a.append(y[0])
	b = list(set(a))
	b.sort()
	url = qradar_api + x
	lb = len(b)								# length of b
	hmb = lb/5000								# how many times b can be devided by 5000
	while (z <= hmb):
		i1 = z*5000
		i2 = z*5000+5000
		req = urllib2.Request(url)
		req.add_header('SEC', api_key)
		req.add_header('Content-Type', 'application/json')
		req.add_data(json.dumps(b[i1:i2]))
		try:
			response = urllib2.urlopen(req,cafile=qradar_ca_pem).read()
		except:
			print "failed"
			raise
			pass
		z+=1
