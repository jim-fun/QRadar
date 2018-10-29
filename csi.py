#!/usr/bin/python
# 5/21/2015 - J. Meyer
# 10/29/2018 - J. Meyer
# Import Critical Stack indicators into QRadar reference list

import csv, urllib, urllib2, json
from IPy import IP

path_to_ca_pem = 'The CA PEM for your qradar SIEM'
qradar_fqdn = 'hostname.example.com'
qradar_api = 'https://' + qradar_fqdn + '/api/reference_data/sets/bulk_load/csi_'
api_key = 'your api key'
file_import = '/opt/critical-stack/frameworks/intel/master-public.bro.dat'
file_out_dir = '/var/www/lists/'
file_export = file_out_dir + 'csi_'
types = {'addr':[],'domain':[],'url':[],'file_hash':[],'indicator':[]}

with open(file_import, 'rU') as file1:
	reader = csv.reader(file1, dialect="excel-tab")
	for row in reader:
		try:
			row_name = row[1].lower()
			row_name = row_name.replace('intel::','')
			if row_name =='addr':
				IP(row[0])
			types[row_name].append(row)
		except:
			pass

for x in types.keys():
	if not 'indicator' in x:
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
				response = urllib2.urlopen(req,cafile=path_to_ca_pem).read()
			except:
				print "fail"
				raise
				pass
			z+=1

with open(file_export+'all', 'wb') as file2:
	out_put = csv.writer(file2, delimiter='\t', quoting=csv.QUOTE_NONE)
	out_put.writerow(['Indicator','Indicator Type','Source','Do Notice'])
	for x in types.keys():
	        if not 'indicator' in x:
			for y in types[x]:
				out_put.writerow(y)
 
