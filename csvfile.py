import csv, os, sys, re, codecs

# Use regex to determine column number. 
# Examples to parse for: 
# 	time: [A-Z][a-z0-9 ]+\d+:\d+:\d+
# 	date: \d{4}-\d{2}-\d{2}
# 	log: log:\d+
# 	ip address: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?
# 	msg: (Allow|Deny|Teardown|Breakdown|Built).*?$

regex_columns = { #number at the beginning of the key is for sorted purposes
	'1': ('date','\d{4}-\d{2}-\d{2}'),
	'2': ('log','log:\d+'),
	'3': ('time','[A-Z][a-z0-9 ]+\d+:\d+:\d+'),
	'4': ('ip_address','\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?'),
	'5': ('protocol','(TCP|UDP|ICMP)'),
	'6': ('decision','(Allow|Deny|Teardown|Breakdown|Built)'),
	'7': ('handshake','(FIN ACK|ACK|RST|dst)'),
	'8': ('interface','[ ]\w+$'),
	'9': ('msg','(Allow|Deny|Teardown|Breakdown|Built).*?$'),
}	

regex_lookup = { #number at the beginning of the key is for sorted purposes
	'date' : '\d{4}-\d{2}-\d{2}',
	'log' : 'log:\d+',
	'time' : '[A-Z][a-z0-9 ]+\d+:\d+:\d+',
	'ip_address' : '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d+)?',
	'protocol' : '(TCP|UDP|ICMP)',
	'decision' : '(Allow|Deny|Teardown|Breakdown|Built)',
	'handshake' : '(FIN ACK|ACK|RST|dst)',
	'interface' : '[ ]\w+$',
	'msg' : '(Allow|Deny|Teardown|Breakdown|Built).*?$',
}	

order = []

def fix_file_format(filename):
	f = open('tmp.txt','w',encoding='utf8')
	try: s = re.sub(r'(\d{4}-\d{2}-\d{2}.*?)\n',r'\g<1>',open(filename, encoding='utf16').read())
	except: s = re.sub(r'(\d{4}-\d{2}-\d{2}.*?)\n',r'\g<1>',open(filename, encoding='utf8').read())
	f.write(s)
	f.close()
	return
	
'''def file_format_is_funky(filename):
	contents = parse(filename)
	for each in contents:
		if each == '' or each == '\n':
			pass
		elif not re.match('\d{4}-\d{2}-\d{2}',each):
			return True
	return False'''
			
def determine_columns_from_first_line(contents):
	for each in contents:
		if re.match('\d{4}-\d{2}-\d{2}',each):
			row = each
			break
	headers = {}
	for nums in sorted(regex_columns):
		name,regex = regex_columns[nums]
		num_cols = len([string.group() for string in re.finditer(regex,row,flags=re.IGNORECASE)])
		if num_cols > 0:
			globals()['order'] = globals()['order'] + [name]
		for each in range(num_cols):
			headers[name] = 1 if name not in headers else headers[name] + 1
	return headers

def alter_to_from_ipaddresses(headers):
	if 'ip_address' in headers:
		headers[headers.index('ip_address')] = "from ip address"
		headers[headers.index('ip_address')] = "to ip address"
	if 'port' in headers:
		headers[headers.index('port')] = "from port"
		headers[headers.index('port')] = "to port"	
	return headers
	
def parse(f):
	contents = open(f,'r',encoding='utf8').read()
	if contents == '':
		return None
	return contents.split('\n')

def headers_to_array(headers):
	arr = []
	for header in order:
		for each in range(headers[header]):
			arr.append(header)
			if header == 'ip_address': # HARD CODED: header for port for each ip address 
				arr.append('port')
	return alter_to_from_ipaddresses(arr)

def write_csv(f, originalfile, contents, headers):
	pywriter = csv.writer(f, delimiter=',',lineterminator='\n')
	pywriter.writerow(headers_to_array(headers))
	for row in contents:
		arr = []
		prev = ""
		for header in order:
			if len([n for n in re.finditer(regex_lookup[header],row,flags=re.IGNORECASE)]) == 0:
				arr = arr + ['.']
			else:
				for string in re.finditer(regex_lookup[header],row,flags=re.IGNORECASE):
					s = string.group().strip()
					if s != prev:
						if header == 'ip_address':
							try: arr = arr + [[s[:s.index("/")]][0]]
							except: arr = arr + [s]
							try: arr = arr + [s[s.index('/')+1:]]
							except: arr = arr + ['.']
						else:
							arr = arr + [s]
					prev = s
		pywriter.writerow(arr)

from tkinter import Tk
from tkinter.filedialog import askopenfilename,asksaveasfile
from tkinter.messagebox import showerror,showinfo
import os

if __name__ == '__main__':
	Tk().withdraw()
	filename = askopenfilename()
	if filename == '':
		sys.exit()
		
	fix_file_format(filename)
	contents = parse('tmp.txt')

	if contents is None:
		showerror("ERROR", "Empty File Alert")
		sys.exit()

	f = asksaveasfile(mode='w', defaultextension='.csv')

	headers = determine_columns_from_first_line(contents)
	write_csv(f, filename, contents, headers)
	showinfo("COMPLETE","File conversion complete")