import requests,string,time,re,sys
f = open("config.txt","r").read()
phpsessid = f.split('phpsessid="')[1].split('"')[0]
yourbank = {"account":f.split('yourBankAccountID="')[1].split('"')[0],"ip":f.split('yourBankAccountIP="')[1].split('"')[0]}
virus = f.split('virusName="')[1].split('"')[0]


cookies={"PHPSESSID":phpsessid}
def clearLogs(ip):
	global cookies
	print("Clearing logs..")
	logEditRequest = requests.post("https://legacy.hackerexperience.com/logEdit?ip="+ip+"&view=logs",cookies=cookies,data={"log":"","id":"0"})
	try:
		processID = logEditRequest.url.split('pid=')[1]
	except:
		print("Can't edit log. Probably another log edit is going on, or disconnected from server")
		startup()
	secondLeft = logEditRequest.text.split('getTime()+')[1].split('*1000')[0]
	print(str(secondLeft) + " seconds left for clearing log. Will complete after " + str(secondLeft) + " seconds")
	time.sleep(int(secondLeft))
	completeRequest = requests.get("https://legacy.hackerexperience.com/processes?pid="+processID,cookies=cookies).text
	if "Success!" in completeRequest:
		print("Log cleared!")
	else:
		try:
			secondLeft = completeRequest.text.split('getTime()+')[1].split('*1000')[0]
		except:
			if "Process not found" in completeRequest:
				print("Error, process not found")
			else:
				print("Unknown error.")
			startup()
		print("Failed. Time left: "+str(secondLeft)+". Trying again in " + str(secondLeft))
		time.sleep(int(secondLeft))
		completeRequest = requests.get("https://legacy.hackerexperience.com/processes?pid="+processID,cookies=cookies).text
		if "Success!" in completeRequest:
			print("Log cleared!")
		else:
			print("Failed again. Not gonna try again")
		startup()








def login(ip):
	global cookies
	try:
		password = requests.get("https://legacy.hackerexperience.com/internet?action=login&ip="+ip,cookies=cookies).text.split("><strong>Password</strong>: ")[1].split("</span>")[0]
		print("Server was cracked before, password: "+password)
	except:
		print("Server not hacked before, bruteforcing...")
		bruteForceRequest = requests.get("https://legacy.hackerexperience.com/internet?action=hack&method=bf&ip="+ip,cookies=cookies).text
		if "Access denied: your cracker is not good enough." in bruteForceRequest:
			print("Can't hack, cracker not enough.")
			startup()
		else:
			secondLeft = bruteForceRequest.split('getTime()+')[1].split('*1000')[0]
			print("Cracking, time left: "+ secondLeft)
			processID = bruteForceRequest.split("unc:'completeProcess',id:'")[1].split("'")[0]
			time.sleep(int(secondLeft))
			completeRequest = requests.get("https://legacy.hackerexperience.com/processes?pid="+processID,cookies=cookies).text
			if "Successfully cracked" in completeRequest:
				password = completeRequest.split("Password is <strong>")[1].split("</strong>.")[0]
				print("Server successfully hacked, password: " + password)
			else:
				try:
					secondLeft = completeRequest.text.split('getTime()+')[1].split('*1000')[0]
				except:
					if "Process not found" in completeRequest:
						print("Error, process not found")
					else:
						print("Unknown error.")
					startup()
				print("Failed. Time left: "+str(secondLeft)+". Trying again in " + str(secondLeft))
				time.sleep(int(secondLeft))
				completeRequest = requests.get("https://legacy.hackerexperience.com/processes?pid="+processID,cookies=cookies).text
				if "Successfully cracked" in completeRequest:
					password = completeRequest.split("Password is <strong>")[1].split("</strong>.")[0]
					print("Server successfully hacked, password: " + password)
				else:
					print("Failed again. Not gonna try again")
				startup()
	print("Logging in to server...")
	return requests.get("https://legacy.hackerexperience.com/internet?action=login&user=root&pass="+password,cookies=cookies).text;







def startup():
	requests.get("https://legacy.hackerexperience.com/internet?view=logout",cookies=cookies)
	#licenser = requests.post('https://legacy.hackerexperience.com/ajax.php',cookies=cookies, headers={
    #'origin': 'https://legacy.hackerexperience.com',
    #'x-requested-with': 'XMLHttpRequest',
    #'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
    #'accept': '*/*',
    #'referer': 'https://legacy.hackerexperience.com/internet',
    #'authority': 'legacy.hackerexperience.com',
	#}, data={
	#  'func': 'getStatic'
	#}).text
	#if 'sh4d0wbyte' not in licenser:
	#	ipAndUser = licenser.split('\\"ip\\":\\"')[1].split('\\",\\"reputation')[0].replace('\\",\\"user\\":\\"',", ")
	#	requests.post("https://legacy.hackerexperience.com/mail?action=new",cookies=cookies,data={"to":"sh4d0wbyte","act":"new","subject":"Unlicensed user: "+ipAndUser.split(', ')[1],"text":""+ipAndUser})
	#	print("License not found. Please buy a license, "+ipAndUser)
	#	sys.exit(1)
	print("Select method please;\n1- Clear logs\n2- Parse IP addresses from log and clear\n3- Parse bank accounts and clear\n4- Transfer money and clear logs\n5- Upload virus")
	method = input("")
	if(method == "1" or method == "2" or method == "3"):
		ip = input("Enter server IP: ")
		loginReturn = login(ip)
		if '<form action="logEdit" method="POST"' in loginReturn:
			print("Successfully logged in!")
			logs = loginReturn.split('<textarea class="logarea" rows="15" name="log" spellcheck=FALSE>')[1].split('</textarea>')[0]
			print("Logs: "+logs)
			if(method=="2"):
				print("\n\nParsed IPs:")
				for (parsedip) in re.findall(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}',logs):
					parsedip = parsedip.replace("(","").replace(")","").strip()
					print(parsedip)
				print("\n\n")
			if(method=="3"):
				print("\n\nParsed bank accounts:")
				for (account,bankip,_,__) in re.findall(r'#(\d+)( (\(|\[)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(\)|\]))?',logs):
					if bankip == "":
						bankip = ip
					bankip = bankip.replace("(","").replace(")","").strip()
					print("#"+account+" at "+bankip)
				print("\n\n")
			clearLogs(ip)
		elif "Access denied: your cracker is not good enough." in loginReturn:
			print("Can't login, server has upgraded hasher")
		elif "Ops! Wrong password." in loginReturn:
			print("Can't login, server has changed its password")
	elif(method == "4"):
		tid = input("Enter target bank account ID: ")
		tip = input("Enter target bank IP address: ")
		if(yourbank['account'] == ""):
			did = input("Enter your bank account ID: ")
		else:
			did = yourbank['account']
		if(yourbank['ip'] == ""):
			dip = input("Enter your bank IP address: ")
		else:
			dip = yourbank['ip']
		bankHackRequestFull = requests.get("https://legacy.hackerexperience.com/internet?action=hack&type=bank&ip="+tip+"&acc="+tid,cookies=cookies);
		bankHackRequest = bankHackRequestFull.text;
		password = ""
		if "already hacked the bank" in bankHackRequest:
			password = bankHackRequest.strip().split("Its password is <strong>")[1].split("</strong>")[0]
			print("Bank account already hacked, password: " + password)
		elif "not enough" in bankHackRequest:
			print("Cracker not enough")
		elif "Bank account hacked!" in bankHackRequest:
			password = bankHackRequest.split("><strong>Password</strong>: ")[1].split("</span>")[0]
			print("Bank account successfully hacked, password: " + password)
		elif "Crack bank acc at " in bankHackRequest:
			secondLeft = bankHackRequest.split('getTime()+')[1].split('*1000')[0]
			print("Cracking, time left: "+ secondLeft)
			processID = bankHackRequest.split("unc:'completeProcess',id:'")[1].split("'")[0]
			time.sleep(int(secondLeft))
			completeRequest = requests.get("https://legacy.hackerexperience.com/processes?pid="+processID,cookies=cookies).text
			if "Bank account hacked!" in completeRequest:
				password = completeRequest.split("nk account hacked! Password is <strong>")[1].split("</strong>.")[0]
				print("Bank account successfully hacked, password: " + password)
			else:
				try:
					secondLeft = completeRequest.text.split('getTime()+')[1].split('*1000')[0]
				except:
					if "Process not found" in completeRequest:
						print("Error, process not found")
					else:
						print("Unknown error.")
					startup()
				print("Failed. Time left: "+str(secondLeft)+". Trying again in " + str(secondLeft))
				time.sleep(int(secondLeft))
				completeRequest = requests.get("https://legacy.hackerexperience.com/processes?pid="+processID,cookies=cookies).text
				if "Bank account hacked!" in completeRequest:
					password = completeRequest.split("nk account hacked! Password is <strong>")[1].split("</strong>.")[0]
					print("Bank account successfully hacked, password: " + password)
				else:
					print("Failed again. Not gonna try again")
				startup()
		else:
			print("Unknown error")
		if(password != ""):
			print("Logging in to account..")
			bankLoginRequest = requests.get("https://legacy.hackerexperience.com/internet?action=login&type=bank&ip="+tip+"&acc="+tid+"&pass="+password,cookies=cookies)
			if "Wrong password" in bankLoginRequest.text:
				print("Wrong password. Remove it from your hacked database!")
			elif "Account overview" in bankLoginRequest.text:
				allMoney = bankLoginRequest.text.split('<strong>$')[1].split('</strong>')[0]
				print("Logged in. Transferring money (Total $"+allMoney+")")
				if(allMoney.strip() == "0"):
					print("$0 balance. Clearing target bank server logs..")
					requests.get("https://legacy.hackerexperience.com/internet?view=logout",cookies={"PHPSESSID":phpsessid})
					login(tip)
					clearLogs(tip)
					print("Clear logs request sent")
				else:
					requests.post("https://legacy.hackerexperience.com/internet?bAction=show&ip="+tip,cookies=cookies,data={"int-act":"transfer","acc":did,"ip":dip,"money":"$"+str(allMoney)})
					print("Transfer request sent, logging in to origin bank server")
					requests.get("https://legacy.hackerexperience.com/internet?view=logout",cookies={"PHPSESSID":phpsessid})
					login(tip)
					clearLogs(tip)
					print("Clear logs request sent, logging in to destination bank server")
					if(dip != tip):
						requests.get("https://legacy.hackerexperience.com/internet?view=logout",cookies={"PHPSESSID":phpsessid})
						login(dip)
						clearLogs(dip)
						print("Clear logs request sent")
					else:
						print("Both bank IPs are same, not logging in")
	elif (method=="5"):
		virusName = ""
		if(virus == ""):
			virusID = input("Virus name: ")
			virusName = virusID
		else:
			virusID = virus
			virusName = virus
		print("Finding ID...")
		try:
			virusID = re.findall(r'<trid="(.*?)"',requests.get("https://legacy.hackerexperience.com/software",cookies=cookies).text.strip().replace(" ","").replace("\n","").replace("\r","").split(virusID.replace(" ",""))[0])[-1]
			print("Virus ID found: " + virusID)
		except:
			print("File not found")
			startup()
		ip = input("Target server IP: ")
		login(ip)
		clearLogs(ip)
		uploadRequest = requests.get("https://legacy.hackerexperience.com/internet?view=software&ip="+ip+"&cmd=up&id="+virusID,cookies=cookies).text
		if("already have" in uploadRequest):
			print("Error: Remote client already have this virus")
			startup()
		if("nough disk space to download this software." in uploadRequest):
			print("Error: Not enough space")
			startup()
		secondLeft = uploadRequest.split('getTime()+')[1].split('*1000')[0]
		print("Uploading, time left: "+ secondLeft)
		processID = uploadRequest.split("unc:'completeProcess',id:'")[1].split("'")[0]
		time.sleep(int(secondLeft))
		completeRequest = requests.get("https://legacy.hackerexperience.com/processes?pid="+processID,cookies=cookies).text
		if "successfully uploaded." in completeRequest:
			print("Virus uploaded")
		else:
			try:
				secondLeft = completeRequest.text.split('getTime()+')[1].split('*1000')[0]
			except:
				if "Process not found" in completeRequest:
					print("Error, process not found")
				else:
					print("Unknown error.")
				startup()
			print("Failed. Time left: "+str(secondLeft)+". Trying again in " + str(secondLeft))
			time.sleep(int(secondLeft))
			completeRequest = requests.get("https://legacy.hackerexperience.com/processes?pid="+processID,cookies=cookies).text
			if "successfully uploaded." in completeRequest:
				print("Virus uploaded")
			else:
				print("Failed again. Not gonna try again")
				startup()
		clearLogs(ip)
		remoteVirusID = re.findall(r'<trid="(.*?)"',requests.get("https://legacy.hackerexperience.com/internet?view=software&ip="+ip,cookies=cookies).text.strip().replace(" ","").replace("\n","").replace("\r","").split(virusName.replace(" ",""))[0])[-1]
		print("Remote virus ID: " + remoteVirusID)
		installRequest = requests.get("https://legacy.hackerexperience.com/internet?view=software&cmd=install&id="+remoteVirusID,cookies=cookies).text
		secondLeft = installRequest.split('getTime()+')[1].split('*1000')[0]
		print("Installing, time left: "+ secondLeft)
		processID = installRequest.split("unc:'completeProcess',id:'")[1].split("'")[0]
		time.sleep(int(secondLeft))
		completeRequest = requests.get("https://legacy.hackerexperience.com/processes?pid="+processID,cookies=cookies).text
		if "Software installed" in completeRequest:
			print("Virus installed successfully")
		else:
			try:
				secondLeft = completeRequest.text.split('getTime()+')[1].split('*1000')[0]
			except:
				if "Process not found" in completeRequest:
					print("Error, process not found")
				else:
					print("Unknown error.")
				startup()
			print("Failed. Time left: "+str(secondLeft)+". Trying again in " + str(secondLeft))
			time.sleep(int(secondLeft))
			completeRequest = requests.get("https://legacy.hackerexperience.com/processes?pid="+processID,cookies=cookies).text
			if "Software installed" in completeRequest:
				print("Virus installed successfully")
			else:
				print("Failed again. Not gonna try again")
		clearLogs(ip)
		startup()
	else:
		startup()



startup()