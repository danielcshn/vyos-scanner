# VyOS Scanner

Forensics tool for VyOS. Search for suspicious properties and weak security points that need to be fixed on the router.

This tool’s functionalities include the following: 
- Get the version of the VyOS and map it to CVEs 
- Check for possible CVEs in installed packages
- Verify that the Built comes from reliable sources

## Executing and arguments

This tool requires Python 3.8 or later. 

### Install required Python packages
`pip install -r requirements.txt`

### The arguments:
 **args**  | **Description**							                                                                | **Must / Optional**
-----------| -----------------------------------------------------------------------------------------------------------| -------------------
`-i`       | The tested VyOS IP address                                                                                 | Must
`-p`       | The tested VyOS SSH port                                                                                   | Optional
`-u`       | Username with admin Permissions                                                                            | Must
`-ps`      | Password of the given user name (vyos password by default)                                                 | Optional
`-j`       | Print the results as json format (prints txt format by default)                                            | Optional
`-c`       | Print a shortened text output focusing on recommendations and suspicious data                              | Optional
`-ud`      | Update the CVE Json file (the file is updated automatically if it hasn't been updated in the last 15 days) | Optional

### Executing examples:
	 ./main.py -i 192.168.1.1 -u vyos
	 ./main.py -i 192.168.1.1 -p 22 -u vyos
	 ./main.py -i 192.168.1.1 -p 8020 -u vyos -ps vyos
	 ./main.py -i 192.168.1.1 -p 2080 -u vyos -ps vyos -J

