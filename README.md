# VyOS Scanner

<div align="center">
  
[![GitHub issues](https://img.shields.io/bitbucket/issues/danielcshn/vyos-scanner?style=for-the-badge)](https://github.com/danielcshn/vyos-scanner/issues)
[![GitHub watchers](https://img.shields.io/github/watchers/danielcshn/vyos-scanner?style=for-the-badge)](https://github.com/danielcshn/vyos-scanner/watchers)
[![GitHub forks](https://img.shields.io/github/forks/danielcshn/vyos-scanner?style=for-the-badge)](https://github.com/danielcshn/vyos-scanner/fork)
[![GitHub stars](https://img.shields.io/github/stars/danielcshn/vyos-scanner?style=for-the-badge)](https://github.com/danielcshn/vyos-scanner/stargazers)
[![License](https://img.shields.io/github/license/danielcshn/vyos-scanner?style=for-the-badge)](https://github.com/danielcshn/vyos-scanner/blob/main/LICENSE)
[![Language](https://img.shields.io/github/languages/top/danielcshn/vyos-scanner?style=for-the-badge)](https://github.com/danielcshn/vyos-scanner/search?l=python)
[![GitHub last commit](https://img.shields.io/github/last-commit/danielcshn/vyos-scanner?style=for-the-badge)](https://github.com/danielcshn/vyos-scanner/commits/main)

</div>

Forensics tool for VyOS. Search for suspicious properties and weak security points that need to be fixed on the router.

This tool’s functionalities include the following: 
- Get the version of the VyOS and map it to CVEs.
- Check for possible CVEs in installed packages.
- Check the Build is from trusted official sources.
- Check the use of default users and passwords.
- Check the use of default ports.
- Check the use of SSHGuard. 
- Check the use of Serial Console / Console-Server.
- Check command history.
- System Health Check (Disk / Memory / Uptime).

## Executing and arguments

This tool requires Python 3.8 or later. 

### Install required Python packages
`pip install -r requirements.txt`

### The arguments:
 **args**  | **Description**                                                                                                | **Must / Optional**
-----------| ---------------------------------------------------------------------------------------------------------------| -------------------
`-i`       | The tested VyOS IP address                                                                                     | Must
`-p`       | The tested VyOS SSH port                                                                                       | Optional
`-u`       | Username with admin Permissions                                                                                | Must
`-ps`      | Password of the given user name <br>(vyos password by default)                                                 | Optional
`-k`       | Filename of optional private key(s) and/or certs to try for authentication                                     | Optional
`-j`       | Print the results as json format <br>(prints txt format by default)                                            | Optional
`-c`       | Print a shortened text output focusing on recommendations and suspicious data                                  | Optional
`-ud`      | Update the CVE Json file <br>(the file is updated automatically if it hasn't been updated in the last 15 days) | Optional
`-sc`      | Skip CVE checks <br>(CVE testing will not be performed by version or by installed packages)                    | Optional

### Executing examples:
	 ./main.py -i 192.168.1.1 -u vyos
	 ./main.py -i 192.168.1.1 -p 22 -u vyos
	 ./main.py -i 192.168.1.1 -p 8020 -u vyos -ps vyos
	 ./main.py -i 192.168.1.1 -p 2080 -u vyos -ps vyos -j
	 ./main.py -i 192.168.1.1 -p 2280 -u vyos -ps vyos -c
	 ./main.py -i 192.168.1.1 -p 2280 -u vyos -ps vyos -c -sc
	 ./main.py -i 192.168.1.1 -p 2222 -u admin -ps 1234 -k 'C:\RSA\key_rsa'

## Legal Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.