import requests
from bs4 import BeautifulSoup
import hashlib

url = 'http://206.189.117.48:30697/'
req = requests.session()

# get request too the webpage and parse out the h3 tag with Beautiful Soup
getx = req.get(url)
bsh = BeautifulSoup(getx.text, 'html.parser')
string2hash = bsh.select('h3')[0].text.strip()

# Hash the string
hashstring = hashlib.md5(string2hash.encode('utf-8')).hexdigest()

# Post the hashed string back to the server
hash = {'hash': hashstring}
x2 = req.post(url, data = hash)

# Print the webserver response
print(x2.text)

