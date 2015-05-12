import socket
import requests
import socks
import stem.process
import argparse
import os.path
import tempfile

from difflib import SequenceMatcher
from stem.descriptor.remote import DescriptorDownloader
from stem.util import term

SOCKS_PORT = 1339
TIMEOUT = 15

argparse = argparse.ArgumentParser()
argparse.add_argument("-u", "--url", dest="url", help="URL to be checked")
args = argparse.parse_args()

global url
global file
url = args.url

if url is None:
    url = "http://www.reddit.com/"
    print("URL was not specified, defaulting to " + url)

if url.startswith("https://"):
    print(term.format("Detected HTTPS connection, should be plaintext (HTTP)", term.Color.RED))

def get_clean():
    global r1
    socket.socket=temp
    r1 = requests.get(url)

def del_fp():
    if os.path.isfile("fp.txt"):
        print("fp.txt exists. Deleting...")
        os.remove("fp.txt")

def get_fps():
    print("Downloadning fresh fingerprints...")
    downloader = DescriptorDownloader(
            use_mirrors = True,
            timeout = 20,
    )
    query = downloader.get_server_descriptors()
    for desc in query:
        if desc.exit_policy.is_exiting_allowed():
            fp = open("fp.txt", "a")
            fp.write('{}\n'.format(desc.fingerprint))
            fp.close()

del_fp()
get_fps()

socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', SOCKS_PORT)
temp = socket.socket
socket.socket = socks.socksocket

def main():
    file = open("fp.txt", mode="r")
    for line in file.readlines():
        tor_process = None
        try:
            tor_process = stem.process.launch_tor_with_config(
            config = {
                      'SocksPort': str(SOCKS_PORT),
                      'ExitNodes': str(line),
                      "DataDirectory": tempfile.gettempdir() + os.pathsep + str(SOCKS_PORT)
            }, timeout=TIMEOUT)
            
            r2 = requests.get(url)
            tor_process.kill()
            get_clean()

            #Bor jag jamfora GZIP eller klartext?
            #if r2.headers['Content-Encoding'] == "gzip":
            #is_gzip()

            m = SequenceMatcher(None, r2.content, r1.content)
            ratio = m.ratio()
            ratio *= 100
            print(str(ratio) + " for fingerprint " + line)

        except Exception as e:
            print("Error: " + str(e) + " for " + line)
            if not tor_process is None:
                tor_process.kill()
        if not tor_process is None:
            tor_process.kill()

if __name__ == "__main__":
        main()

