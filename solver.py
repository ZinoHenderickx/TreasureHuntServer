##Auteur: Zino Henderickx
##Versie: 1.0

import requests
import base64
import hashlib

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

## URL zodat ik niet bij elke opdracht de url moet plaatsen.
URL = "http://185.115.217.205:1234"


## Opdracht 1
def opdracht1():

    opdracht =  {
            "nr1"   :   "Eerste regel",
            "nr2"   :   "Tweede regel",
            "nr3"   :   "Derde regel"
        }

    x = requests.post(URL + "/opdracht2", json=opdracht)

    print(x.text)


## Opdracht 2
def opdracht2():

    my_string = "opdracht 3"
    my_bytes = bytearray(my_string, "utf-8")

    x = requests.post(URL + "/opdracht3/" + my_bytes.hex())

    result = x.text
    print(result)


## Opdracht 3
def opdracht3():

    my_string = "opdracht 4 lijkt heel erg op opdracht 3"
    my_bytes = my_string.encode("utf-8")

    x = requests.post(URL + "/opdracht4/" + base64.b64encode(my_bytes).decode("utf-8"))

    result = x.text
    print(result)


## Opdracht 4
def opdracht4():

    input = 'Dit is een testbestand voor opdracht 4!'
    hash = hashlib.sha512( str( input ).encode("utf-8") ).hexdigest()

    sha512 =   {
            "sha512"   :   hash
        }

    x = requests.post(URL + "/opdracht5", json=sha512)

    print(x.text)


## Opdracht 5
def opdracht5():

    URL = "http://185.115.217.205:1234"

    checksum = "5f2a5c31a292cc46bacf546c961a8424"

    exes = ["/static/opdracht5/applicatie_jos.exe",
            "/static/opdracht5/applicatie_jef.exe",
            "/static/opdracht5/applicatie_odilon.exe",
            "/static/opdracht5/applicatie_george.exe",
            "/static/opdracht5/applicatie_mariette.exe",
            "/static/opdracht5/applicatie_ivonne.exe"]

    for file in exes:
        application_name = file[18:]
        hash_md5 = hashlib.md5()
        with open(application_name, 'rb') as open_file:
            content = open_file.read()
            hash_md5.update(content)
        if hash_md5.hexdigest() == checksum:
            right_exe = application_name

    x = requests.post(URL + "/opdracht6", json={"relatieve_url": right_exe})
    result = x.text


## Opdracht 6
def opdracht6():
    data = b'Geheim bericht bestemd voor de docenten IoT aan de KdG'
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    x = requests.post(URL + "/opdracht7", json={"bericht_versleuteld": ciphertext.hex(), "sleutel": key.hex(), "nonce": cipher.nonce.hex()})

    result = x.text
    print(result)


## main.py
if __name__ == "__main__":
    opdracht1()
    opdracht2()
    opdracht3()
    opdracht4()
    opdracht5()
    opdracht6()