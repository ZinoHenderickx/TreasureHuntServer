import os
from typing import Optional
from fastapi import FastAPI, Response, File, UploadFile, Form
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import base64
from Crypto.Hash import SHA1, SHA256, SHA512, MD5
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import Salsa20

default_string_encoding = 'utf-8'
parent_dir_path = os.path.dirname(os.path.realpath(__file__))

app = FastAPI()
opdracht_8_bericht = "PlayStation 5"

app.mount("/static", StaticFiles(directory=parent_dir_path + "/static"), name="static")

def encode_base64_string(message: str, string_encoding: str = default_string_encoding):
    message_bytes = message.encode(string_encoding)
    return encode_base64_bytes(message_bytes)

def encode_base64_bytes(message: bytes):
    base64_bytes = base64.b64encode(message)
    base64_hex = base64_bytes.hex()
    base64_ascii = base64_bytes.decode('ascii')
    return base64_bytes, base64_hex, base64_ascii
    
def hash(file, hash_buffer):
    buffer_size = 65536  # 64 KB
    file.seek(0)

    while True:
        data = file.read(buffer_size)
        if not data:
            break
        hash_buffer.update(data)

    return hash_buffer

def hash_hexdigest(file, hash_buffer):
    return hash(file, hash_buffer).hexdigest()

def hex_encode(message: str):
    hex_text = '48616c6c6f'
    text_decode = bytes.fromhex(hex_text)
    text = text_decode.decode(encoding='utf_8')
    return hex_text, text_decode, text

class Opdracht2Body(BaseModel):
    nr1: str
    nr2: str
    nr3: str

class Opdracht5Body(BaseModel):
    sha512: str

class Opdracht6Body(BaseModel):
    relatieve_url: str

class Opdracht7Body(BaseModel):
    bericht_versleuteld: str
    sleutel: str
    nonce: str

class Opdracht8Body(BaseModel):
    bericht_versleuteld : str

fout_antwoord = Response(content='Fout antwoord!')

@app.get("/")
async def root():
    return Response(content=(
        'Welkom op de Build 3 schattenjacht 2020!'
        ' De opdrachten kan je steeds terugvinden op de "/opdrachtXX" paden, waarbij XX het nummer van de opdracht voorstelt.'
        ' De eerste opdracht vind je dus op het volgende pad: "/opdracht1".'
        ' Een eenvoudige GET request volstaat om aan de slag te gaan!'))

opdracht1_json = {
    "opdracht" : {
        "id" : 1,
        "beschrijving" : (
            "Plaats volgende regels in de juiste volgorde door ze via een POST request in de vorm van een JSON in te sturen voor de volgende opdracht."
            " Je plaatst elke regel als 'value' in de root van deze JSON en gebruikt telkens het rangnummer, voorafgaand door 'nr', als 'tag'."
            " Bijvoorbeeld {..., 'nr2' : 'Tweede regel', ...}. Denk eraan dat JSON steeds met dubbele quotes werkt!")
    },
    "regels" : [
        "Derde regel",
        "Eerste regel",
        "Tweede regel"
    ]
}

@app.get("/opdracht1")
async def opdracht1():
    return opdracht1_json

opdracht2_json = {
    "opdracht" : {
        "id" : 2,
        "beschrijving" : (
            "Je start met de string hieronder."
            " Vorm deze om naar bytes en maak daarbij gebruik van de bijhorende karakterset."
            " Stuur deze bytes vervolgens via het URL pad in voor de volgende opdracht."
            " Gebruik hiervoor een POST request."
            " Denk eraan dat URLs niet zomaar pure bytes toelaten: je zal ze bijvoorbeeld eerst moeten omvormen naar hexadecimale waarden (die je wel makkelijk als string kan sturen)."
            " Je URL zal er dus als volgt uitzien: .../opdracht3/JeHexadecimaleWaarde")
    },
    "string" : "opdracht 3",
    "karakterset" : "utf-8"
}

@app.post("/opdracht2")
async def opdracht2(body: Opdracht2Body):
    if body.nr1 == opdracht1_json['regels'][1] and body.nr2 == opdracht1_json['regels'][2] and body.nr3 == opdracht1_json['regels'][0]:
        return opdracht2_json
    else:
        return fout_antwoord

opdracht3_json = {
    "opdracht" : {
        "id" : 3,
        "beschrijving" : (
            "Doe nu hetzelfde voor de string hieronder, maar gebruik dit keer een base64 encodering in plaats van een hexadecimale encodering."
            " Van je resulterende bytes kan je een string maken door de ascii karakterset te gebruiken."
            " Je URL zal er dus als volgt uitzien: .../opdracht4/JeBase64WaardeAlsAsciiKarakters")
    },
    "string" : "opdracht 4 lijkt heel erg op opdracht 3",
    "karakterset" : "utf-8"
}

@app.post("/opdracht3/{hex_encoded}")
async def opdracht3(hex_encoded: str):
    value_string = opdracht2_json['string']
    value_bytes = value_string.encode(opdracht2_json['karakterset'])
    solution = value_bytes.hex()
    if hex_encoded == solution:
        return opdracht3_json
    else:
        return fout_antwoord

opdracht4_json = {
    "opdracht" : {
        "id" : 4,
        "beschrijving" : (
            "Bereken de hash van het bestand met onderstaande relatieve URL volgens de SHA512 methode"
            " en stuur hem in hexadecimaal formaat via een POST request in de vorm van een JSON in voor de volgende opdracht."
            " Je JSON zal er dus als volgt uitzien: {'sha512' : 'JeHexadecimaleHash'}")
    },
    "relatieve_url" : "/static/opdracht4"
}

@app.post("/opdracht4/{base64_encoded}")
async def opdracht4(base64_encoded: str):
    value_string = opdracht3_json['string']
    encoding_string = opdracht3_json['karakterset']
    _, _, solution = encode_base64_string(value_string, encoding_string)
    if base64_encoded == solution:
        return opdracht4_json
    else:
        return fout_antwoord

opdracht5_origineel_relatieve_url = '/static/opdracht5/applicatie_george.exe'

with open(parent_dir_path + opdracht5_origineel_relatieve_url, 'rb') as file:
    opdracht5_origineel_md5 = hash_hexdigest(file, MD5.new())

opdracht5_json = {
    "opdracht" : {
        "id" : 5,
        "beschrijving" : (
            "Je hebt een applicatie gedownload van het internet en wil die installeren op je computer."
            " Je vrienden hebben dezelfde applicatie gedownload, maar de .exe bestanden zijn niet hetzelfde."
            " Je loopt dus het risico om je computer te infecteren met malware van een derde partij..."
            " Gelukkig vermeldt de officiële website van de applicatie ook een MD5 checksum (zie hieronder)."
            " Gebruik deze checksum om na te gaan welke van onderstaande bestanden de echte applicatie voorstelt."
            " Het relatieve pad van het juiste bestand (er is er slechts één) stuur je via een POST request in de vorm van een JSON in voor de volgende opdracht."
            " Je JSON ziet er als volgt uit: {'relatieve_url' : '...'}")
    },
    "bestanden" : [
        {
            "relatieve_url" : "/static/opdracht5/applicatie_jos.exe"
        },
        {
            "relatieve_url" : "/static/opdracht5/applicatie_jef.exe"
        },
        {
            "relatieve_url" : "/static/opdracht5/applicatie_odilon.exe"
        },
        {
            "relatieve_url" : opdracht5_origineel_relatieve_url
        },
        {
            "relatieve_url" : "/static/opdracht5/applicatie_mariette.exe"
        },
        {
            "relatieve_url" : "/static/opdracht5/applicatie_ivonne.exe"
        }
    ],
    "md5_checksum" : opdracht5_origineel_md5
}

@app.post("/opdracht5")
async def opdracht5(body: Opdracht5Body):
    relatieve_url = opdracht4_json['relatieve_url']
    with open(parent_dir_path + relatieve_url, 'rb') as file:
        solution = hash_hexdigest(file, SHA512.new())
    if body.sha512 == solution:
        return opdracht5_json
    else:
        return fout_antwoord

opdracht6_json = {
    "opdracht" : {
        "id" : 6,
        "beschrijving" : (
            "Versleutel onderstaand bericht met de AES encryptietechniek."
            " Maak hiervoor gebruik van de EAX kettingmodus en verlies de bijhorende karakterset niet uit het oog."
            " Gebruik je eigen nonce en 256-bit sleutel."
            " Het versleuteld bericht stuur je samen met de nonce en sleutel in via een POST request in JSON-formaat voor de volgende opdracht."
            " Gebruik hexadecimale encodering voor het versturen van ruwe bits/bytes."
            " Je JSON ziet er als volgt uit: {'bericht_versleuteld' : '...', 'sleutel' : '...', 'nonce' : '...'}")
    },
    "bericht" : "Geheim bericht bestemd voor de docenten IoT aan de KdG",
    "karakterset" : "utf-8"
}

@app.post("/opdracht6")
async def opdracht6(body: Opdracht6Body):
    if body.relatieve_url == opdracht5_origineel_relatieve_url:
        return opdracht6_json
    else:
        return fout_antwoord

# Aanmaken publiek en privaat sleutelpaar
get_random_bytes(32)
plaintext = b'PlayStation 5'
secret = b'\x8d\xd4_\xcb\xd4W\xc5C\xa0{\xa72 \xb4\x11\xf9(\xfd\x00-?\x9fI\xc6\xf2NR\x9f\x97^h!'
cipher = Salsa20.new(key=secret)
msg = cipher.nonce + cipher.encrypt(plaintext)

key_hex = b'\x8d\xd4_\xcb\xd4W\xc5C\xa0{\xa72 \xb4\x11\xf9(\xfd\x00-?\x9fI\xc6\xf2NR\x9f\x97^h!'.hex()
msg_hex = b'\x0fO\xa3M\xfa\x1c\xf4b\xaf\x07\x8f\xe7\xda\xc0\xa2T\xd45\x81Aa'.hex()
nonce = b'7\x9f\x91\xf6$s\x97]'.hex()

print(nonce)


# Publieke sleutel (in bytes) omvormen naar HEX om in JSON te zetten hieronder



# Private sleutel bijhouden

opdracht7_json = {
    "opdracht" : {
        "id" : 7,
        "beschrijving" : (
            "Decrypteer het bijgevoegde bericht met de bijgevoegde publieke sleutel."
            "De key, nonce en het bericht staan in hex waarde."
            "Vergeet niet de nonce mee te sturen, deze heb je nodig om je code te vervoledigen"
            "{'bericht_versleuteld' : '...'}")
    },
    "bericht": "0f4fa34dfa1cf462af078fe7dac0a254d435814161",
    "publieke_sleutel" : "8dd45fcbd457c543a07ba73220b411f928fd002d3f9f49c6f24e529f975e6821",
    "nonce" : "379f91f62473975d"
}

@app.post("/opdracht7")
async def opdracht7(body: Opdracht7Body):
    try:
        key = bytes.fromhex(body.sleutel)
        required_key_length = 256 // 8
        if len(key) != required_key_length:
            return fout_antwoord
        nonce = bytes.fromhex(body.nonce)
        ciphertext_bytes = bytes.fromhex(body.bericht_versleuteld)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        plaintext_bytes = cipher.decrypt(ciphertext_bytes)
        plaintext = plaintext_bytes.decode(opdracht6_json['karakterset'])
        if plaintext == opdracht6_json['bericht']:
            return opdracht7_json
        else:
            return fout_antwoord
    except:
        return fout_antwoord
        
opdracht8_json = {
    "opdracht" : {
        "id" : 8,
        "beschrijving" : (
            "Proficiat u hebt gewonnen")
    },
}

@app.post("/opdracht8")
async def opdracht8(body: Opdracht8Body):
    if body.bericht_versleuteld == opdracht_8_bericht:
        return opdracht8_json
    else:
        return fout_antwoord