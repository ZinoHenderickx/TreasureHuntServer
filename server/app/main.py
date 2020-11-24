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

default_string_encoding = 'utf-8'
parent_dir_path = os.path.dirname(os.path.realpath(__file__))

app = FastAPI()

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
    bytes_text: str
    key_text: str
    bericht_hex: str
    bericht_versleuteld_hex : str

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
key = RSA.generate(1024)
private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().export_key()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
file_out.close()

print(public_key)
print(private_key)



# Publieke sleutel (in bytes) omvormen naar HEX om in JSON te zetten hieronder

print(public_key.hex())

# Private sleutel bijhouden


private_key = "2d2d2d2d2d424547494e205253412050524956415445204b45592d2d2d2d2d0a4d4949435777494241414b4267514458475941566a6e3376544c72464b7a6b6f316f632b4f305630516933436e7666694d6778676e6343506634424b2b5353430a6835617a67684d662f30496c73784b574857436c48722f3443396f664d3249352f5247365a564363315a4a4362486e7547567072384c536e594e316f615578700a6e654a4250492b65565465796538436375594c4c714d384b7a44324c726671394e3536384c6c6732356465554970494b795473783079447a59774944415141420a416f474148766a67576f2b5a547073576476626d2f334730666b6f6d6b575a49767a4949734d6453784f3679494349707a36485a6c30395377644a45557266520a386455524932573432586834736f7a4872457079657773586c73326d326b33647968645a4753593962696c7076596f336e64502f6b336c76614965452f432b440a49536674635742554b6c45474c5044775553697458353759766161314a6f4550586245496e6855454973496e4e4a4543515144655a697273514868745a344c5a0a39525743704d624869727657674748574b7075307a6354354b785442595051714749316733787a5437554e7056434a715563724975385845676b69302f6e434e0a6163727a55507466416b454139356b42326a4b4f6533786936507862792b6b466e76304f592b4765354b46556742446a2f356a48554755444e666f47414c314b0a695a51484969705a62313979384b717473566e3157532b5433414e6c6341754b66514a414a7972724b45783661526f7679313845654d7534546e4136674a352f0a6e493549656545376258364f327a664f434a506d596b636f3970483071316f7237586d574d79414f786e734466777a496d62386d4252416746514a414c304d330a78557a7451636b6d6f4536377678724742656c4d4f2b697669666a35786c427a465445327172503966756f78427963612b565157594945772f54393945302b680a5244396c78425a2b355071492f48425869514a41577174354f583068493970462f446c412f6e46437a4d525a6458503367675230745a47374b6d3741596939660a344f5a35665a794e754d356f50674c6a644e513859707537552b6d467a35506c70334c47484966372b773d3d0a2d2d2d2d2d454e44205253412050524956415445204b45592d2d2d2d2d"
opdracht7_json = {
    "opdracht" : {
        "id" : 7,
        "beschrijving" : (
            "Encrypteer het bijgevoegde bericht met de bijgevoegde publieke sleutel"
            "{'bericht_versleuteld_hex' : '...'}")
    },
    "bericht": "Geheim bericht aan Zino",
    "publieke_sleutel_hex" : "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d4947664d413047435371475349623344514542415155414134474e4144434269514b42675143306c3879446d6b5a68497248454c31785564395549454330780a7245394161584b46415763666a4d4b63716f4f7737656432534e344c6d4d4e54505176422f534b4f4f55394c4b6677374b45316b3952756e37735439565034500a6c764a526a33463755536f666d317379516b70737063504a753851636e616a51474173366c6b4830377a4d765445664b45366f514e7954346136694e6a4c4f6e0a3966534164466b794e6e55772f302b4671774944415141420a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d"
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
    try:
        # je krijgt hier versleuteld bericht binnen
        # bericht_versleuteld_hex = print(body.bericht_hex)

        # bericht is HEX, omvormen naar bytes alvorens te gebruiken
        bytes_versleuteld = bytes.fromhex(body.bericht_hex)

        # versleuteld bericht decrypteren met private sleutel die je hierboven opgeslagen hebt
        cipher_aes = AES.new(private_key, AES.MODE_EAX)
        bytes_versleuteld = cipher_aes.decrypt_and_verify()
        print(bytes_versleuteld.decode("utf-8"))

        # checken of resultaat overeenkomt met origineel bericht (denk eraan dat resultaat bytes zijn, dus nog decoderen naar string)
        if bytes_versleuteld == cipher_aes.decrypt(body.bytes_text):
            return opdracht8_json
        else:
            return fout_antwoord
    except:
        return fout_antwoord
