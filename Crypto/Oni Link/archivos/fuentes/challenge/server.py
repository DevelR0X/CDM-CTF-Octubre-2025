from Crypto.Cipher import ChaCha20

import os

FLAG = os.getenv("GZCTF_FLAG", "CDM{73571nG_fl4g!}")

class OniLink:
    def __init__(self, debug: bool = True):
        self.keygen()

        self.debug = debug

    def keygen(self):
        self.key   = os.urandom(32)
        self.nonce = os.urandom(12)
    
    def encrypt(self, data: bytes):
        cipher = ChaCha20.new(key = self.key, nonce = self.nonce)
        return cipher.encrypt(data).hex()
    
    def decrypt(self, data: str):
        data = bytes.fromhex(data)
        cipher = ChaCha20.new(key = self.key, nonce = self.nonce)
        return cipher.decrypt(data).decode()

    def execute(self, data: str):
        command = self.decrypt(data)

        if   command == "ACCESS_GRANTED:INITIALIZATION_COMPLETE": return self.encrypt(b"ACK")
        elif command == "ACCESS_GRANTED:NONCE":                   return self.encrypt(self.nonce)
        elif command == "ACCESS_GRANTED:KEY":                     return self.encrypt(self.key)
        elif command == "ACCESS_GRANTED:RESEED":                  self.keygen()
        elif command == "ACCESS_GRANTED:ENGAGE":                  return self.encrypt(FLAG.encode())
        else:                                                     return self.encrypt(b"NACK")

def main():
    link = OniLink()

    if link.debug == True:
        print(f"Debug mode enabled: {link.encrypt(b'ACCESS_GRANTED:INITIALIZATION_COMPLETE')}")  

    menu = """
    Terminal de comunicación de Kuro-Oni.

    Les hemos hecho llegar la llave maestra a sus
    correos electrónicos. Si la pierden, no podrán
    comunicarse por este portal.

    Recuerden validar su llave maestra contra el
    comando de debug.
    """ 

    print(menu)

    while True:
        encrypted_command = input('> ')

        command = link.execute(encrypted_command)

        print(command)

if __name__ == '__main__':
    main()