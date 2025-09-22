from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import os

FLAG = os.getenv("GZCTF_FLAG", "CDM{73571nG_fl4g!}")

class Cipher:
    def __init__(self):
        self.key = os.urandom(16)
    
    def encrypt(self, data: str):
        cipher = AES.new(self.key, AES.MODE_ECB)
        return cipher.encrypt(pad(data.encode(), 16)).hex()
    
    def decrypt(self, data: str):
        data = bytes.fromhex(data)
        cipher = AES.new(self.key, AES.MODE_ECB)
        return unpad(cipher.decrypt(data), 16).decode()

class Valoris:
    def __init__(self):
        self.cipher       = Cipher()
        self.users        = {}
        self.limit        = {}
        self.transactions = []
        
        self.add_user('admin')
        self.add_user('crypto')

        self.set_balance('admin', 1_000_000)
        
        self.auth_transaction('admin', 'crypto', 100_000)

    def add_user(self, user: str, new: bool = False):
        if user in self.users:
            print('El usuario ya existe.')
            return

        self.users[user] = 0

        if not new:
            self.limit[user] = 100_000

        else:
            self.limit[user] = 20

    def set_balance(self, user: str, amount: int):
        if user not in self.users:
            print('El usuario no existe.')
            return
        
        self.users[user] = amount

    def auth_transaction(self, sender: str, receiver: str, amount: int, payload: str = None):
        if sender not in self.users or receiver not in self.users:
            print('El usuario no existe.')
            return

        if self.limit[sender] <= 0:
            print('Has alcanzado el límite de transacciones.')
            return
        
        if self.users[sender] < amount:
            print('Saldo insuficiente.')
            return
        
        self.users[sender]   -= amount
        self.users[receiver] += amount

        if not payload:
            payload = f"{self.cipher.encrypt(sender)}:{self.cipher.encrypt(receiver)}:{self.cipher.encrypt(str(amount))}"

        self.transactions.append(payload)

    def guest_transaction(self, payload: str):
        sender, receiver, amount = [ self.cipher.decrypt(param) for param in payload.split(':') ]

        self.auth_transaction(sender, receiver, int(amount), payload)

def main():
    bank = Valoris()
    
    menu = """
    ¡Bienvenido a Valoris, donde el valor está en los bloques!

    Regístrate en Valoris para comenzar a transferir dinero en
    nuestro sistema de pagos sin red.
    """

    print(menu)

    user = input('Ingrese un nombre de usuario: ')

    bank.add_user(user, new = True)

    print(
        f"¡Encantado de recibirte {user}! Te regalamos un bono de bienvenida de 5000 CLP.\n"
        "Como usuario nuevo, sólo puedes realizar un máximo de 20 transacciones cada 24 horas.\n"
        "Al cabo de una semana, las restricciones se levantan.\n"
    )
    
    bank.auth_transaction('admin', user, 5000)

    menu = """
    1. Ver balance
    2. Ver historial de transacciones
    3. Transferir
    4. Transferir como invitado
    5. Salir
    """

    print(menu)

    while bank.limit[user] > 0:
        option = input('> ')

        if option == '1':
            print(f'Balance: {bank.users[user]} CLP')

        elif option == '2':
            print(f'Historial de transacciones: {bank.transactions}')

        elif option == '3':
            receiver = input('Ingrese el nombre del destinatario: ')
            amount   = int(input('Ingrese la cantidad: '))
            
            bank.auth_transaction(user, receiver, amount)
        
        elif option == '4':
            encrypted = input('Ingrese la transaccion: ')
            
            bank.guest_transaction(encrypted)

        elif option == '5':
            print('Gracias por usar Valoris.')
            break

        else:
            print('Opcion invalida.')

        if bank.users[user] == 1_000_000:
            print(
                "Dijeron que los bloques eran seguros. Dijeron que Valoris no podía vaciarse.\n"
                "Dijeron muchas cosas.\n"
                "La cuenta de Valoris queda vacia.\n"
                "El sistema no protesta. Solo escribe:\n"
                f"{FLAG}"
            )
            break
        

if __name__ == '__main__':
    main()