from pwn import remote

r = remote("127.0.0.1", "1337")

r.sendlineafter(b"Ingrese un nombre de usuario: ", b"D-Cryp7")

r.sendlineafter(b"> ", b"2")

transactions = eval(r.recvline()[len("Historial de transacciones: "):-1])

admin, crypto, amount_100k = transactions[0].split(":")
user = transactions[1].split(":")[1]

r.sendlineafter(b"> ", b"3")
r.sendlineafter(b"Ingrese el nombre del destinatario: ", b"admin")
r.sendlineafter(b"Ingrese la cantidad: ", b"5000")

transaction = f"{admin}:{user}:{amount_100k}"
for _ in range(9):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b"Ingrese la transaccion: ", transaction.encode())
    
    r.sendlineafter(b"> ", b"1")
    print(r.recvline().decode())

transaction = f"{crypto}:{user}:{amount_100k}"
r.sendlineafter(b"> ", b"4")
r.sendlineafter(b"Ingrese la transaccion: ", transaction.encode())

print(r.recv(1024).decode())