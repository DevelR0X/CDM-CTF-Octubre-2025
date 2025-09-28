from pwn import remote # pip install pwntools

r = remote("ctf.campodemarte.cl", 32781)

r.sendlineafter("Coloca tus fichas cuánticas: añade compuertas al circuito (Ej: X:0;H:1): ".encode('utf-8'), b"CX:0,1")

player_numbers = r.recvline()[len("El qubit 1 deja ver sus números como cartas marcadas: ") + 1:-1]

print(player_numbers)

r.sendlineafter("Haz tu apuesta: ingresa tu lista de 8 números: ".encode('utf-8'), player_numbers)

print(r.recv(1024).decode())

