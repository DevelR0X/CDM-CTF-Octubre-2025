from pwn import remote, process

r = process(['python3', 'server.py'], level = 'error')

for _ in range(100):
    r.sendlineafter(b"Coloca tus compuertas: ", b"CX:1,0;CCX:0,1,2;CX:2,1;H:2")
    print(r.recvline().decode())