from Crypto.Cipher import ChaCha20
from pwn import remote, xor

def get_command_output(command, key, decrypt = True):
    r.sendlineafter(b"> ", xor(command.encode(), key[:len(command)]).hex().encode())
    encrypted = bytes.fromhex(r.recvline()[:-1].decode())
    if decrypt == True:
        return xor(encrypted, key)
    else:
        return encrypted

r = remote("127.0.0.1", "1337")

encrypted = bytes.fromhex(r.recvline()[len("Debug mode enabled: "):-1].decode())

key = xor(b"ACCESS_GRANTED:INITIALIZATION_COMPLETE", encrypted)

nonce = get_command_output("ACCESS_GRANTED:NONCE", key)[:12]
raw_key = get_command_output("ACCESS_GRANTED:KEY", key)[:32]

encrypted_flag = get_command_output("ACCESS_GRANTED:ENGAGE", key, decrypt = False)

cipher = ChaCha20.new(key = raw_key, nonce = nonce)

flag = cipher.decrypt(encrypted_flag)

print(flag)