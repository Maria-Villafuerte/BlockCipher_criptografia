"""
Generador de claves criptográficamente seguras.
"""
import secrets


def generate_des_key():
    """
    Genera una clave DES aleatoria de 8 bytes (64 bits).
    
    Nota: DES usa efectivamente 56 bits (los otros 8 son de paridad),
    pero la clave es de 8 bytes.
    """
    return secrets.token_bytes(8)


def generate_3des_key(key_option: int = 2):
    """
    Genera una clave 3DES aleatoria.
    
    key_option = 2 → 16 bytes (2 claves independientes, K1≠K2, K3=K1)
    key_option = 3 → 24 bytes (3 claves independientes, K1≠K2≠K3)
    """
    if key_option == 2:
        return secrets.token_bytes(16)
    elif key_option == 3:
        return secrets.token_bytes(24)
    else:
        raise ValueError("key_option debe ser 2 o 3")


def generate_aes_key(key_size: int = 256):
    """
    Genera una clave AES aleatoria.
    
    key_size: 128, 192 o 256 bits
    """
    if key_size not in (128, 192, 256):
        raise ValueError("key_size debe ser 128, 192 o 256")
    # Convertir bits a bytes: key_size // 8
    return secrets.token_bytes(key_size // 8)


def generate_iv(block_size: int = 8) -> bytes:
    """
    Genera un vector de inicialización (IV) aleatorio.
    
    block_size: 8 para DES/3DES, 16 para AES
    """
    return secrets.token_bytes(block_size)


# Pruebas realizadas
if __name__ == "__main__":

    # Quiero saber la llave y los bytes de la llave para cada caso, por eso imprimo el resultado en hexadecimal.
    des_key = generate_des_key()
    print(f"DES key   ({len(des_key)} bytes): {des_key.hex()}")

    des3_key_2 = generate_3des_key(2)
    print(f"3DES key2 ({len(des3_key_2)} bytes): {des3_key_2.hex()}")

    des3_key_3 = generate_3des_key(3)
    print(f"3DES key3 ({len(des3_key_3)} bytes): {des3_key_3.hex()}")

    aes_128 = generate_aes_key(128)
    print(f"AES-128   ({len(aes_128)} bytes): {aes_128.hex()}")

    aes_256 = generate_aes_key(256)
    print(f"AES-256   ({len(aes_256)} bytes): {aes_256.hex()}")

    iv_des = generate_iv(8)
    print(f"IV DES    ({len(iv_des)} bytes): {iv_des.hex()}")

    iv_aes = generate_iv(16)
    print(f"IV AES    ({len(iv_aes)} bytes): {iv_aes.hex()}")
