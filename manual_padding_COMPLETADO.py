"""
Módulo de padding PKCS#7 para cifrados de bloque.
Implementación manual sin usar bibliotecas externas.
"""

def pkcs7_pad(data: bytes, block_size: int = 8):
    """
    Implementa padding PKCS#7 según RFC 5652.
    
    Regla: Si faltan N bytes para completar el bloque,
    agregar N bytes, cada uno con el valor N (recuerden seguir la regla de pkcs#7).
    
    Importante: Si el mensaje es múltiplo exacto del tamaño
    de bloque, se agrega un bloque completo de padding.
    
    Examples:
        >>> pkcs7_pad(b"HOLA", 8).hex()
        '484f4c4104040404'  # HOLA + 4 bytes con valor 0x04
        
        >>> pkcs7_pad(b"12345678", 8).hex()  # Exactamente 8 bytes
        '31323334353637380808080808080808'  # + bloque completo
    """
    # Calcular cuántos bytes faltan para completar el bloque
    padding_needed = block_size - (len(data) % block_size)
    # Si es múltiplo exacto, padding_needed será block_size (bloque completo)
    # Crear los bytes de padding: cada byte tiene el valor de padding_needed
    padding = bytes([padding_needed] * padding_needed)
    return data + padding


def pkcs7_unpad(data: bytes) -> bytes:
    """
    Elimina padding PKCS#7 de los datos.
    
    Examples:
        >>> padded = pkcs7_pad(b"HOLA", 8)
        >>> pkcs7_unpad(padded)
        b'HOLA'
    """
    # El último byte indica cuántos bytes de padding hay
    padding_value = data[-1]
    # Remover esa cantidad de bytes del final
    return data[:-padding_value]


#  Pruebas realizadas
if __name__ == "__main__":
    # Test: Padding normal
    result = pkcs7_pad(b"HOLA BUENAS", 8)
    print(f"pkcs7_pad(b'HOLA BUENAS', 8) = {result.hex()}")
    print(f"  Esperado:              484f4c41204255454e41530202")

    # Test: Múltiplo exacto del bloque
    result2 = pkcs7_pad(b"12345678", 8)
    print(f"\npkcs7_pad(b'12345678', 8) = {result2.hex()}")
    print(f"  Esperado:                  31323334353637380808080808080808")

    # Test: Unpad
    unpadded = pkcs7_unpad(result)
    print(f"\npkcs7_unpad(padded) = {unpadded}")
    print(f"  Esperado:           b'HOLA BUENAS'")
