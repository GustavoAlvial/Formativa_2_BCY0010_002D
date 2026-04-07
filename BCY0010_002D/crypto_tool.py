#Imports de PyCryptodome para cifrado simétrico
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

import os
import sys

tamanio_llave = 32  #32 bytes
tamanio_bloque = AES.block_size #16 bytes
tamanio_max_archivo = 1024  #1 kb máx
archivo_llave = "secret.key"

#Funciones
#Función para generar una llave AES-256 y guardarla, o cargar una ya existente
def generar_llave():
    #Retorna una llave AES de 32 bytes
    if os.path.exists(archivo_llave):
        with open(archivo_llave, "rb") as f:
            key = f.read()
            print("Llave cargada desde 'secret.key'.")
            return key
        pass
    else:
        key = get_random_bytes(tamanio_llave)
        with open(archivo_llave, "wb") as f:
            f.write(key)
            print("Llave generada y guardada.")
            return key
        pass
#Función para cifrar archivo de texto en modo CBC
def cifrar_archivo(ruta_archivo, key):
    texto = open(ruta_archivo, "r", encoding="utf-8").read()
    if len(texto.encode("utf-8")) > tamanio_max_archivo:
        raise ValueError(f"El archivo excede el tamaño máximo de {tamanio_max_archivo}.")
    bytes_texto = texto.encode("utf-8")
    cifrado = AES.new(key, AES.MODE_CBC)
    texto_rellenado = pad(bytes_texto, AES.block_size)
    texto_cifrado = cifrado.encrypt(texto_rellenado)
    iv = cifrado.iv
    return iv, texto_cifrado

#función para descifrar un texto en modo CBC
def descifrar(iv, texto_cifrado, key):
    cifrado = AES.new(key, AES.MODE_CBC, iv=iv)
    texto_rellenado = cifrado.decrypt(texto_cifrado)
    bytes_texto = unpad(texto_rellenado, AES.block_size)
    texto = bytes_texto.decode("utf-8")
    return texto

#Función para guardar el IV y el texto cifrado en un solo archivo
def guardar_archivo(archivo_salida, iv, texto_cifrado):
    with open(archivo_salida, "wb") as f:
        f.write(iv + texto_cifrado)

#Función para leer un archivo cifrado y separar el IV
def cargar_archivo(archivo_cifrado):
    with open(archivo_cifrado, "rb") as f:
        data = f.read()
    iv = data[:tamanio_bloque] #Para indicar los primeros 16 bytes
    texto_cifrado = data[tamanio_bloque:] #Para indicar el resto
    print(f"IV: {iv.hex()}")
    return iv, texto_cifrado

#Programa principal
def main():
    accion = sys.argv[1].lower()
    archivo = sys.argv[2]
    if accion == "cifrar":
        #Se genera o carga la llave
        key = generar_llave()
        #Se cifra el archivo
        try:
            iv, texto_cifrado = cifrar_archivo(archivo, key)
        except Exception as e:
            print(f"Error al cifrar: {e}")
            sys.exit(1)
        #Se guarda el archivo cifrado
        archivo_salida = archivo + ".enc"
        guardar_archivo(archivo_salida, iv, texto_cifrado)
        print("Cifrado completado.")
    elif accion == "descifrar":
        key = generar_llave()
        #Se lee el archivo cifrado
        iv, texto_cifrado = cargar_archivo(archivo)
        #Se descifra
        try:
            texto = descifrar(iv, texto_cifrado, key)
        except Exception as e:
            print(f"Error al descifrar: {e}")
            sys.exit(1)
        #Se guarda el texto descifrado
        archivo_salida = archivo.replace(".enc", ".dec.txt")
        with open(archivo_salida, "w", encoding="utf-8") as f:
            f.write(texto)
            print(f"Archivo descifrado guardado en: {archivo_salida}")
    else:
        print("Acción no reconocida")
        sys.exit(1)

if __name__ == "__main__":
    main()