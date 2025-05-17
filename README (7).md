# AES-128 en C

Este proyecto implementa el algoritmo de cifrado y descifrado AES-128 (Advanced Encryption Standard) en lenguaje C, incluyendo todas las transformaciones requeridas por la norma FIPS-197. El programa permite cifrar y descifrar bloques de 128 bits (16 bytes) utilizando una clave de 128 bits.

## Requisitos

- **Compilador de C** (GCC recomendado)
- **Sistema operativo** con soporte para compilación en C (Windows, Linux o macOS)

## Características

- Implementación completa de AES-128 con:
  - SubBytes / InvSubBytes
  - ShiftRows / InvShiftRows
  - MixColumns / InvMixColumns
  - AddRoundKey
  - Expansión de clave (KeyExpansion)
- Cifrado y descifrado de bloques de 16 bytes
- Menú interactivo en consola para seleccionar la operación
- Comentarios detallados en el código fuente para facilitar su comprensión

## Compilación

Para compilar el programa, se recomienda utilizar `gcc`:

```sh
gcc AES.c -o AES
```

### Ejecución

```sh
./AES
```

## Ejemplo de uso de cifrado y descifrado.

--- MENU AES-128 ---
        1. Cifrar mensaje
        2. Descifrar mensaje
        3. Salir
Seleccione una opción: 1

Ingrese el texto plano (16 caracteres): Two One Nine Two
Ingrese la clave AES-128 (16 caracteres): Thats my Kung Fu

Texto cifrado (hex): 29 c3 50 5f 57 14 20 f6 40 22 99 b3 1a 02 d7 3a

Cifrado finalizado con éxito.

--- MENU AES-128 ---
        1. Cifrar mensaje
        2. Descifrar mensaje
        3. Salir
Seleccione una opción: 2
Ingrese texto cifrado en hexadecimal (32 caracteres): 29c3505f571420f6402299b31a02d73a
Ingrese la clave AES-128 (16 caracteres): Thats my Kung Fu
Texto descifrado (ASCII): Two One Nine Two

Descifrado finalizado con éxito.

--- MENU AES-128 ---
        1. Cifrar mensaje
        2. Descifrar mensaje
        3. Salir
Seleccione una opción: 3

Gracias, vuelva pronto.