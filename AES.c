#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define Nk 4    // Número de palabras de clave (128 bits)
#define Nb 4    // Número de columnas (bloque de 128 bits)
#define Nr 10   // Número de rondas para AES-128

// ----------------------------
// 1. Tablas: S-box, Inv S-box y Rcon
// ----------------------------
static const uint8_t s_box[256] =
{
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t inv_s_box[256] =
{
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D
};

static const uint8_t Rcon[11] =
{
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36
};

// ----------------------------
// 2. Operaciones en GF(2^8)
// ----------------------------

// ----------------------------------------------------------------------
// Multiplica un byte por x (es decir, por 2) en GF(2^8)
// Si el bit más significativo (bit 7) es 1, se aplica la reducción modular
// con el polinomio irreducible AES (x^8 + x^4 + x^3 + x + 1), representado por 0x1b.
// ----------------------------------------------------------------------
uint8_t xtime(uint8_t x){
    // Desplaza a la izquierda (multiplicación por 2)
    // Si el bit más significativo era 1, se aplica reducción con XOR 0x1b
    return (x << 1) ^ ((x >> 7) * 0x1b);
}

// ----------------------------------------------------------------------
// Multiplica dos bytes en GF(2^8) usando el algoritmo de multiplicación
// rusa (peasant multiplication).
// ----------------------------------------------------------------------
uint8_t mul(uint8_t x, uint8_t y){
    uint8_t result = 0;

    // Mientras y no sea cero
    while (y){
        // Si el bit menos significativo de y es 1, suma (XOR) x al resultado
        if (y & 1){
            result ^= x;
        }

        // Multiplica x por 2 (mod AES) y desplaza y a la derecha (divide entre 2)
        x = xtime(x);
        y >>= 1;
    }

    return result;
}

// ----------------------------
// 3. Transformaciones de cifrado
// ----------------------------

// ----------------------------------------------------------------------
// Sustituye cada byte del estado usando la S-box de AES
// ----------------------------------------------------------------------
void SubBytes(uint8_t state[4][4]){
    // Recorre cada fila (i) y cada columna (j) de la matriz de estado
    for(int i = 0; i < 4; i++)
        for(int j = 0; j < 4; j++)
            // Sustituye el byte actual por su equivalente en la S-box
            state[i][j] = s_box[state[i][j]];
}


// ----------------------------------------------------------------------
// Esta operación desplaza cíclicamente hacia la izquierda cada fila,
// incrementando la cantidad de desplazamiento por fila (excepto la primera).
// ----------------------------------------------------------------------
void ShiftRows(uint8_t state[4][4]){
    uint8_t temp;

    // Fila 1: se desplaza 1 posición a la izquierda
    temp = state[1][0];
    for(int i = 0; i < 3; i++){
        state[1][i] = state[1][i+1]; // mueve los elementos hacia la izquierda
    }
    state[1][3] = temp; // coloca el primer elemento al final

    // Fila 2: se desplaza 2 posiciones a la izquierda
    uint8_t t1 = state[2][0], t2 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = t1;
    state[2][3] = t2;

    // Fila 3: se desplaza 3 posiciones a la izquierda (equivale a 1 a la derecha)
    temp = state[3][3];
    for (int i = 3; i > 0; i--){
        state[3][i] = state[3][i-1]; // mueve los elementos hacia la derecha
    }
    state[3][0] = temp; // coloca el último elemento al inicio
}

// ----------------------------------------------------------------------
// Esta operación mezcla los bytes de cada columna usando multiplicación
// en el campo finito GF(2^8), proporcionando difusión entre bytes.
// ----------------------------------------------------------------------
void MixColumns(uint8_t state[4][4]){
    uint8_t tmp[4];  // Almacena temporalmente los nuevos valores de cada columna

    // Itera sobre cada una de las 4 columnas del estado
    for (int j = 0; j < 4; j++){
        tmp[0] = mul(0x02, state[0][j]) ^ mul(0x03, state[1][j]) ^ state[2][j] ^ state[3][j];
        tmp[1] = state[0][j] ^ mul(0x02, state[1][j]) ^ mul(0x03, state[2][j]) ^ state[3][j];
        tmp[2] = state[0][j] ^ state[1][j] ^ mul(0x02, state[2][j]) ^ mul(0x03, state[3][j]);
        tmp[3] = mul(0x03, state[0][j]) ^ state[1][j] ^ state[2][j] ^ mul(0x02, state[3][j]);

        // Guarda los nuevos valores calculados en la columna correspondiente del estado
        for (int i = 0; i < 4; i++){
            state[i][j] = tmp[i];
        }
    }
}

// ----------------------------------------------------------------------
// Esta operación XORea el estado con la subclave correspondiente (roundKey).
// ----------------------------------------------------------------------

void AddRoundKey(uint8_t state[4][4], uint8_t* roundKey){
    // Recorre las 4 columnas del estado
    for (int i = 0; i < 4; i++){
        // Recorre las 4 filas (bytes) de cada columna
        for (int j = 0; j < 4; j++){
            // Aplica XOR entre cada byte del estado y la subclave correspondiente.
            // El índice roundKey[i*4 + j] accede a los bytes de roundKey en orden columna mayor.
            state[j][i] ^= roundKey[i*4 + j];
        }
    }
}

// ----------------------------
// 4. Transformaciones de descifrado
// ----------------------------

// ----------------------------------------------------------------------
// Aplica la S-box inversa a cada byte del estado.
// ----------------------------------------------------------------------
void InvSubBytes(uint8_t state[4][4]){
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            // Sustitución inversa usando la S-box inversa
            state[i][j] = inv_s_box[state[i][j]];
        }
    }
}

// ----------------------------------------------------------------------
// Esta operación desplaza cíclicamente hacia la derecha cada fila,
// incrementando la cantidad de desplazamiento por fila (excepto la primera).
// ----------------------------------------------------------------------
void InvShiftRows(uint8_t state[4][4]){
    uint8_t temp;

    // Fila 1: rotación a la derecha de 1 byte
    temp = state[1][3];
    for (int i = 3; i > 0; i--){
        state[1][i] = state[1][i-1];
    }
    state[1][0] = temp;

    // Fila 2: rotación a la derecha de 2 bytes
    uint8_t t1 = state[2][2], t2 = state[2][3];
    state[2][3] = state[2][1];
    state[2][2] = state[2][0];
    state[2][1] = t2;
    state[2][0] = t1;

    // Fila 3: rotación a la derecha de 3 bytes (o izquierda de 1)
    temp = state[3][0];
    for (int i = 0; i < 3; i++){
        state[3][i] = state[3][i+1];
    }
    state[3][3] = temp;
}

// ----------------------------------------------------------------------
// Esta operación es más compleja que la directa y utiliza multiplicaciones
// en GF(2^8) con coeficientes específicos para deshacer MixColumns.
// ----------------------------------------------------------------------
void InvMixColumns(uint8_t state[4][4]){
    uint8_t tmp[4];

    for(int j = 0; j < 4; j++){
        // Aplicación de la matriz inversa de MixColumns:
        tmp[0] = mul(0x0e, state[0][j]) ^ mul(0x0b, state[1][j]) ^ mul(0x0d, state[2][j]) ^ mul(0x09, state[3][j]);
        tmp[1] = mul(0x09, state[0][j]) ^ mul(0x0e, state[1][j]) ^ mul(0x0b, state[2][j]) ^ mul(0x0d, state[3][j]);
        tmp[2] = mul(0x0d, state[0][j]) ^ mul(0x09, state[1][j]) ^ mul(0x0e, state[2][j]) ^ mul(0x0b, state[3][j]);
        tmp[3] = mul(0x0b, state[0][j]) ^ mul(0x0d, state[1][j]) ^ mul(0x09, state[2][j]) ^ mul(0x0e, state[3][j]);

        // Actualiza la columna j del estado con los nuevos valores
        for (int i = 0; i < 4; i++){
            state[i][j] = tmp[i];
        }
    }
}

// ----------------------------
// 5. Expansión de clave
// ----------------------------

// ----------------------------------------------------------------------
// Esta función genera todas las subclaves (round keys) necesarias
// para cada ronda del algoritmo AES-128 a partir de la clave original.
// ----------------------------------------------------------------------
void KeyExpansion(const uint8_t* key, uint8_t* roundKeys){
    // Copiar la clave original como los primeros 16 bytes de roundKeys
    memcpy(roundKeys, key, 16);

    uint8_t temp[4];
    int i = Nk;  // Comienza desde la palabra Nk (4 para AES-128)

    // Hasta completar las 44 palabras, cada una de 4 bytes.
    while(i < Nb * (Nr + 1)){
        // Copia la palabra anterior (4 bytes) en temp
        for(int j = 0; j < 4; j++){
            temp[j] = roundKeys[(i - 1) * 4 + j];
        }

        // Cada Nk palabras, aplica transformación especial
        if(i % Nk == 0){
            // RotWord: rota los bytes una posición a la izquierda
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord: aplica sustitución S-box a cada byte
            for(int j = 0; j < 4; j++){
                temp[j] = s_box[temp[j]];
            }

            // XOR con el valor correspondiente de Rcon
            temp[0] ^= Rcon[i / Nk];
        }

        // XOR entre temp y la palabra Nk posiciones atrás
        for(int j = 0; j < 4; j++){
            roundKeys[i * 4 + j] = roundKeys[(i - Nk) * 4 + j] ^ temp[j];
        }

        i++;
    }
}


// ----------------------------
// 6. Funciones AES
// ----------------------------

// ----------------------------------------------------------------------
// Función que cifra un bloque de 16 bytes (128 bits) usando AES-128
// ----------------------------------------------------------------------
void AES_encrypt(const uint8_t* input, const uint8_t* key, uint8_t* output){
    uint8_t state[4][4];
    uint8_t roundKeys[176];

    // Expande la clave original de 16 bytes a 176 bytes de claves de ronda
    KeyExpansion(key, roundKeys);

    // Copia el input de 16 bytes al estado en forma de columna mayor
    for(int i = 0; i < 16; i++){
        state[i % 4][i / 4] = input[i];
    }

    // Ronda inicial: se aplica la primera clave de ronda
    AddRoundKey(state, roundKeys);

    // Rondas principales: 9 rondas para AES-128
    for(int round = 1; round < Nr; round++){
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }

    // Última ronda (no incluye MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + Nr * 16);

    // Se copia el estado cifrado al arreglo de salida en orden columna mayor
    for(int i = 0; i < 16; i++){
        output[i] = state[i % 4][i / 4];
    }
}

// ----------------------------------------------------------------------
// Función para descifrar un bloque de 16 bytes con AES-128
// ----------------------------------------------------------------------
void AES_decrypt(const uint8_t* input, const uint8_t* key, uint8_t* output){
    uint8_t state[4][4];
    uint8_t roundKeys[176];

    // Expande la clave original de 16 bytes a 176 bytes de claves de ronda
    KeyExpansion(key, roundKeys);

    // Copia el input de 16 bytes al estado en forma de columna mayor
    for (int i = 0; i < 16; i++){
        state[i % 4][i / 4] = input[i];
    }

    // Ronda inicial: se aplica la última clave de ronda
    AddRoundKey(state, roundKeys + Nr * 16);

    // Rondas inversas desde Nr-1 hasta 1
    for (int round = Nr - 1; round > 0; round--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, roundKeys + round*16);
        InvMixColumns(state);
    }

    // Última ronda inversa (sin InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, roundKeys);

    // Copiar el estado al bloque de salida, conservando el orden columna mayor
    for (int i = 0; i < 16; i++){
        output[i] = state[i % 4][i / 4];
    }
}

// ----------------------------
// 7. Funciones para obtener y tartar los datos del usuario.
// ----------------------------

// ----------------------------------------------------------------------
// Limpia el buffer de entrada del teclado.
// ----------------------------------------------------------------------
void clear_input_buffer(){
    int ch;
    while((ch = getchar()) != '\n' && ch != EOF);
}

// ----------------------------------------------------------------------
// Convierte cada carácter del primer parámetro a su valor byte (ASCII)
// y lo almacena en el segundo parámetro.
// ----------------------------------------------------------------------
void ascii_to_bytes(const char* input, uint8_t* output){
    for(int i = 0; i < 16; i++){
        output[i] = (uint8_t)input[i];
    }
}

// ----------------------------------------------------------------------
// Convierte cada carácter del primer parámetro a su valor byte y lo
// almacena en el segundo parámetro.
// ----------------------------------------------------------------------
int hex_to_bytes(const char* hex_input, uint8_t* output){
    for(int i = 0; i < 16; i++){
        char byte_str[3] = {hex_input[i * 2], hex_input[i * 2 + 1], '\0'};
        char* endptr;
        long byte_val = strtol(byte_str, &endptr, 16);

        if(*endptr != '\0' || byte_val < 0 || byte_val > 255){
            printf("\nError, no se trata de valores hexadecimales.");
            return -1;
        }

        output[i] = (uint8_t)byte_val;
    }

    return 0;
}

// ----------------------------------------------------------------------
// Solicita al usuario un texto plano y una clave, los dos de 16
// caracteres, convierte ambos a arreglos de bytes, realiza el cifrado
// AES-128 y muestra el resultado cifrado en formato hexadecimal.
// ----------------------------------------------------------------------
int encrypt(){
    char input_text[17], input_key[17];
    uint8_t plaintext[16], key[16], ciphertext[16];

    printf("\nIngrese el texto plano (16 caracteres): ");
    if(fgets(input_text, sizeof(input_text), stdin) == NULL){
        printf("\nError al leer el texto plano.");
        clear_input_buffer();
        return -1;
    }
    clear_input_buffer();

    printf("Ingrese la clave AES-128 (16 caracteres): ");
    if(fgets(input_key, sizeof(input_key), stdin) == NULL){
        printf("\nError al leer la clave.");
        clear_input_buffer();
        return -1;
    }
    clear_input_buffer();

    if(strlen(input_text) != 16 || strlen(input_key) != 16){
        printf("\nError: Ambos campos deben tener 16 caracteres exactos.");
        return -1;
    }

    ascii_to_bytes(input_text, plaintext);
    ascii_to_bytes(input_key, key);

    AES_encrypt(plaintext, key, ciphertext);

    printf("Texto cifrado (hex): ");
    for (int i = 0; i < 16; i++){
            printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    return 0;
}

// ----------------------------------------------------------------------
// Solicita al usuario un texto cifrado en hexadecimal y una clave, el
// primero de 32 caracteres y el segundo de 16 caracteres, convierte
// ambos a arreglos de bytes, realiza el descifrado AES-128 y muestra el
// resultado descifrado en formato ASCII.
// ----------------------------------------------------------------------
int decrypt(){
    char hex_input[33], input_key[17];
    uint8_t ciphertext[16], key[16], decrypted[16];

    printf("Ingrese texto cifrado en hexadecimal (32 caracteres): ");

    if(fgets(hex_input, sizeof(hex_input), stdin) == NULL){
        printf("\nError al leer el texto cifrado (hex).");
        clear_input_buffer();
        return -1;
    }
    clear_input_buffer();

    printf("Ingrese la clave AES-128 (16 caracteres): ");
    if(fgets(input_key, sizeof(input_key), stdin) == NULL){
        printf("\nError al leer la clave.");
        clear_input_buffer();
        return -1;
    }
    clear_input_buffer();

    if (strlen(hex_input) != 32 || strlen(input_key) != 16) {
        printf("Error: Texto cifrado debe ser 32 caracteres hexadecimales, y clave 16 caracteres.\n");
        return -1;
    }

    if(hex_to_bytes(hex_input, ciphertext) != 0){
        return -1;
    }
    ascii_to_bytes(input_key, key);

    AES_decrypt(ciphertext, key, decrypted);

    printf("Texto descifrado (ASCII): ");
    for (int i = 0; i < 16; i++){
        printf("%c", decrypted[i]);
    }
    printf("\n");

    return 0;
}

// ----------------------------
// 8. Función principal del programa.
// ----------------------------

// ----------------------------------------------------------------------
// Muestra un menú para que el usuario seleccione entre cifrar, descifrar
// o salir del programa. Se ejecuta la acción según la opción elegida.
// ----------------------------------------------------------------------
int main(){
    int opcion;

    do{
        printf("\n--- MENU AES-128 ---\n");
        printf("\t1. Cifrar mensaje\n");
        printf("\t2. Descifrar mensaje\n");
        printf("\t3. Salir\n");
        printf("Seleccione una opci%cn: ", 162);
        if (scanf("%d", &opcion) != 1){
            printf("\nFormato incorrecto. Intente de nuevo.\n");
            clear_input_buffer();
            continue;
        }
        clear_input_buffer();

        switch (opcion){
            case 1:
                if(encrypt() == 0){
                    printf("\nCifrado finalizado con %cxito.\n", 130);
                } else{
                    printf("Fall%c el cifrado.\n", 162);
                }
                break;

            case 2:
                if(decrypt() == 0){
                    printf("\nDescifrado finalizado con %cxito.\n", 130);
                } else{
                    printf("Fall%c el descifrado.\n", 162);
                }
                break;

            case 3:
                printf("\nGracias, vuelva pronto.\n");
                break;

            default:
                printf("\nOpci%cn invalida. Intente de nuevo.\n", 162);
        }
    }while(opcion != 3);

    return 0;
}
