import os
import time
import class_G_F

class AES:
    '''
    Documento de referencia:
    Federal Information Processing Standards Publication (FIPS) 197: Advanced Encryption
    Standard (AES) https://doi.org/10.6028/NIST.FIPS.197-upd1
    El nombre de los métodos, tablas, etc son los mismos (salvo capitalización)
    que los empleados en el FIPS 197
    '''
    def __init__(self, key, Polinomio_Irreducible = 0x11B):
        '''
        Entrada:
        key: bytearray de 16 24 o 32 bytes
        Polinomio_Irreducible: Entero que representa el polinomio para construir
        el cuerpo
        SBox: equivalente a la tabla 4, pág. 14
        InvSBOX: equivalente a la tabla 6, pág. 23
        Rcon: equivalente a la tabla 5, pág. 17
        InvMixMatrix : equivalente a la matriz usada en 5.3.3, pág. 24
        '''
        self.Polinomio_Irreducible = Polinomio_Irreducible
        self.GF = class_G_F.G_F(self.Polinomio_Irreducible)
        self.SBox, self.InvSBox = self.__Cal_SBox_InvSBox()
        
        self.Rcon = self.__Cal_Rcon()
        self.__key = key

        self.MixMatrix = [[0x02, 0x03, 0x01, 0x01], [0x01, 0x02, 0x03, 0x01], [0x01, 0x01, 0x02, 0x03], [0x03, 0x01, 0x01, 0x02]]
        self.InvMixMatrix = [[0x0e, 0x0b, 0x0d, 0x09], [0x09, 0x0e, 0x0b, 0x0d], [0x0d, 0x09, 0x0e, 0x0b], [0x0b, 0x0d, 0x09, 0x0e]]
    
    def __Cal_SBox_InvSBox(self):
        """Calcula las tablas SBox y InvSBox de acuerdo con el estándar AES.
    
        - SBox se obtiene calculando el inverso multiplicativo de cada byte en GF(2^8),
        seguido de una transformación afín.
        - InvSBox es la tabla inversa de SBox.
        """

        SBox = [0 for _ in range(256)]
        InvSBox = [0 for _ in range(256)]

        # Constante de la transformación afín
        c = 0x63

        # Para cada byte b en el rango de 0 a 255
        for b in range(256):
            # 1. Calcular el inverso multiplicativo en GF(2^8), excepto cuando b es 0
            intermediate_b = 0 if b == 0 else self.GF.inverso(b)
            # 2. Aplicar la transformación afín
            sb = 0
            for i in range(8):

                aux = (
                    ((intermediate_b >> i) & 1) ^
                    ((intermediate_b >> ((i + 4) % 8)) & 1) ^
                    ((intermediate_b >> ((i + 5) % 8)) & 1) ^
                    ((intermediate_b >> ((i + 6) % 8)) & 1) ^
                    ((intermediate_b >> ((i + 7) % 8)) & 1) ^
                    ((c >> i) & 1)
                )
                aux = aux << i
                sb |= aux

            # Añadir la constante de la transformación afín (0x63)
            SBox[b] = sb

            # 3. Calcular InvSBox (la inversa de SBox)
            InvSBox[sb] = b

        return SBox, InvSBox
    
    def __Cal_Rcon(self):
        """
        Método auxiliar para calcular las constantes de ronda (Rcon).
        Genera una lista de 10 valores Rcon, donde cada Rcon es una lista de 4 bytes.
        Las constantes se utilizan en el proceso de expansión de clave (Key Schedule) del AES.
        
        Salida:
        - Rcon: Lista de 10 listas, cada una con 4 bytes.
        """
        Rcon = [[0, 0, 0, 0] for _ in range(10)]

        # El primer valor de Rcon[1] es [0x01, 0x00, 0x00, 0x00]
        Rcon[0][0] = 0x01

        for i in range(9):
            j = i+1
            Rcon[j][0] = self.GF.xTimes(Rcon[i][0])
        return Rcon
    
    def _Create_State(self, lst):
        r1, r2, r3, r4 = [], [], [], []
        State = [r1, r2, r3, r4]
        for i in range(16):  # el estado siempre es 4x4
            State[i%4].append(lst[i])
        return State
    
    def _Extract_State(self, State):
        lst = [None for _ in range(16)]
        for i in range(4):
            for j in range(4):
                lst[i + 4*j] = (State[i][j])
        return lst
    
    def _RotWord(self, word):
        return [word[1], word[2], word[3], word[0]]

    def _SubWord(self, word):
        return [self.SBox[word[0]], self.SBox[word[1]],
                 self.SBox[word[2]], self.SBox[word[3]]]

    def SubBytes(self, State):
        '''
        5.1.1 SUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(4):
            for j in range(4):
                State[i][j] = self.SBox[State[i][j]]
        return State

        
    def InvSubBytes(self, State):
        '''
        5.3.2 INVSUBBYTES()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for i in range(4):
            for j in range(4):
                State[i][j] = self.InvSBox[State[i][j]]
        return State

    def ShiftRows(self, State):
        '''
        5.1.2 SHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for r in range(4):
            lst_aux = State[r].copy()
            for c in range(4):
                j = (c + r) % 4
                State[r][c] = lst_aux[j]
        return State


    def InvShiftRows(self, State):
        '''
        5.3.1 INVSHIFTROWS()
        FIPS 197: Advanced Encryption Standard (AES)
        4
        '''
        for r in range(4):
            lst_aux = State[r].copy()
            for c in range(4):
                j = (c - r) % 4
                State[r][c] = lst_aux[j]
        return State

    def MixColumns(self, State):
        '''
        5.1.3 MIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        # Para cada columna c
        for c in range(4):
            
            # Extraer la columna actual
            col = [State[r][c] for r in range(4)]
            
            # Multiplicar la columna por la MixMatrix
            for r in range(4):
                State[r][c] = (
                    self.GF.producto(self.MixMatrix[r][0], col[0]) ^
                    self.GF.producto(self.MixMatrix[r][1], col[1]) ^
                    self.GF.producto(self.MixMatrix[r][2], col[2]) ^
                    self.GF.producto(self.MixMatrix[r][3], col[3])
                )
            

        return State


    def InvMixColumns(self, State):
        '''
        5.3.3 INVMIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        # Para cada columna c
        for c in range(4):
            # Extraer la columna actual
            col = [State[r][c] for r in range(4)]
            
            # Multiplicar la columna por la InvMixMatrix
            for r in range(4):
                State[r][c] = (
                    self.GF.producto(self.InvMixMatrix[r][0], col[0]) ^
                    self.GF.producto(self.InvMixMatrix[r][1], col[1]) ^
                    self.GF.producto(self.InvMixMatrix[r][2], col[2]) ^
                    self.GF.producto(self.InvMixMatrix[r][3], col[3])
                )
        
        return State
    def AddRoundKey(self, State, roundKey):
        '''
        5.1.4 ADDROUNDKEY()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        for r in range(4):  # Recorremos las filas
            for c in range(4):  # Recorremos las columnas
                # XOR entre el byte del estado y el byte de la clave de ronda
                State[r][c] ^= roundKey[c][r] 
        
        return State


    def KeyExpansion(self, key):
        '''
        5.2 KEYEXPANSION()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        key_length = len(key)  # longitud en bytes
        Nk, Nr = self.__check_Nk_Nr(key_length=key_length)
        
        # Inicializar las primeras Nk palabras con la clave original
        w = [None for _ in range(4 * (Nr + 1))] 
        # (Nr+1) bloques de 4 palabras (de 32 bits cada una)

        for i in range(Nk):
            w[i] = [key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]] # key[4*i, 4*i+1, 4*i+2, 4*i+3]
        # Expandir la clave para generar las subclaves
        for i in range(Nk, 4 * (Nr + 1)):
            temp = w[i-1]
            if i % Nk == 0:
                temp = self._SubWord(self._RotWord(temp))
                temp = [temp[j] ^ self.Rcon[(i//Nk)-1][j] for j in range(4)]
            elif Nk > 6 and i % Nk == 4:
                temp = self._SubWord(temp)
            w[i] = [w[i-Nk][j] ^ temp[j] for j in range(4)]
        return w


    def Cipher(self, State, Nr, Expanded_KEY):
        '''
        5.1 Cipher(), Algorithm 1 pág. 12
        FIPS 197: Advanced Encryption Standard (AES)
        '''
        w = Expanded_KEY
        State = self.AddRoundKey(State=State, roundKey=w[0:4])
        for round in range(1, Nr):
            State = self.SubBytes(State=State)
            State = self.ShiftRows(State=State)
            State = self.MixColumns(State=State)   
            State = self.AddRoundKey(State=State, roundKey=w[4*round:4*round+4])

        State = self.SubBytes(State=State)
        State = self.ShiftRows(State=State)
        State = self.AddRoundKey(State=State, roundKey=w[4*Nr:4*Nr+4])
        return State

    def InvCipher(self, State, Nr, Expanded_KEY):
        '''
        5. InvCipher()
        Algorithm 3 pág. 20 o Algorithm 4 pág. 25. Son equivalentes
        FIPS 197: Advanced Encryption Standard (AES)
        '''

        w = Expanded_KEY

        State = State = self.AddRoundKey(State=State, roundKey=w[4*Nr:4*Nr+4])
        for round in range(Nr-1, 0, -1):
            State = self.InvShiftRows(State=State)
            State = self.InvSubBytes(State=State)
            State = self.AddRoundKey(State=State, roundKey=w[4*round:4*round+4])
            State = self.InvMixColumns(State=State)
        State = self.InvShiftRows(State=State)
        State = self.InvSubBytes(State=State)
        State = self.AddRoundKey(State=State, roundKey=w[0:4])
        return State


    def encrypt_file(self, fichero):
        '''
        Entrada: Nombre del fichero a cifrar
        Salida: Fichero cifrado usando la clave utilizada en el constructor
        de la clase.
        Para cifrar se usará el modo CBC, con IV generado aleatoriamente
        y guardado en los 16 primeros bytes del fichero cifrado.
        El padding usado será PKCS7.
        El nombre de fichero cifrado será el obtenido al a~nadir el sufijo .enc
        al nombre del fichero a cifrar: NombreFichero --> NombreFichero.enc
        '''
        # Leer el contenido del archivo
        with open(fichero, 'rb') as f:
            plaintext = f.read()

        # Generar IV aleatorio de 16 bytes (128 bits) para el modo CBC
        iv = os.urandom(16)

        # Aplicar padding PKCS7
        block_size = 16  # Tamaño del bloque en AES (128 bits = 16 bytes)
        padding_length = block_size - (len(plaintext) % block_size)
        padding = bytes([padding_length] * padding_length)  # Rellenar con el valor del padding
        padded_plaintext = plaintext + padding

        # Inicializar el estado para la operación de cifrado (modo CBC)
        list_States = [list(padded_plaintext[i:i + 16]) for i in range(0, len(padded_plaintext), 16)]  # Dividir en bloques de 16 bytes

        # Cifrado en modo CBC
        key_length = len(self.__key)  # longitud en bytes
        Nk, Nr = self.__check_Nk_Nr(key_length)

        Expanded_KEY = self.KeyExpansion(self.__key)  # Expansión de la clave
        previous_block = self._Create_State(list(iv))  # El primer bloque a cifrar usa el IV

        ciphertext = iv  # El archivo cifrado empieza con el IV

        for flattened_state in list_States:
            
            State = self._Create_State(flattened_state)
            # XOR del bloque actual con el bloque anterior (o IV en la primera iteración)
            for i in range(4):
                for j in range(4):
                    State[i][j] ^= previous_block[i][j]
            
            # Cifrar el bloque usando AES
            encrypted_block = self.Cipher(State, Nr, Expanded_KEY)

            # Guardar el bloque cifrado
            ciphertext += bytes(self._Extract_State(encrypted_block))

            # Actualizar el bloque anterior para la siguiente iteración
            previous_block = encrypted_block

        # Escribir el archivo cifrado
        # encrypted_filename = fichero + "_" + hex(self.Polinomio_Irreducible) + "_" + self.__key.hex() + "_SergiG" + '.enc'
        encrypted_filename = fichero + '.enc'
        with open(encrypted_filename, 'wb') as f:
            f.write(ciphertext)

        print(f"Archivo cifrado guardado como: {encrypted_filename}")
    
    def decrypt_file(self, fichero):
        '''
        Entrada: Nombre del fichero a descifrar
        Salida: Fichero descifrado usando la clave utilizada en el constructor
        de la clase.
        Para descifrar se usará el modo CBC, con el IV guardado en los 16
        primeros bytes del fichero cifrado, y se eliminará el padding
        PKCS7 a~nadido al cifrar el fichero.
        El nombre de fichero descifrado será el obtenido al a~nadir el sufijo .dec
        al nombre del fichero a descifrar: NombreFichero --> NombreFichero.dec
        '''
        # Leer el archivo cifrado
        with open(fichero, 'rb') as f:
            ciphertext = f.read()

        # Extraer el IV (primeros 16 bytes)
        iv = list(ciphertext[:16])  # Lo convertimos a lista para operar en CBC
        ciphertext = ciphertext[16:]  # El resto es el ciphertext

        # Inicializar el estado para la operación de descifrado (modo CBC)
        block_size = 16  # Tamaño del bloque en AES (128 bits = 16 bytes)
        
        key_length = len(self.__key)  # longitud en bytes
        Nk, Nr = self.__check_Nk_Nr(key_length)

        Expanded_KEY = self.KeyExpansion(self.__key)  # Expansión de la clave

        # Dividir ciphertext en bloques de 16 bytes
        list_States = [list(ciphertext[i:i + block_size]) for i in range(0, len(ciphertext), block_size)]

        # Descifrado en modo CBC
        previous_block = self._Create_State(iv)
        plaintext = bytearray()

        for flattened_state in list_States:
            State = self._Create_State(flattened_state)
            # Descifrar el bloque
            decrypted_state = self.InvCipher(State, Nr, Expanded_KEY)

            # XOR con el bloque anterior (o el IV en la primera iteración)
            for i in range(4):
                for j in range(4):
                    decrypted_state[i][j] ^= previous_block[i][j]

            # Añadir al texto descifrado
            flattened_decrypted_state = self._Extract_State(decrypted_state)
            plaintext.extend(flattened_decrypted_state)


            # Actualizar el bloque anterior para la siguiente iteración
            previous_block = self._Create_State(flattened_state)

        # Eliminar el padding PKCS7
        padding_length = plaintext[-1]
        plaintext = plaintext[:-padding_length]

        # Escribir el archivo descifrado
        decrypted_filename = fichero + '.dec'
        with open(decrypted_filename, 'wb') as f:
            f.write(plaintext)

        print(f"Archivo descifrado guardado como: {decrypted_filename}")

    def __print_state(self, state):
        for row in state:
            print(list(map(hex,row)))

    def __check_Nk_Nr(self, key_length):
        
        if key_length == 16:  # 128 bits
            Nk = 4
            Nr = 10
        elif key_length == 24:  # 192 bits
            Nk = 6
            Nr = 12
        elif key_length == 32:  # 256 bits
            Nk = 8
            Nr = 14
        else:
            raise ValueError(f"""Clave inválida. Debe ser de 128, 192 o 256 bits.
                             Longitud recibida {key_length}""")
        return Nk, Nr


if __name__ == "__main__":

    """TODO:

        -debug each function (per encrypt_file)
        -debug tot des de Python
        - fer anar amb openssl:
                descifrar: openssl aes-128-cbc -d -K key -iv IV -in infile -out outfile
                cifrar   : openssl aes-128-cbc -e -K key -iv IV -in infile -out outfile 
    """
    


    ### provar cifrar
    key = "184d0214afe945d315339b6d92b01c0f"
    key = bytearray.fromhex(key)
    aes1 = AES(key=key, Polinomio_Irreducible = 0x11B)
    
    start_encrypt = time.time()
    aes1.encrypt_file("./Valores_test/wells_the_time_machine.txt")
    end_encrypt = time.time()
    print(f"Tiempo de cifrado: {end_encrypt - start_encrypt:.4f} segundos")

    start_decrypt = time.time()
    aes1.decrypt_file("./Valores_test/wells_the_time_machine.txt_0x11b_184d0214afe945d315339b6d92b01c0f_SergiG.enc")
    end_decrypt = time.time()
    print(f"Tiempo de descifrado: {end_decrypt - start_decrypt:.4f} segundos")

    ### provar descifrar
    # key = "4887d4193e4bc8c8d850c1e12adcb3ab"
    # key = bytearray.fromhex(key)
    # aes2 = AES(key=key, Polinomio_Irreducible = 0x11b)
    # aes2.decrypt_file(fichero="./Valores_test/wells_the_time_machine.txt_0x11b_4887d4193e4bc8c8d850c1e12adcb3ab.enc")