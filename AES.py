from G_F import *

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
        self.GF = GF(self.Polinomio_Irreducible)
        self.SBox, self.InvSBox = self.__Cal_SBox_InvSBox()
        self.Rcon
        self.MixMatrix = [[0x02, 0x03, 0x01, 0x01], [0x01, 0x02, 0x03, 0x01], [0x01, 0x01, 0x02, 0x03], [0x03, 0x01, 0x01, 0x02]]
        self.InvMixMatrix = [[0x0e, 0x0b, 0x0d, 0x09], [0x09, 0x0e, 0x0b, 0x0d], [0x0d, 0x09, 0x0e, 0x0b], [0x0b, 0x0d, 0x09, 0x0e]]
    
    def __Cal_SBox_InvSBox(self):
        for b in range(256):
            intermediate_b = 0 if b == 0 else self.GF.inverso(b)
            


        return SBox, InvSBox

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

    def InvMixColumns(self, State):
        '''
        5.3.3 INVMIXCOLUMNS()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
    def AddRoundKey(self, State, roundKey):
        '''
        5.1.4 ADDROUNDKEY()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
    def KeyExpansion(self, key):
        '''
        5.2 KEYEXPANSION()
        FIPS 197: Advanced Encryption Standard (AES)
        '''
    def Cipher(self, State, Nr, Expanded_KEY):
        '''
        5.1 Cipher(), Algorithm 1 pág. 12
        FIPS 197: Advanced Encryption Standard (AES)
        '''
    def InvCipher(self, State, Nr, Expanded_KEY):
        '''
        5. InvCipher()
        Algorithm 3 pág. 20 o Algorithm 4 pág. 25. Son equivalentes
        FIPS 197: Advanced Encryption Standard (AES)
        '''
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

if __name__ == "__main__":
    aes = AES()

    """
    lab AES 1: init, SubBytes, MixColumns, ShiftRow 
    i els seus determinats inversos, 
    intentar també AddRoundKey
    """
