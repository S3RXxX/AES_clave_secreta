from G_F import G_F
from AES import AES

# Examples brought from 
# https://formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng-html5.html
# KeyExpansion, Cipher, InvCipher,... tested w/ aes-Valores test

def testing_GF():
    e = 0
    values_test = [0x03, 0xff, 0, 47, 254, 33]
    value_test_2 = [5, 155, 255, 37, 1, 78]
    correct_results = {0x11b: {"xTimes": [6, 229, 0, 94, 231, 66],
                               "producto": [15, 175, 0, 4, 254, 77], 
                               "inverso": [246, 28, 0, 194, 65, 110],
                               "division": [246, 220, 0, 197, 254, 205]},

                               0x1e7: {"xTimes": [6, 25, 0, 94, 27, 66],
                               "producto": [15, 113, 0, 198, 254, 205], 
                               "inverso": [162, 199, 0, 218, 90, 61],
                               "division": [162, 119, 0, 102, 254, 102]}
                       }
    print("Testing values for Galois field")
    print()

    for polinomio_irreducible in correct_results:
        CF = G_F(Polinomio_Irreducible=polinomio_irreducible, verbose=False)
        # provar xTimes
        for n, res_correcto in zip(values_test, correct_results[polinomio_irreducible]["xTimes"]):
            res = CF.xTimes(n)
            if res != res_correcto:
                e += 1
                print(f"xTimes n={n}: {res}, debería dar {res_correcto} para el polinomio irreducible {hex(polinomio_irreducible)}")

        # provar producto
        for a, b, res_correcto in zip(values_test, value_test_2, correct_results[polinomio_irreducible]["producto"]):
            res = CF.producto(a, b)
            if res != res_correcto:
                e += 1
                print(f"producto a={a}, b={b}: {res}, debería dar {res_correcto} para el polinomio irreducible {hex(polinomio_irreducible)}")
        
        # provar inverso
        for n, res_correcto in zip(values_test, correct_results[polinomio_irreducible]["inverso"]):
            res = CF.inverso(n)
            if res != res_correcto:
                e += 1
                print(f"inverso n={n}: {res}, debería dar {res_correcto} para el polinomio irreducible {hex(polinomio_irreducible)}")
        
        # provar division (multiplicar por el inverso)
        for a, b, res_correcto in zip(values_test, value_test_2, correct_results[polinomio_irreducible]["division"]):
            res = CF.producto(a, CF.inverso(b))
            if res != res_correcto:
                e += 1
                print(f"división a={a}, b={b}: {res}, debería dar {res_correcto} para el polinomio irreducible {hex(polinomio_irreducible)}")
        
    print("All values tested for Galois field")
    return e

def testing_Rcon(verbose=False):
    e = 0
    aes = AES(key = 111111)
    gt_Rcon = [[0x01, 0,0,0], [0x02, 0,0,0], [0x04, 0,0,0], 
               [0x08, 0,0,0], [0x10, 0,0,0], [0x20, 0,0,0],
               [0x40, 0,0,0], [0x80, 0,0,0], [0x1b, 0,0,0],
               [0x36, 0,0,0]]
    if verbose:
        print("Rcon:")
        for i in range(10):
            print(f"Calculated Rcon: {aes.Rcon[i]}")
            print(f"actual Rcon: {gt_Rcon[i]}")
            print()
    
    for i in range(10):

        if aes.Rcon[i] != gt_Rcon[i]:
            e += 1
    return e

def testing_SBox(verbose=False):
    e = 0
    aes = AES(key=bytearray(16))
    aes_subbytes = (0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
           0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
           0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
           0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
           0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
           0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
           0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
           0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
           0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
           0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
           0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
           0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
           0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
           0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
           0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
           0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
           0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
           0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
           0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
           0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
           0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
           0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
           0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
           0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
           0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
           0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
           0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
           0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
           0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
           0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
           0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
           0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16)
    if verbose:
        print("SBox")
        print(list(map(hex, aes.SBox)))
    for i in range(len(aes_subbytes)):
        if aes_subbytes[i] != aes.SBox[i]:
            e += 1
            if verbose:
                print(f"Error SBox per in: {i} out: {aes_subbytes[i]}, calculat: {aes.SBox[i]}")
    return e
        

        

def testing_SubBytes(verbose=False):
    e = 0
    aes = AES(key=bytearray(16))  # Usar clave adecuada
    state = [[0x19, 0xa0, 0x9a, 0xe9],
             [0x3d, 0xf4, 0xc6, 0xf8],
             [0xe3, 0xe2, 0x8d, 0x48],
             [0xbe, 0x2b, 0x2a, 0x08]]
    new_state = [[0xd4, 0xe0, 0xb8, 0x1e],
                [0x27, 0xbf, 0xb4, 0x41],
                [0x11, 0x98, 0x5d, 0x52],
                [0xae, 0xf1, 0xe5, 0x30]]
    if verbose:
        print("Estado antes de SubBytes:")
        for row in state:
            print(list(map(hex,row)))
    state = aes.SubBytes(state)
    for i in range(len(new_state)):
        for j in range(len(new_state[i])):
            if new_state[i][j] != state[i][j]:
                e+=1
    if verbose:
        print("Estado después de SubBytes:")
        for row in state:
            print(list(map(hex,row)))
    return e

def testing_InvSubBytes(verbose=False):
    e = 0
    aes = AES(key=bytearray(16))  # Usar clave adecuada
    state = [[0xd4, 0xe0, 0xb8, 0x1e],
                [0x27, 0xbf, 0xb4, 0x41],
                [0x11, 0x98, 0x5d, 0x52],
                [0xae, 0xf1, 0xe5, 0x30]]
    
    new_state = [[0x19, 0xa0, 0x9a, 0xe9],
             [0x3d, 0xf4, 0xc6, 0xf8],
             [0xe3, 0xe2, 0x8d, 0x48],
             [0xbe, 0x2b, 0x2a, 0x08]]
    

    if verbose:
        print("Estado antes de InvSubBytes:")
        for row in state:
            print(list(map(hex,row)))
    state = aes.InvSubBytes(state)
    for i in range(len(new_state)):
        for j in range(len(new_state[i])):
            if new_state[i][j] != state[i][j]:
                e+=1
    if verbose:
        print("Estado después de InvSubBytes:")
        for row in state:
            print(list(map(hex,row)))
    return e

def testing_ShiftRows(verbose=False):
    e = 0
    aes = AES(key=bytearray(16))
    state = [[0xd4, 0xe0, 0xb8, 0x1e],
                [0x27, 0xbf, 0xb4, 0x41],
                [0x11, 0x98, 0x5d, 0x52],
                [0xae, 0xf1, 0xe5, 0x30]]
    new_state = [[0xd4, 0xe0, 0xb8, 0x1e],
                [0xbf, 0xb4, 0x41, 0x27],
                [0x5d, 0x52, 0x11, 0x98],
                [0x30, 0xae, 0xf1, 0xe5]]
    if verbose:
        print("Estado antes de ShiftRows:")
        for row in state:
            print(list(map(hex,row)))
    state = aes.ShiftRows(state)
    for i in range(len(new_state)):
        for j in range(len(new_state[i])):
            if new_state[i][j] != state[i][j]:
                e+=1
    if verbose:
        print("Estado después de ShiftRows:")
        for row in state:
            print(list(map(hex,row)))
    return e

def testing_InvShiftRows(verbose=False):
    e = 0
    aes = AES(key=bytearray(16))
    new_state = [[0xd4, 0xe0, 0xb8, 0x1e],
                [0x27, 0xbf, 0xb4, 0x41],
                [0x11, 0x98, 0x5d, 0x52],
                [0xae, 0xf1, 0xe5, 0x30]]
    state = [[0xd4, 0xe0, 0xb8, 0x1e],
                [0xbf, 0xb4, 0x41, 0x27],
                [0x5d, 0x52, 0x11, 0x98],
                [0x30, 0xae, 0xf1, 0xe5]]
    if verbose:
        print("Estado antes de InvShiftRows:")
        for row in state:
            print(list(map(hex,row)))
    state = aes.InvShiftRows(state)
    for i in range(len(new_state)):
        for j in range(len(new_state[i])):
            if new_state[i][j] != state[i][j]:
                e+=1
    if verbose:
        print("Estado después de InvShiftRows:")
        for row in state:
            print(list(map(hex,row)))
    return e

def testing_MixColumns(verbose=False):
    e = 0
    aes = AES(key=bytearray(16))
    state = [[0xd4, 0xe0, 0xb8, 0x1e],
                [0xbf, 0xb4, 0x41, 0x27],
                [0x5d, 0x52, 0x11, 0x98],
                [0x30, 0xae, 0xf1, 0xe5]]
    
    new_state = [[0x04, 0xe0, 0x48, 0x28],
                 [0x66, 0xcb, 0xf8, 0x06],
                 [0x81, 0x19, 0xd3, 0x26],
                 [0xe5, 0x9a, 0x7a, 0x4c]]

    if verbose:
        print("Estado antes de MixColumns:")
        for row in state:
            print(list(map(hex,row)))
    state = aes.MixColumns(state)
    for i in range(len(new_state)):
        for j in range(len(new_state[i])):
            if new_state[i][j] != state[i][j]:
                e+=1
    if verbose:
        print("Estado después de MixColumns:")
        for row in state:
            print(list(map(hex,row)))
    return e

def testing_InvMixColumns(verbose=False):
    e = 0
    aes = AES(key=bytearray(16))
    state = [[0x04, 0xe0, 0x48, 0x28],
                 [0x66, 0xcb, 0xf8, 0x06],
                 [0x81, 0x19, 0xd3, 0x26],
                 [0xe5, 0x9a, 0x7a, 0x4c]]
    new_state = [[0xd4, 0xe0, 0xb8, 0x1e],
                [0xbf, 0xb4, 0x41, 0x27],
                [0x5d, 0x52, 0x11, 0x98],
                [0x30, 0xae, 0xf1, 0xe5]]
    if verbose:
        print("Estado antes de InvMixColumns:")
        for row in state:
            print(list(map(hex,row)))
    state = aes.InvMixColumns(state)
    for i in range(len(new_state)):
        for j in range(len(new_state[i])):
            if new_state[i][j] != state[i][j]:
                e+=1
    if verbose:
        print("Estado después de InvMixColumns:")
        for row in state:
            print(list(map(hex,row)))
    return e

def testing_AddRoundKey(verbose=False):
    e = 0
    state = [[0x04, 0xe0, 0x48, 0x28],
                 [0x66, 0xcb, 0xf8, 0x06],
                 [0x81, 0x19, 0xd3, 0x26],
                 [0xe5, 0x9a, 0x7a, 0x4c]]
    
    round_key = [[0xa0, 0x88, 0x23, 0x2a],
                 [0xfa, 0x54, 0xa3, 0x6c],
                 [0xfe, 0x2c, 0x39, 0x76],
                 [0x17, 0xb1, 0x39, 0x05]]
    
    new_state = [[0xa4, 0x68, 0x6b, 0x02],
                 [0x9c, 0x9f, 0x5b, 0x6a],
                 [0x7f, 0x35, 0xea, 0x50],
                 [0xf2, 0x2b, 0x43, 0x49]]
    aes = AES(key=bytearray(16))
    if verbose:
        print("Estado antes de AddRoundKey:")
        for row in state:
            print(list(map(hex,row)))
    state = aes.AddRoundKey(state, roundKey=round_key)
    for i in range(len(new_state)):
        for j in range(len(new_state[i])):
            if new_state[i][j] != state[i][j]:
                e+=1
    if verbose:
        print("Estado después de AddRoundKey:")
        for row in state:
            print(list(map(hex,row)))
    return e

def testing_RotWord(verbose=False):
    word = [0x09, 0xcf, 0x4f, 0x3c]
    gt = [0xcf, 0x4f, 0x3c, 0x09]
    e = 0
    aes = AES(key=bytearray(16))
    new_word = aes._RotWord(word=word)
    if verbose:
        print(f"Word: {list(map(hex,word))}")
        print(f"RotWord: {list(map(hex,new_word))}")
    for i in range(len(word)):
        if gt[i] != new_word[i]:
            e += 1

    return e


def testing_SubWord(verbose=False):
    gt = [0x8a, 0x84, 0xeb, 0x01]
    word = [0xcf, 0x4f, 0x3c, 0x09]
    e = 0
    aes = AES(key=bytearray(16))
    new_word = aes._SubWord(word=word)
    if verbose:
        print(f"Word: {list(map(hex,word))}")
        print(f"SubWord: {list(map(hex,new_word))}")
    for i in range(len(word)):
        if gt[i] != new_word[i]:
            e += 1

    return e

def testing_KeyExpansion(key, pi=0x11B, verbose=False):
    key = bytearray.fromhex(key)
    aes = AES(key=key, Polinomio_Irreducible=pi)
    expanded_key = aes.KeyExpansion(key)

    print("Expanded Key Schedule:")
    for i, word in enumerate(expanded_key):
        print(f"w[{i}]: {list(map(hex, word))}")

def testing_Cipher():
    pass

def testing_InvCipher():
    pass

def testing_encrypt_file():
    pass

def testing_decrypt_file():
    pass

if __name__ == "__main__":
    # testing clase que implementa Galois fields
    es = 0
    es += testing_GF()

    es += testing_Rcon()

    es += testing_SBox()

    es += testing_SubBytes()

    es += testing_InvSubBytes()

    es += testing_ShiftRows()

    es += testing_InvShiftRows()

    es += testing_MixColumns()

    es += testing_InvMixColumns()

    es += testing_AddRoundKey()

    es += testing_RotWord()

    es += testing_SubWord()

    # Polinomio Irreducible = 0x11B
    # testing_KeyExpansion(key="2b7e151628aed2a6abf7158809cf4f3c", verbose=False) 
    # testing_KeyExpansion(key="8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b", verbose=True)
    # testing_KeyExpansion(key=" 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", verbose=True)

    # Polinomio Irreducible = 0x11

    # Polinomio Irreducible = 0x11B

    testing_Cipher()

    # es += testing_InvCipher()

    print(f"All tested performed with {es} errors")
