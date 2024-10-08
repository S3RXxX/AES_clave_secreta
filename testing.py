from G_F import G_F
from AES import AES

def testing_GF():
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
                print(f"xTimes n={n}: {res}, debería dar {res_correcto} para el polinomio irreducible {hex(polinomio_irreducible)}")

        # provar producto
        for a, b, res_correcto in zip(values_test, value_test_2, correct_results[polinomio_irreducible]["producto"]):
            res = CF.producto(a, b)
            if res != res_correcto:
                print(f"producto a={a}, b={b}: {res}, debería dar {res_correcto} para el polinomio irreducible {hex(polinomio_irreducible)}")
        
        # provar inverso
        for n, res_correcto in zip(values_test, correct_results[polinomio_irreducible]["inverso"]):
            res = CF.inverso(n)
            if res != res_correcto:
                print(f"inverso n={n}: {res}, debería dar {res_correcto} para el polinomio irreducible {hex(polinomio_irreducible)}")
        
        # provar division (multiplicar por el inverso)
        for a, b, res_correcto in zip(values_test, value_test_2, correct_results[polinomio_irreducible]["division"]):
            res = CF.producto(a, CF.inverso(b))
            if res != res_correcto:
                print(f"división a={a}, b={b}: {res}, debería dar {res_correcto} para el polinomio irreducible {hex(polinomio_irreducible)}")
        
    print("All values tested for Galois field")

def testing_Rcon():
    aes = AES(key = 111111)
    print("Rcon:")
    for i in range(10):
        print(aes.Rcon[i])

def testing_SubBytes():
    pass

def testing_InvSubBytes():
    pass

def testing_ShiftRows():
    pass

def testing_InvShiftRows():
    pass

def testing_MixColumns():
    pass

def testing_InvMixColumns():
    pass

def testing_AddRoundKey():
    pass

def testing_KeyExpansion():
    pass

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
    testing_GF()

    # testing_Rcon()



