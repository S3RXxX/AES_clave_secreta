# test descifrar
import time
import random
import aes_Sergi_Guimera as aes

def decrypt(key, pol, path, gt_path):

    aes1 = aes.AES(key=key, Polinomio_Irreducible = pol)
    print(f"Doing {path} with IP={pol} and key={key}")
    start_decrypt = time.time()
    aes1.decrypt_file(path)
    end_decrypt = time.time()
    print(f"Tiempo de descifrado: {end_decrypt - start_decrypt:.3f} segundos")

    compare_files(path+'.dec', gt_path)


def compare_files(file1, file2):
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        file1_contents = f1.read()
        file2_contents = f2.read()

    if file1_contents == file2_contents:
        print("The files are identical.")
    else:
        print("The files are different!!!!!!!!!!!!!!!!!!!!!!!!")
        print(file1, file2)
    print()

def parsero(s, d):
    dicc = {"path": d+s}
    
    aux = s.split(".")[1]
    ll = aux.split("_")[1:]
    dicc["pol"] = int(ll[0], 16)
    dicc["key"] = key = bytearray.fromhex(ll[1])

    dicc["gt"] = d + s.split(".")[0] + "." + aux[0:3]
    return dicc

if __name__=="__main__":
    ss = [
            """mandril.png_0x11b_184d0214afe945d315339b6d92b01c0f.enc"""
            ,
            """mandril.png_0x11d_a26d65fdd2fea302638290cdd2cbf626.enc""",
            """wells_the_time_machine.txt_0x11b_4887d4193e4bc8c8d850c1e12adcb3ab.enc""",
            """wells_the_time_machine.txt_0x11d_265f23ddc4dfc43f00f8401f446d6c81.enc"""
        ]
    
    d = "./Valores_test/"
    s = "mandril.png_0x11b_184d0214afe945d315339b6d92b01c0f.enc"
    lst = []
    for s in ss:
        lst.append(parsero(s=s, d=d))

    for info in lst:
        decrypt(key=info["key"], pol=info["pol"], path=info["path"], gt_path=info["gt"])



