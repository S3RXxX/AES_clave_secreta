import time
import random
import aes_Sergi_Guimera as aes

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

if __name__=="__main__":
    pass