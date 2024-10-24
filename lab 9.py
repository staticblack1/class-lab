import string
from idlelib.editor import keynames
from msvcrt import kbhit
from operator import index
from pydoc import plaintext

letter= string.ascii_lowercase + ' '


###def vigenere_square(alphabet):
###    square1= alphabet
 #   square2 = alphabet:-1
  #  for i in range(26):
   #     row =[(square1[(1+i)%26]) for 1 in range(26)]
     #   column =[(square2[(1+i)% 26])for 1 in range(26)]
    #        return row.append(square1.join(square2))


     #   print()

def vigenere_square(alphabet):
    square1= alphabet
    squarelist= []
    for i in range(26):
        row = [(square1[(i + j) % 26]) for j in range(26)]
        squarelist.append(row)
        #print(' '.join(row))
    return squarelist
#print(vigenere_square(letter))

def vigenere_refind(squarelist):
    for i, row in enumerate(squarelist):
        print(f'| {' | '.join(row)} |')
        if i == 0 :
            print('|----'* len(row) +'|')

def letter_to_index(let, alphabet):
    let = let.lower()
    # print(f'{let}, {alphabet}')
    for i, l in enumerate(alphabet.lower()):
        if l == let:
            return i
    return -1

def index_to_letter(alphabet, index):
    i = 0
    for l in alphabet:
        if i == index:
            return l
        i += 1
    return ''
def vigenere_index(key_letter, plaintext_letter,alphabet):
    key_index = letter_to_index(key_letter, alphabet)
    plain_index = letter_to_index(plaintext_letter, alphabet)
    # print(f'{key_index} {plain_index}')
    encrypted_index = (key_index + plain_index)% len(alphabet)

    return index_to_letter(alphabet, encrypted_index)

#key = "loveone"
#plaintext= "everyday live"
def get_key_and_text():
    key = input("Enter encryption key: ")
    text = input("Enter plaintext: ")
    return key, text

def encrypt_vigenere(key, plaintext, alphabet):
    ciphertext = []
    k_len =len(key)
    for i, l in enumerate(plaintext):
        print(f'{i}: {key[i%k_len]},{l}')
        ct = (vigenere_index(key[i%k_len], l, alphabet))
        ciphertext.append(ct)
    return ''.join(ciphertext)

def decrypt_index(key_letter, cipher_letter, alphabet):
    key_index = letter_to_index(key_letter, alphabet)
    cipher_index = letter_to_index(cipher_letter, alphabet)
    plain_index = (cipher_index-key_index+len(alphabet))% len(alphabet)
    return index_to_letter(alphabet, plain_index)

def get_key_and_ct():
    key = input("Enter decryption key: ")
    ct = input("Enter decryption text: ")
    return key, ct
def decrypt_vigenere(key, ciphertext, alphabet):
    decrypttext= []
    k_len =len(key)
    for i, l in enumerate(ciphertext):
        dt = decrypt_index(key[i%k_len], l, alphabet)
        decrypttext.append(dt)
    return ''.join(decrypttext)

encrypted_texts = []

def encrypt():
    global encrypted_texts
    key = input("Enter encryption key: ")
    plaintext = input("Enter plaintext: ")
    ciphertext = encrypt_vigenere(key, plaintext, letter)
    encrypted_texts.append(ciphertext)
    print(f"Encrypted text: {ciphertext}")

def decrypt():
    global encrypted_texts
    key = input("Enter decryption key: ")
    ct = input("Enter decryption text: ")
    #for ct in encrypted_texts:
    decrypted_text = decrypt_vigenere(key, ct, letter)
    print(f"Decrypted text: {decrypted_text}")

def dump_encrypted():
    global encrypted_texts
    print("Encrypted texts:")
    for idx, ct in enumerate(encrypted_texts):
        print(f"{idx + 1}: {ct}")


def main_menu():
    menu_items = [
        ["Encrypt", encrypt],
        ["Decrypt", decrypt],
        ["Dump Encrypted Text", dump_encrypted],
        ["Quit", exit]
    ]

    while True:
        print("\nMenu:")
        for i, (option, _) in enumerate(menu_items):
            print(f"{i + 1}. {option}")

        choice = input("Select an option: ")

        if choice.isdigit() and 1 <= int(choice) <= len(menu_items):
            _, function_to_call = menu_items[int(choice) - 1]
            function_to_call()
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main_menu()


#print(vigenere_refind(vigenere_square(letter)))
#print(letter_to_index('k',letter))
#print(index_to_letter(letter,8))
#print(vigenere_index('o',"o",letter))
#print(encrypt_vigenere(*(get_key_and_text()), letter))
#print(decrypt_index('o','o',letter))
#print(decrypt_vigenere(*(get_key_and_ct()), letter))
(encrypt())
(decrypt())