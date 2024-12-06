HY457 Introduction to Secure Systems
Assignment 1 Cryptogtaphy Algorithms & Key Store
Artemisia Stamataki csd4742

Part A: Cryptogtaphy Algorithms

1. One-time pad
For the encryption algorithm One-time pad i have created a test function in the file tests.c where it takes as
an argument the plaintext, calculates a random key the length of the plaintext and uses that to encrypt the plaintext.
After that it used the generated plaintext and previous random key to decrypt the plaintext.
The one_time_pad_encr function takes as arguments the plaintext the length and the random key and for every character/byte
of the plaintext it xors it with the corresponding byte of the key. one_time_pad_decr function does the exact same thing 
only in place of the plaintext know is the ciphertext.

2. Affine Cipher
For the encryption algorithm Affine Cipher i created a seperate test function that takes as argument the plaintext and encrypts
it and after takes that ciphertext and decrypts it. The function affine_encr takes as input the plaintext and using the ASCII 
encoding and calculating the offsets we map each letter to its corresponding number based on the assignments given table. 
Then the function calculates the equation (5x + 8)mod26 by substituting x for the number of every letter of the plaintext 
and lastly the letters are converted back from numbers to their corresponding characters. Function affine_decr is similar but know
we get as argument the ciphertext and use a different equation (21*(y-8))mod26 but due to (y-1) in the operation and the fact that 
we can have letters with the numbers [0-25] we might get a negative results and in that case we need to perform the equation 
((y % 26) + 26) % 26 to get the correct and positive result.

4. Trithemius Cipher
For the encryption algorithm Trithemius Cipher i created a seperate test function that takes as argument the plaintext and encrypts
it and after takes that ciphertext and decrypts it. The function trithemius_encr takes each plaintext char and maps it to the
corresponding letter in the tabula recta. Similarly the function trithemius_decr takes each plaintext char, searches for the index
of each char in the tabula recta and then maps it to the corresponding alphabet that was not shifted.

5. Scytale Cipher
For the encryption algorithm Scytale Cipher i created a seperate test function that takes as argument the plaintext with the diameter
and encrypts it and after takes that ciphertext with the diameter and decrypts it. Function scytale_encr takes as arguments the plaintext
and the diameter. Gets the parsed_plaintext that contains only the letters of the plaintext without and symbols, numbers or spaces, then
it creates the scytale by placing the letters in the 2d array. Then it reads the ciphertext in column-major order and adda back the 
punctuation, spaces and symbols. Function scytale_decr takes the ciphertext and the diameter and executes the same steps but now using the 
ciphertext instead of the plaintext while being careful to not adding letters to the n empty spaces in the last row of the scytale if the
length of the ciphertext letters is not a multiple of the diameter.

6. Rail-Fence Cipher
For the encryption algorithm Rail-Fence i created a seperate test function that takes as argument the plaintext with the number of rails
and encrypts it and after takes that ciphertext and decrypts it. The functions rail_fence_encr and rail_fence_decr are kind of complicated
and hard to explaint through text, although i have added comments but for better understanding i will explain them during the oral examination.
