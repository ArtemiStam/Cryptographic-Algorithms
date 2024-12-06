/*****************************************************************************
   cs457_crypto.h

   Provides the declaration of all the functions used for Part A Cryptography 
   Algorithms of Assignment 1 in HY457. Artemisia Stamataki csd4742.
******************************************************************************/

#ifndef _CS457_CRYPTO_H_ 
#define _CS457_CRYPTO_H_ 

char *one_time_pad_encr(const char* plaintext, int length, const char* key);

char *one_time_pad_decr(const char* ciphertext, int length, const char* key);

char *affine_encr(char *plaintext);

char *affine_decr(char *ciphertext);

char *trithemius_encr(char *plaintext);

char *trithemius_decr(char *ciphertext);

char *scytale_encr(char *plaintext, int diameter);

char *scytale_decr(char *ciphertext, int diameter);

char *rail_fence_encr(char *plaintext, int num_rails);

char *rail_fence_decr(char *ciphertext);

#endif