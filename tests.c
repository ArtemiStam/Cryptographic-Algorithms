/*****************************************************************************
   tests.c

   Provides the testing of all the functions used for Part A Cryptography 
   Algorithms of Assignment 1 in HY457. Artemisia Stamataki csd4742.
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cs457_crypto.h"

void one_time_pad_test(char *plaintext) {
    char *decrypted_plaintext;
    char *ciphertext;
    char *key;
    FILE* fp;
    int plaintextsize; 

    plaintextsize = (int)strlen(plaintext);
    
    fp = fopen("/dev/urandom", "r"); //read from /de/urandom
    if (fp == NULL) {
        printf("The file is not opened. The program will exit now");
        exit(0);
    }
    else {
        key = (char *) malloc(plaintextsize + 1); // + 1 for the "/0" null termination
        fread(key, 1, plaintextsize, fp); //Read plaintextsize number of bytes from /dev/urandom and store them in key
        key[plaintextsize] = '\0'; //make stream of bytes null terminated
        fclose(fp);
    }
    printf("\n-----------------One time pad-----------------\n");
    printf("Plaintext: %s\n", plaintext);
    printf("Key: %s\n", key);
    
    ciphertext = one_time_pad_encr(plaintext, plaintextsize, key);
    printf("Ciphertext: %s\n", ciphertext);
    decrypted_plaintext = one_time_pad_decr(ciphertext, plaintextsize, key);
    printf("Decrypted plaintext: %s\n", decrypted_plaintext);

    free(key);
    free(ciphertext);
    free(decrypted_plaintext);
}

void affain_test(char *plaintext) {
    char *ciphertext;
    char *decrypted_plaintext;

    printf("\n-----------------Affain Cipher----------------\n");
    printf("Plaintext: %s\n", plaintext);
    ciphertext = affine_encr(plaintext);
    printf("Ciphertext: %s\n", ciphertext);
    decrypted_plaintext = affine_decr(ciphertext);
    printf("Decrypted plaintext: %s\n", decrypted_plaintext);

    free(ciphertext);
    free(decrypted_plaintext);
}

void trithemus_test(char *plaintext) {
    char *ciphertext;
    char *decrypted_plaintext;

    printf("\n-----------------Trithemius Cipher------------\n");
    printf("Plaintext: %s\n", plaintext);
    ciphertext = trithemius_encr(plaintext);
    printf("Ciphertext: %s\n", ciphertext);
    decrypted_plaintext = trithemius_decr(ciphertext);
    printf("Decrypted plaintext: %s\n", decrypted_plaintext);

    free(ciphertext);
    free(decrypted_plaintext);
}

void scytale_test(char *plaintext, int diameter) {
    char *ciphertext;
    char *decrypted_plaintext;

    printf("\n-----------------Scytale Cipher---------------\n");
    printf("Diameter: %d\n", diameter);
    printf("Plaintext: %s\n", plaintext);
    ciphertext = scytale_encr(plaintext, diameter);
    printf("Ciphertext: %s\n", ciphertext);
    decrypted_plaintext = scytale_decr(ciphertext, diameter);
    printf("Decrypted plaintext: %s\n", decrypted_plaintext);

    free(ciphertext);
    free(decrypted_plaintext);
}

void rail_fence_test(char *plaintext, int rails) {
    char *ciphertext;
    char *decrypted_plaintext;

    printf("\n-----------------Scytale Cipher---------------\n");
    printf("Rails: %d\n", rails);
    printf("Plaintext: %s\n", plaintext);
    ciphertext = rail_fence_encr(plaintext, rails);
    printf("Ciphertext: %s\n", ciphertext);
    decrypted_plaintext = rail_fence_decr(ciphertext);
    printf("Decrypted plaintext: %s\n", decrypted_plaintext);

    free(ciphertext);
    free(decrypted_plaintext);
}

int main(void) 
{
    char *plaintext;
    int   diameter, rails;

/*-----------------One-time pad--------------------------*/
    plaintext = "ThisIsACat";
    one_time_pad_test(plaintext);
    
    plaintext = "QuickLittleFox123";
    one_time_pad_test(plaintext);

   
/*-----------------Affine Cipher--------------------------*/
    plaintext = "AFFINECIPHER";
    affain_test(plaintext);

    plaintext = "Little BlaCk DOG";
    affain_test(plaintext);

/*-----------------Trithemius Cipher-----------------------*/
    plaintext = "HElLO";
    trithemus_test(plaintext);

    plaintext = "1AC !DC";
    trithemus_test(plaintext);

/*-----------------Scytale Cipher-----------------------*/
    diameter = 5;
    plaintext = "I am hurt very badly help";
    scytale_test(plaintext, diameter);

    diameter = 3;
    plaintext = "I am hurt very badly help";
    scytale_test(plaintext, diameter);

    diameter = 8;
    plaintext = "I am hurt very badly help";
    scytale_test(plaintext, diameter);

    diameter = 6;
    plaintext = "Her phone number is: 697841@#35&*557!";
    scytale_test(plaintext, diameter);

/*-----------------Rail-Fence Cipher---------------------*/
    rails = 3;
    plaintext = "I... am hurt -very- badly help me please";
    rail_fence_test(plaintext, rails);

    rails = 5;
    plaintext = "I... am hurt -very- badly help me please";
    rail_fence_test(plaintext, rails);
   
    return 0;
}