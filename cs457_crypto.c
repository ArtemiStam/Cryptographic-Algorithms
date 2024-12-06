/*****************************************************************************
   cs457_crypto.c

   Provides the implementation of all the functions used for Part A Cryptography 
   Algorithms of Assignment 1 in HY457. Artemisia Stamataki csd4742.
******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include "cs457_crypto.h"

char TABULA_RECTA[26][26] = { "ABCDEFGHIJKLMNOPQRSTUVWXYZ","BCDEFGHIJKLMNOPQRSTUVWXYZA","CDEFGHIJKLMNOPQRSTUVWXYZAB","DEFGHIJKLMNOPQRSTUVWXYZABC","EFGHIJKLMNOPQRSTUVWXYZABCD"
,"FGHIJKLMNOPQRSTUVWXYZABCDE","GHIJKLMNOPQRSTUVWXYZABCDEF","HIJKLMNOPQRSTUVWXYZABCDEFG","IJKLMNOPQRSTUVWXYZABCDEFGH","JKLMNOPQRSTUVWXYZABCDEFGHI","KLMNOPQRSTUVWXYZABCDEFGHIJ"
,"LMNOPQRSTUVWXYZABCDEFGHIJK","MNOPQRSTUVWXYZABCDEFGHIJKL","NOPQRSTUVWXYZABCDEFGHIJKLM","OPQRSTUVWXYZABCDEFGHIJKLMN","PQRSTUVWXYZABCDEFGHIJKLMNO","QRSTUVWXYZABCDEFGHIJKLMNOP"
,"RSTUVWXYZABCDEFGHIJKLMNOPQ","STUVWXYZABCDEFGHIJKLMNOPQR","TUVWXYZABCDEFGHIJKLMNOPQRS","UVWXYZABCDEFGHIJKLMNOPQRST","VWXYZABCDEFGHIJKLMNOPQRSTU","WXYZABCDEFGHIJKLMNOPQRSTUV"
,"XYZABCDEFGHIJKLMNOPQRSTUVW","YZABCDEFGHIJKLMNOPQRSTUVWX","ZABCDEFGHIJKLMNOPQRSTUVWXY"};
char *PLAINTEXT_WITH_PANCT; //plaintext that contains the panctuation, letters and spaces to be able to re-insert them after decryption

char *one_time_pad_encr(const char* plaintext, int length, const char* key) {
    char *ciphertext = (char *) malloc(length + 1);
    if (ciphertext == NULL)
    {
        printf("Memory not allocated.\n");
        exit(0);
    }
    
    for (int i = 0; i < length; i++) 
    {
        ciphertext[i] = plaintext[i] ^ key[i]; //xor all the bytes of the plaintext and key
    }
    ciphertext[length] = '\0'; //make ciphertext null terminated

    return ciphertext;
}

char *one_time_pad_decr(const char* ciphertext, int length, const char* key) {
    char *plaintext = (char *) malloc(length + 1);
    if (plaintext == NULL)
    {
        printf("Memory not allocated.\n");
        exit(0);
    }
    
    for (int i = 0; i < length; i++)
    {
        plaintext[i] = ciphertext[i] ^ key[i];//xor all the bytes of the ciphertext and key
    }    
    plaintext[length] = '\0'; //make ciphertext null terminated

    return plaintext;
}

char *affine_encr(char *plaintext) {
    int length = strlen(plaintext);
    char *mapped_plaintext;

    mapped_plaintext = (char *) malloc(length+1);
    if (mapped_plaintext == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }

    for (int i = 0; i < length; i++)
    {
        if (plaintext[i] == 32) { //if char is space leave it as is
            mapped_plaintext[i] = plaintext[i];
            continue;
        
        } else  if (plaintext[i] >= 97 && plaintext[i] <= 122) { //if char is lower case
            mapped_plaintext[i] = plaintext[i] - 97; //map it into the corresponding number
            mapped_plaintext[i] = (mapped_plaintext[i]*5 + 8) % 26;
            mapped_plaintext[i] = 97 + mapped_plaintext[i]; //map it back to a letter
 
        } else if (plaintext[i] >= 65 && plaintext[i] <= 90) { //if char is capital
            mapped_plaintext[i] = plaintext[i] - 65; //map it into the corresponding number
            mapped_plaintext[i] = (mapped_plaintext[i]*5 + 8) % 26;
            mapped_plaintext[i] = 65 + mapped_plaintext[i]; //map it back to a letter
        
        } else {
            printf("\033[0;31mERROR: Invalid character in plaintnext, use only letters and/or spaces\033[0m\n");
            exit(0);
        } 
    }
    
    mapped_plaintext[length] = '\0'; // null terminate the ciphertext
    return mapped_plaintext;
}

char *affine_decr(char *ciphertext) {
    int length = strlen(ciphertext);
    char *mapped_ciphertext;
    int y;

    mapped_ciphertext = (char *) malloc(length+1);
    if (mapped_ciphertext == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }

    for (int i = 0; i < length; i++)
    {
        if (ciphertext[i] == 32) { //if char is space
            mapped_ciphertext[i] = ciphertext[i];
            continue;
        
        } else  if (ciphertext[i] >= 97 && ciphertext[i] <= 122) { //if char is lower case
            mapped_ciphertext[i] = ciphertext[i] - 97;
            y = 21*(mapped_ciphertext[i] - 8);
            if (y < 0) { //if y is negative perform the mod operation so that it doesnt have a negative result
                mapped_ciphertext[i] = ((y % 26) + 26) % 26;
            } else {
                mapped_ciphertext[i] = y % 26;
            }
            mapped_ciphertext[i] = 97 + mapped_ciphertext[i]; //map it back to a letter
 
        } else if (ciphertext[i] >= 65 && ciphertext[i] <= 90) { //if char is capital
            mapped_ciphertext[i] = ciphertext[i] - 65;
            y = 21*(mapped_ciphertext[i] - 8);
            if (y < 0) { //if y is negative perform the mod operation so that it doesnt have a negative result
                mapped_ciphertext[i] = ((y % 26) + 26) % 26;
            } else {
                mapped_ciphertext[i] = y % 26;
            }
            mapped_ciphertext[i] = 65 + mapped_ciphertext[i]; //map it back to a letter
        
        } else {
            printf("\033[0;31mERROR: Invalid character in plaintnext, use only letters and/or spaces\033[0m\n");
            exit(0);
        } 
    }
    
    mapped_ciphertext[length] = '\0'; // null terminate the ciphertext
    return mapped_ciphertext;
}

char *trithemius_encr(char *plaintext) {
    char *ciphertext;
    int length = strlen(plaintext);
    int index = 0;

    ciphertext = (char *) malloc(length + 1);
    if (ciphertext == NULL)
    {
        printf("Memory not allocated.\n");
        exit(0);
    }
    
    for (int i = 0; i < length; i++)
    {
        if (plaintext[i] >= 97 && plaintext[i] <= 122) { //char is lower case letter
            ciphertext[i] = TABULA_RECTA[index++ % 26][plaintext[i] - 97] + 32; /*get the corresponding char from the tabula recta
            and convert it to a lower case becouse the tabula recta has upper case letters*/

        } else if(plaintext[i] >= 65 && plaintext[i] <= 90){ //if char is upper case
            ciphertext[i] = TABULA_RECTA[index++ % 26][plaintext[i] - 65];/*get the corresponding char from the tabula recta
            and DONT convert it to a lower case becouse the plaintext char was upper case and the tabula recta has upper case letters*/

        } else { //if char is not a letter keep it in the ciphertext as is
            ciphertext[i] = plaintext[i];
        }
    }
    
    ciphertext[length] = '\0';
    return ciphertext;
}

char *trithemius_decr(char *ciphertext) {
    char *plaintext;
    int length = strlen(ciphertext);
    int index = 0;
    int j = 0;

    plaintext = (char *) malloc(length + 1);
    if (plaintext == NULL)
    {
        printf("Memory not allocated.\n");
        exit(0);
    }

    for (int i = 0; i < length; i++)
    {
        if (ciphertext[i] >= 97 && ciphertext[i] <= 122) { //char is lower case letter
            j = 0;
            while (TABULA_RECTA[index % 26][j] != ciphertext[i]-32){ //make letter upper case so we can search the tabula recta and find the index of the letter in the ciphertext in the correpsonding line of the tabula recta
                j++;
            }
            plaintext[i] = TABULA_RECTA[0][j] + 32; //get the original letter in the alphabet that was not shifted and make it lower case
            index++;
            
        } else if(ciphertext[i] >= 65 && ciphertext[i] <= 90){ //find the index of the letter in the ciphertext in the correpsonding line of the tabula recta
            j = 0;
            while (TABULA_RECTA[index % 26][j] != ciphertext[i]){
                j++;
            }
            plaintext[i] = TABULA_RECTA[0][j];  //get the original letter in the alphabet that was not shifted 
            index++;
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    
    plaintext[length] = '\0';
    return plaintext;
}

char *scytale_encr(char *plaintext, int diameter) { 
    char** scytale;
    char *ciphertext;
    char *parsed_plaintext;
    char *temp;
    int index = 0, i = 0, j = 0, length, rows;

    assert(diameter > 0);

    temp = (char *) malloc(strlen(plaintext) + 1);
    ciphertext = (char *) malloc(strlen(plaintext) + 1);
    parsed_plaintext = (char *) malloc(strlen(plaintext) + 1); //plaintext without panctuation and spaces is going to be as long as the plaintext or shorter
    if (parsed_plaintext == NULL || ciphertext == NULL || temp == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }

    for (i = 0; i < strlen(plaintext); i++) //create a string with only the letters of the plaintext
    {
        if (((plaintext[i] >= 97 && plaintext[i] <= 122) || (plaintext[i] >= 65 && plaintext[i] <= 90))) {
            parsed_plaintext[index++] = plaintext[i];
        }
    }
    parsed_plaintext[index] = '\0';

    length = strlen(parsed_plaintext);
    if (length % diameter == 0) //take the least number of rows that fit all of the letters of the plaintext
    {
        rows = length / diameter;
    } else { 
        rows = (length / diameter) + 1;
    } 

    scytale = (char**) malloc(rows * sizeof(char*)); //create scytale 2D array
    if (scytale == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }
    for (i = 0; i < rows; i++) {
        scytale[i] = (char*) malloc(diameter);
        if (scytale[i] == NULL) {
            printf("Memory not allocated.\n");
            exit(0);
        }
    }

    index = 0;
    for (i = 0; i < rows; i++) //insert the parsed plaintext into the scytale
    {
        for (j = 0; (j < diameter) && (index < strlen(parsed_plaintext)); j++) { //while we have not reached the diameter or the ciphertext letters are not all in the scytale
            scytale[i][j] = parsed_plaintext[index++];
        } 
    }

    index = 0;
    for (j = 0; j < diameter; j++) //Read the scytale in column-major order to get the letters of the ciphertext 
    {
        for (i = 0; i < rows; i++)
        {
            if ((i*diameter + j) < strlen(parsed_plaintext)) { 
                temp[index++] = scytale[i][j];
            } else {
                continue;
            }
        }
        
    }
    temp[index] = '\0';

    index = 0;
    for ( i = 0; i < strlen(plaintext); i++) //re-insert punctuation and spaces in ciphertext
    {
        if ((plaintext[i] >= 97 && plaintext[i] <= 122) || (plaintext[i] >= 65 && plaintext[i] <= 90)) 
        {
            ciphertext[i] = temp[index++];
        } else {
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[i] = '\0';

    free(temp);
    free(parsed_plaintext);
    for (int i = 0; i < rows; i++) {
        free(scytale[i]);
    }
    free(scytale);

    return ciphertext;
}

char *scytale_decr(char *ciphertext, int diameter) {
    char** scytale;
    char *plaintext;
    char *parsed_ciphertext;
    char *temp;
    int index = 0, i = 0, j = 0, length, rows;

    assert(diameter > 0);

    temp = (char *) malloc(strlen(ciphertext) + 1);
    plaintext = (char *) malloc(strlen(ciphertext) + 1);
    parsed_ciphertext = (char *) malloc(strlen(ciphertext) + 1); //plaintext without panctuation and spaces is going to be as long as the plaintext or shorter
    if (parsed_ciphertext == NULL || plaintext == NULL || temp == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }

    for (i = 0; i < strlen(ciphertext); i++) //create a string with only the letters of the ciphertext
    {
        if (((ciphertext[i] >= 97 && ciphertext[i] <= 122) || (ciphertext[i] >= 65 && ciphertext[i] <= 90))) {
            parsed_ciphertext[index++] = ciphertext[i];
        }
    }
    parsed_ciphertext[index] = '\0';

    length = strlen(parsed_ciphertext);
    if (length % diameter == 0) //take the least number of rows that fit all of the letters of the plaintext
    {
        rows = length / diameter;
    } else {
        rows = (length / diameter) + 1;
    } 

    scytale = (char**) malloc(rows * sizeof(char*)); //create scytale 2D array
    if (scytale == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }
    for (i = 0; i < rows; i++) {
        scytale[i] = (char*) malloc(diameter);
        if (scytale[i] == NULL) {
            printf("Memory not allocated.\n");
            exit(0);
        }
    }

    index = 0;
    for (j = 0; j < diameter; j++) //insert the parsed ciphertext into the scytale
    {
        for (i = 0; (i < rows) && (index < strlen(parsed_ciphertext)); i++) {
            if ((i < rows-1) || ((i == rows-1) && (j < (diameter - (rows*diameter - strlen(parsed_ciphertext)))))) { //add letters in column-wise order (without adding letters to the n empty spaces in the last row of the scytale if the length of the ciphertext letters is not a multiple of the diameter)
                scytale[i][j] = parsed_ciphertext[index++];
            }
        } 
    }

    /*for (i = 0; i < rows; i++) //print scytale
    {
        for (j = 0; j < diameter; j++)
        {
            printf("%c ", scytale[i][j]);
        }
        printf("\n");
    }*/

    index = 0;
    for (i = 0; i < rows; i++)
    {
        for (j = 0; j < diameter; j++)
        {
            if ((i*diameter + j) < strlen(parsed_ciphertext)) { //while we havent reached the last letter of the scytale
                temp[index++] = scytale[i][j];
            } else {
                continue;
            }
        }
        
    }
    temp[index] = '\0';

    index = 0;
    for ( i = 0; i < strlen(ciphertext); i++) //re-insert punctuation and spaces in ciphertext
    {
        if ((ciphertext[i] >= 97 && ciphertext[i] <= 122) || (ciphertext[i] >= 65 && ciphertext[i] <= 90)) 
        {
            plaintext[i] = temp[index++];
        } else {
            plaintext[i] = ciphertext[i];
        }
    }
    plaintext[i] = '\0';

    free(temp);
    free(parsed_ciphertext);
    for (i = 0; i < rows; i++) {
        free(scytale[i]);
    }
    free(scytale);
    
    return plaintext;
}

char *rail_fence_encr(char *plaintext, int num_rails) {
    char** arr;
    char *ciphertext;
    char *parsed_plaintext;
    int index = 0, i = 0, j = 0, length, mode = 0;

    assert(num_rails != 0 && plaintext != NULL);

    PLAINTEXT_WITH_PANCT = plaintext; //save plaintext so that during decryprion we can re-insert the punctuation,spaces and symbols
    ciphertext = (char *) malloc(strlen(plaintext) + (num_rails-1) + 1);
    parsed_plaintext = (char *) malloc(strlen(plaintext) + 1); //plaintext without panctuation and spaces is going to be as long as the plaintext or shorter
    if (parsed_plaintext == NULL || ciphertext == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }

    for (i = 0; i < strlen(plaintext); i++) //create a string with only the letters of the plaintext
    {
        if (((plaintext[i] >= 97 && plaintext[i] <= 122) || (plaintext[i] >= 65 && plaintext[i] <= 90))) {
            parsed_plaintext[index++] = plaintext[i];
        }
    }
    parsed_plaintext[index] = '\0';

    length = strlen(parsed_plaintext);
    arr = (char**) malloc(num_rails * sizeof(char*)); //create scytale 2D array
    if (arr == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }
    for (i = 0; i < num_rails; i++) {
        arr[i] = (char*) malloc(length);
        if (arr[i] == NULL) {
            printf("Memory not allocated.\n");
            exit(0);
        }
    }

    for (i = 0; i < num_rails; i++) //initialize array with spaces
    {
        for (j = 0; j < length; j++)
        {
            arr[i][j] = ' ';
        }
    }
    
    i = 0;
    mode = 0;
    index = 0;
    for (j = 0; j < length; j++) //insert the parsed plaintext into the rails
    {
        if (mode == 0) //mode == 0 means going down, mode == 1 means going up
        {
            if (num_rails == 1) {
                arr[i][j] = parsed_plaintext[j];
            }
            else if (i == num_rails - 1) {
                mode = 1;
                arr[i--][j] = parsed_plaintext[j];
            }
            else {
                arr[i++][j] = parsed_plaintext[j];
            }
        } else {
            if (i == 0)
            {
                mode = 0;
                arr[i++][j] = parsed_plaintext[j];
            } else {
                arr[i--][j] = parsed_plaintext[j];
            }   
        }
    }

    /*for (i = 0; i < num_rails; i++) //print array
    {
        for (j = 0; j < length; j++)
        {
            printf("%c", arr[i][j]);
        }
        printf("\n");
    }*/    

    index = 0;
    for (i = 0; i < num_rails; i++)
    {
        for (j = 0; j < length; j++)
        {
            if ((arr[i][j] >= 97 && arr[i][j] <= 122) || (arr[i][j] >= 65 && arr[i][j] <= 90))
            {
                ciphertext[index++] = arr[i][j];
            }
        }
        ciphertext[index++] = ' ';
    }
    ciphertext[index-1] = '\0';

    free(parsed_plaintext);
    for (int i = 0; i < num_rails; i++) {
        free(arr[i]);
    }
    free(arr);
    
    return ciphertext;
}

char *rail_fence_decr(char *ciphertext) {
    char *plaintext;
    char *parsed_plaintext;
    int  *indexes;
    char *token;
    char *temp;
    char **ciphertext_arr;
    int i = 0, j = 0, mode = 0, num_rails = 0, rows = 0, index = 0;

    temp = (char *) malloc(strlen(ciphertext) + 1); //we need temp because strotk changes the input string and we dont want to change ciphertext
    if (temp == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }
    strcpy(temp, ciphertext); //copy the contents of ciphertext to temp
    
    for (i = 0; i < strlen(ciphertext); i++) //get the number of rails from ciphertext
    {
        if (ciphertext[i] == ' ')
        {
            num_rails++;
        }
    }
    num_rails++;
   
    ciphertext_arr = (char **) malloc(num_rails*sizeof(char *));
    if (ciphertext_arr == NULL)
    {
        printf("Memory not allocated.\n");
        exit(0);
    }
    
    rows = 0;
    token = strtok(temp, " ");
    ciphertext_arr[rows] = temp;
    while (token != NULL)
    {
        token = strtok(NULL, " ");
        ciphertext_arr[++rows] = token;
    }

    indexes = (int *) malloc(rows*sizeof(int)); //indexes will cotnain the index of each row and will be used to decrypt the ciphertext
    if (indexes == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }

    for (i = 0; i < num_rails && i < rows; i++) //while j is smaller than the number of rails and smaller that the created rows in the ciphertext array(because when the num of rails is bigger than the ciphertext we have to check that)
    {
        indexes[i] = 0;
        //printf("%s\n", ciphertext_arr[i]);
    }
    
    plaintext = (char *) malloc(strlen(PLAINTEXT_WITH_PANCT) + 1);
    parsed_plaintext = (char *) malloc(strlen(ciphertext) - (num_rails-1)  + 1); //plaintext without panctuation and spaces is going to be as long as the plaintext or shorter
    if (parsed_plaintext == NULL || plaintext == NULL) {
        printf("Memory not allocated.\n");
        exit(0);
    }
    
    i = 0;
    j = 0;
    index = 0;
    mode = 0;
    while (index < (strlen(ciphertext) - (num_rails-1))) //insert the parsed plaintext into the rails
    {
        if (mode == 0) //mode == 0 means going down, mode == 1 means going up
        {
            if (num_rails == 1) {
                parsed_plaintext[index++] = ciphertext_arr[i][j++];
            } else if (i == rows - 1) {
                mode = 1;
                parsed_plaintext[index++] = ciphertext_arr[i][indexes[i]++];
                i--;
            } else {
                parsed_plaintext[index++] = ciphertext_arr[i][indexes[i]++];
                i++;
            }
        } else {
            if (i == 0)
            {
                mode = 0;
                parsed_plaintext[index++] = ciphertext_arr[i][indexes[i]++];
                i++;
            } else {
                parsed_plaintext[index++] = ciphertext_arr[i][indexes[i]++];
                i--;
            }   
        }
    }
    //parsed_plaintext[index] = '\0';

    index = 0;
    for (i = 0; i < strlen(PLAINTEXT_WITH_PANCT); i++) //index now contains the length of the parsed_plaintext
    {
        if ((PLAINTEXT_WITH_PANCT[i] >= 97 && PLAINTEXT_WITH_PANCT[i] <= 122) || (PLAINTEXT_WITH_PANCT[i] >= 65 && PLAINTEXT_WITH_PANCT[i] <= 90))
        {
            plaintext[i] = parsed_plaintext[index++];
        } else {
            plaintext[i] = PLAINTEXT_WITH_PANCT[i];
        }
    }
    plaintext[i] = '\0';
    
   free(temp);
   free(ciphertext_arr);
   free(indexes);
   free(parsed_plaintext);

   return plaintext;

}