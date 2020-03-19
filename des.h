#ifndef _DES_H
#define _DES_H

#define MAX_SIZE 64

typedef struct
{
    char v[MAX_SIZE];
    int size;
} text;

extern int R;					//holds number of rounds

void des_initialize();				//initilizes des functions: it is necessary to be called at the beginning.
unsigned long long t2n(text input);  		//converts text to number
text n2t(unsigned long long input, int size); 	//converts number to text
text des_encrypt(text plaintext, text key);	//returns ciphertext of given plaintext and 64-bit key
void des_IP(text *ciphertext);			//takes initial permutation of given text
void des_iIP(text *ciphertext);			//takes inverse initial permutation of given text
void des_shift(text *ciphertext);		//takes shift of given text
text des_ffunction(text input, text subkey);	//takes f-function of given input and subkey
text des_keyschedule(text *key, int round);	//returns the roundkey of given round which is between 0 and R-1, changes global key accordingly
text des_ipc1(text input);			//applies inverse PC-1 permutation to given 56-bit input and outputs 64-bit inverse permuted key
text des_ipc2(text input);			//applies inverse PC-2 permutation to given 48-bit input and outputs 56-bit inverse permuted key
text des_initkey(text key);			//applies PC-1 permutation to given 64-bit key and outputs 56-bit permuted key
text des_expandkey(text input);			//expands 56-bit key to 64-bit

#endif
