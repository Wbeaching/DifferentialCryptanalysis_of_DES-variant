/*
Bilkent University Computer Engineering
CS519 Cryptography and Network Security
Fall 2010
Project #1: Differential Cryptanalysis of DES-variant

Based on: http://www.cs.bilkent.edu.tr/~selcuk/teaching/cs519/Biham-DC.pdf

Authors:
Halil Kemal TASKIN
Murat DEMIRCIOGLU

*/

#include <stdio.h>
//#include <conio.h>
#include <math.h>
#include <time.h>
#include <stdlib.h>
#include <inttypes.h>

#include "des.c"

int main()
{
    srand (time(NULL));

    time_t t0,t1;

	unsigned long long MainKey;
    unsigned long long subkey;

    // generate a random initial state for the LFSR
    unsigned long long initialplaintext = rand();
    unsigned long long plaintext;
    unsigned long long plaintext2;
    unsigned long long ciphertext;
    unsigned long long ciphertext2;
    unsigned long long cipherdiff;
    unsigned long long XORresult;

    unsigned long long RightC1[4];
    unsigned long long RightC2[4];
    unsigned long long RightP1[4];
    unsigned long long RightP2[4];

    unsigned long long omegap, sayac, limit;

    char Keys[1<<18];

    unsigned long long pSubKeys[4][16];

    int AttackNo;
    int PSKcounter;
    int gecen, RightPairCount;

    text t_key;
    text t_plaintext;
    text t_plaintext2;
    text t_ciphertext;
    //text t_cipherdiff;

    unsigned long long cipherdiffL;
    text t_cipherdiffL;
    text t_cdLtemp;

    unsigned long long ust1;
    unsigned long long ust2;
    unsigned long long ust3;

    text t_input1;
    text t_input2;
    unsigned long long RC1,RC2;

    // for the main key recovery
    text RealRealKey, TestKey, MutluAnahtar, t_RealKey, t_kk, t_TempC1, t_TempC2, t_TempP1, t_TempP2;
    unsigned long long TempC1, TempC2;

    des_initialize();

    printf("Halil Kemal TASKIN - Murat DEMIRCIOGLU\nCS519 Project 1: Differential Cryptanalysis of DES-variant.\n\n");
    printf("DES Round Number: %d and the S-Box order is: ", R);
    for(int t=0; t<8; t++)printf("%d ",s[t]+1);

    printf("\n\nEnter Key (14 digit hexadecimal): ");
    scanf("%" PRIx64, &MainKey);

    // save the time
    t0 = time(NULL);

    t_key = des_expandkey(n2t(MainKey, 56));

    // plaintext requirement for 8 round : 2^24
    // plaintext requirement for 6 round : 2^17

    printf("\nInitial Plaintext for 64-bit mLFSR: HEX=%llx DEC=%llu\n\n",initialplaintext,initialplaintext);

    // print round keys
    text tempkey = des_initkey(t_key);
    for(int round=0; round<R; round++)
    {
        printf("Round %d Key: 0x%012" PRIx64 "\n", round+1,(unsigned long long)t2n(des_keyschedule(&tempkey,round)));
    }

    // clear pSubKeys array
    for(int y=0; y<4; y++)
    {
        for(int z=0; z<16; z++)
        {
            pSubKeys[y][z] = 0;
        }
    }

//ATTACK 1 : 3-4-7 -------------------------------------------------------------------------------------------------

    //START FINDING RIGHT PAIRS
    //--------------------------------------------------------
    //parameters
    plaintext = initialplaintext;
    gecen = 0;
    AttackNo = 0;
    omegap = 0x0194000000000000u;
    // limit = 146^2 * 4 < 2^18
    limit = 1<<24;
    sayac = 0;
    RightPairCount = 4;
    PSKcounter = 0;

    for(int m = 0; m < 64; m++)
    {
        RightC1[m] = 0;
        RightC2[m] = 0;
    }

    printf("\n(3-4-7) Started finding right pairs...\n");
    do
    {
        sayac++;

        // clock the lfsr to generate another plaintext.
        // 64-bit m-LFSR taps: 64 63 61 60; characteristic polynomial: x^64 + x^63 + x^61 + x^60 + 1
        plaintext = (plaintext >> 1) ^ (unsigned long long)((0 - (plaintext & 1u)) & 0xD800000000000000u);

        t_plaintext = n2t(plaintext, 64);

        // apply inverse IP to eliminate the IP in the DES
        des_iIP(&t_plaintext);
        // encrypt the plaintext
        t_ciphertext = des_encrypt(t_plaintext,t_key);
        // apply IP to eliminate the inverse IP at the end of the DES
        des_IP(&t_ciphertext);

        // result is ciphertext
        ciphertext = t2n(t_ciphertext);

        // generate the second plaintext with the selected difference omegap
        plaintext2 = plaintext ^ omegap;

        // encrypt the new plaintext
        t_plaintext2 = n2t(plaintext2,64);

        des_iIP(&t_plaintext2);
        text t_ciphertext2 = des_encrypt(t_plaintext2,t_key);
        des_IP(&t_ciphertext2);

        // result is ciphertex2
        ciphertext2 = t2n(t_ciphertext2);

        // compute the difference between ciphertext and ciphertext2
        //, mask;
        cipherdiff = ciphertext ^ ciphertext2;

        // apply the inverse P to the cipherdiff to eliminate the effect of the permutation P at the end of the f function in a round of DES
        cipherdiffL = cipherdiff >> 32;
        t_cipherdiffL = n2t(cipherdiffL,32);
        t_cdLtemp = t_cipherdiffL;
        for(int x = 0; x<32; x++)
        {
            t_cipherdiffL.v[x] = t_cdLtemp.v[isp[x]-1];
        }
        cipherdiffL = t2n(t_cipherdiffL);
        cipherdiff = ((cipherdiff<<32)>>32) ^ (cipherdiffL<<32);

        // check for the cipherdiff it it satisfies the certain properties for our difference omegap
        ust1 = pow(2,60); // 1<<60;
        ust2 = pow(2,48); // 1<<48;
        ust3 = 26476544; // 0x01940000u
        if ((cipherdiff % ust2 == ust3) && (cipherdiff < ust1))
        {
            printf("\n\nPlaintext : 0x%016" PRIx64 "\nDifference: 0x%016" PRIx64 "\n\n",plaintext,cipherdiff);
            //t_cipherdiff = n2t(cipherdiff,64);
            //print_cipher(t_cipherdiff);

            RightC1[gecen] = ciphertext;
            RightC2[gecen] = ciphertext2;

            gecen++;
            // if the right pair count is 4 then stop searching for the right pair.
            if (gecen>(RightPairCount-1)) break;
        }

        // show the percentage ofthe progress for finding right pairs.
        if(sayac % (limit/100) == 0) printf("%llu-", ((sayac*100)/limit)+1);

    }
    while(sayac < limit);

    if(gecen != RightPairCount)
    {
        printf("\n\nEnough right pairs couldn't be found. Please restart application to try again.\nPress any key to exit...");
        //getch();
        return 0;
    }

    printf("Found %d pairs. Starting to find the partial subkeys...", gecen);

    //START THE ATTACK TO RECOVER PARTIAL SUBKEY BITS
    //--------------------------------------------------------
    printf("\nPlease Wait...\n\n");

    // Reset the counter for the candidate partial subkeys.
    for(unsigned long long key = 0; key < (1<<18); key++)
    {
        Keys[key] = 0;
    }

    // look for every pair
    for(int i = 0; i <gecen; i++)
    {
        // look for every subkey which is 18-bit
        for(unsigned long long key = 0; key < (1<<18); key++)
        {
            // place the key in the corresponding place w.r.t. S-Boxes
            subkey = (key <<24);

            RC1 = RightC1[i];
            RC2 = RightC2[i];

            t_input1 = n2t(RC1,64);
            t_input2 = n2t(RC2,64);

            // apply 1 round encrytion to ciphertext pairs
            round_des(&t_input1, n2t(subkey,48));
            round_des(&t_input2, n2t(subkey,48));

            RC1 = t2n(t_input1);
            RC2 = t2n(t_input2);

            // compute the difference of C1 and C2
            XORresult = RC1 ^ RC2;

            // check the differece is as expected or not
            if(XORresult == omegap)
            {
                // increase the counter for the corresponding subkey
                Keys[key]++;
            }
        }
    }

    // write the partial subkey data for the subkeys which gives the highest count.
    printf("Candidates: \n");
    for(unsigned long long key = 0; key < (1<<18); key++)
    {
        if((Keys[key] == gecen) && (gecen > 0))
        {
            printf("Count: %d and the partial subkey bits: ", gecen);
            pSubKeys[AttackNo][PSKcounter] = key;
            PSKcounter++;
            print_binary(n2t(key,18),18);
        }
    }





//ATTACK 2 : 1-6-8 -------------------------------------------------------------------------------------------------





    //START FINDING RIGHT PAIRS
    //--------------------------------------------------------
    plaintext = initialplaintext;
    gecen = 0;
    AttackNo = 1;
    omegap = 0x000001D400000000u;
    // limit = 234^2 * 4
    limit = 1<<24;
    sayac = 0;
    RightPairCount = 4;
    PSKcounter = 0;

    for(int m = 0; m < 64; m++)
    {
        RightC1[m] = 0;
        RightC2[m] = 0;
    }

    printf("\n(1-6-8) Started finding right pairs...\n");
    do
    {
        sayac++;

        // clock the lfsr to generate another plaintext.
        // 64-bit m-LFSR taps: 64 63 61 60; characteristic polynomial: x^64 + x^63 + x^61 + x^60 + 1
        plaintext = (plaintext >> 1) ^ (unsigned long long)((0 - (plaintext & 1u)) & 0xD800000000000000u);

        t_plaintext = n2t(plaintext, 64);

        // apply inverse IP to eliminate the IP in the DEs
        des_iIP(&t_plaintext);
        // encrypt the plaintext
        t_ciphertext = des_encrypt(t_plaintext,t_key);
        // apply IP to eliminate the inverse IP at the end of the DES
        des_IP(&t_ciphertext);

        // result is ciphertext
        ciphertext = t2n(t_ciphertext);

        // generate the second plaintext with the selected difference omegap
        plaintext2 = plaintext ^ omegap;

        // encrypt the new plaintext
        t_plaintext2 = n2t(plaintext2,64);

        des_iIP(&t_plaintext2);
        text t_ciphertext2 = des_encrypt(t_plaintext2,t_key);
        des_IP(&t_ciphertext2);

        // result is ciphertex2
        ciphertext2 = t2n(t_ciphertext2);

        // compute the difference between ciphertext and ciphertext2
        //, mask;
        cipherdiff = ciphertext ^ ciphertext2;

        // apply the inverse P to the cipherdiff to eliminate the effect of the permutation P at the end of the f function in a round of DES
        cipherdiffL = cipherdiff >> 32;
        t_cipherdiffL = n2t(cipherdiffL,32);
        t_cdLtemp = t_cipherdiffL;
        for(int x = 0; x<32; x++)
        {
            t_cipherdiffL.v[x] = t_cdLtemp.v[isp[x]-1];
        }
        cipherdiffL = t2n(t_cipherdiffL);
        cipherdiff = ((cipherdiff<<32)>>32) ^ (cipherdiffL<<32);

        // check for the cipherdiff if it satisfies the certain properties for our difference omegap
        ust1 = pow(2,44); // 1<<44;
        ust2 = pow(2,32); // 1<<48;
        ust3 = 468; // 0x000001D4u
        if ((cipherdiff % ust2 == ust3) && (cipherdiff < ust1))
        {
            printf("\n\nPlaintext : 0x%016" PRIx64 "\nDifference: 0x%016" PRIx64 "\n\n",plaintext,cipherdiff);
            //printf("\n\nPlaintext (Hex) : %llx\nThe found ciphertext difference is:\n",plaintext);
            //t_cipherdiff = n2t(cipherdiff,64);
            //print_cipher(t_cipherdiff);

            RightC1[gecen] = ciphertext;
            RightC2[gecen] = ciphertext2;

            gecen++;
            // if the right pair count is 4 then stop searching for the right pair.
            if (gecen>(RightPairCount-1)) break;
        }

        // show the percentage ofthe progress for finding right pairs.
        if(sayac % (limit/100) == 0) printf("%llu-", ((sayac*100)/limit)+1);

    }
    while(sayac < limit);

    if(gecen != RightPairCount)
    {
        printf("\n\nEnough right pairs couldn't be found. Please restart application to try again.\nPress any key to exit...");
        //getch();
        return 0;
    }

    printf("Found %d pairs. Starting to find the partial subkeys...", gecen);

    //START THE ATTACK TO RECOVER PARTIAL SUBKEY BITS
    //--------------------------------------------------------
    printf("\nPlease Wait...\n\n");

    // Reset the counter for the candidate partial subkeys.
    for(unsigned long long key = 0; key < (1<<18); key++)
    {
        Keys[key] = 0;
    }

    // look for every pair
    for(int i = 0; i <gecen; i++)
    {
        // look for every subkey which is 18-bit
        for(unsigned long long key = 0; key < (1<<18); key++)
        {
            // place the key in the corresponding place w.r.t. S-Boxes
            subkey = key;

            RC1 = RightC1[i];
            RC2 = RightC2[i];

            t_input1 = n2t(RC1,64);
            t_input2 = n2t(RC2,64);

            // apply 1 round encrytion to ciphertext pairs
            round_des(&t_input1, n2t(subkey,48));
            round_des(&t_input2, n2t(subkey,48));

            RC1 = t2n(t_input1);
            RC2 = t2n(t_input2);

            // compute the difference of C1 and C2
            XORresult = RC1 ^ RC2;

            // check the differece is as expected or not
            if(XORresult == omegap)
            {
                // increase the counter for the corresponding subkey
                Keys[key]++;
            }
        }
    }

    // write the partial subkey data for the subkeys which gives the highest count.
    printf("Candidates: \n");
    for(unsigned long long key = 0; key < (1<<18); key++)
    {
        if((Keys[key] == gecen) && (gecen > 0))
        {
            printf("Count: %d and the partial subkey bits: ", gecen);
            pSubKeys[AttackNo][PSKcounter] = key;
            PSKcounter++;
            print_binary(n2t(key,18),18);
        }
    }






//ATTACK 3 : 7-2-1 -------------------------------------------------------------------------------------------------






    //START FINDING RIGHT PAIRS
    //--------------------------------------------------------
    plaintext = initialplaintext;
    gecen = 0;
    AttackNo = 2;
    omegap = 0x0001940000000000u;
    // limit = 341^2 * 4 < 2^19
    limit = 1<<24;
    sayac = 0;
    RightPairCount = 4;
    PSKcounter = 0;

    for(int m = 0; m < 64; m++)
    {
        RightC1[m] = 0;
        RightC2[m] = 0;
    }

    printf("\n(7-2-1) Started finding right pairs...\n");
    //for(plaintext = 0; plaintext < limit; plaintext++)
    //plaintext = rand();
    do
    {
        sayac++;

        // clock the lfsr to generate another plaintext.
        // 64-bit m-LFSR taps: 64 63 61 60; characteristic polynomial: x^64 + x^63 + x^61 + x^60 + 1
        plaintext = (plaintext >> 1) ^ (unsigned long long)((0 - (plaintext & 1u)) & 0xD800000000000000u);

        t_plaintext = n2t(plaintext, 64);

        // apply inverse IP to eliminate the IP in the DEs
        des_iIP(&t_plaintext);
        // encrypt the plaintext
        t_ciphertext = des_encrypt(t_plaintext,t_key);
        // apply IP to eliminate the inverse IP at the end of the DES
        des_IP(&t_ciphertext);

        // result is ciphertext
        ciphertext = t2n(t_ciphertext);

        // generate the second plaintext with the selected difference omegap
        plaintext2 = plaintext ^ omegap;

        // encrypt the new plaintext
        t_plaintext2 = n2t(plaintext2,64);

        des_iIP(&t_plaintext2);
        text t_ciphertext2 = des_encrypt(t_plaintext2,t_key);
        des_IP(&t_ciphertext2);

        // result is ciphertex2
        ciphertext2 = t2n(t_ciphertext2);

        // compute the difference between ciphertext and ciphertext2
        //, mask;
        cipherdiff = ciphertext ^ ciphertext2;

        // apply the inverse P to the cipherdiff to eliminate the effect of the permutation P at the end of the f function in a round of DES
        cipherdiffL = cipherdiff >> 32;
        t_cipherdiffL = n2t(cipherdiffL,32);
        t_cdLtemp = t_cipherdiffL;
        for(int x = 0; x<32; x++)
        {
            t_cipherdiffL.v[x] = t_cdLtemp.v[isp[x]-1];
        }
        cipherdiffL = t2n(t_cipherdiffL);
        cipherdiff = ((cipherdiff<<32)>>32) ^ (cipherdiffL<<32);

        // check for the cipherdiff if it satisfies the certain properties for our difference omegap
        ust1 = pow(2,52);
        ust2 = pow(2,40);
        ust3 = 103424; // 0x19400u;
        if ((cipherdiff % ust2 == ust3) && (cipherdiff < ust1))
        {
            printf("\n\nPlaintext : 0x%016" PRIx64 "\nDifference: 0x%016" PRIx64 "\n\n",plaintext,cipherdiff);
            //printf("\n\nPlaintext (Hex) : %llx\nThe found ciphertext difference is:\n",plaintext);
            //t_cipherdiff = n2t(cipherdiff,64);
            //print_cipher(t_cipherdiff);

            RightC1[gecen] = ciphertext;
            RightC2[gecen] = ciphertext2;

            gecen++;
            // if the right pair count is 4 then stop searching for the right pair.
            if (gecen>(RightPairCount-1)) break;
        }

        // show the percentage ofthe progress for finding right pairs.
        if(sayac % (limit/100) == 0) printf("%llu-", ((sayac*100)/limit)+1);

    }
    while(sayac < limit);

    if(gecen != RightPairCount)
    {
        printf("\n\nEnough right pairs couldn't be found. Please restart application to try again.\nPress any key to exit...");
        //getch();
        return 0;
    }

    printf("Found %d pairs. Starting to find the partial subkeys...", gecen);

    //START THE ATTACK TO RECOVER PARTIAL SUBKEY BITS
    //--------------------------------------------------------
    printf("\nPlease Wait...\n\n");

    // Reset the counter for the candidate partial subkeys.
    for(unsigned long long key = 0; key < (1<<18); key++)
    {
        Keys[key] = 0;
    }

    // look for every pair
    for(int i = 0; i <gecen; i++)
    {
        // look for every subkey which is 18-bit
        for(unsigned long long key = 0; key < (1<<18); key++)
        {
            // place the key in the corresponding place w.r.t. S-Boxes
            subkey = (key<<12);

            RC1 = RightC1[i];
            RC2 = RightC2[i];

            t_input1 = n2t(RC1,64);
            t_input2 = n2t(RC2,64);

            // apply 1 round encrytion to ciphertext pairs
            round_des(&t_input1, n2t(subkey,48));
            round_des(&t_input2, n2t(subkey,48));

            RC1 = t2n(t_input1);
            RC2 = t2n(t_input2);

            // compute the difference of C1 and C2
            XORresult = RC1 ^ RC2;

            // check the differece is as expected or not
            if(XORresult == omegap)
            {
                // increase the counter for the corresponding subkey
                Keys[key]++;
            }
        }
    }

    // write the partial subkey data for the subkeys which gives the highest count.
    printf("Candidates: \n");
    for(unsigned long long key = 0; key < (1<<18); key++)
    {
        if((Keys[key] == gecen) && (gecen > 0))
        {
            printf("Count: %d and the partial subkey bits: ", gecen);
            pSubKeys[AttackNo][PSKcounter] = key;
            PSKcounter++;
            print_binary(n2t(key,18),18);
        }
    }




//ATTACK 4 : 8-5-3 -------------------------------------------------------------------------------------------------

    //START FINDING RIGHT PAIRS
    //--------------------------------------------------------
    plaintext = initialplaintext;
    gecen = 0;
    AttackNo = 3;
    omegap = 0x9600000700000000u;
    // limit = 819^2 * 4 < 2^22
    limit = 1<<24;
    sayac = 0;
    RightPairCount = 4;
    PSKcounter = 0;

    for(int m = 0; m < 64; m++)
    {
        RightC1[m] = 0;
        RightC2[m] = 0;
        RightP1[m] = 0;
        RightP2[m] = 0;
    }

    printf("\n(8-5-3) Started finding right pairs...\n");
    //for(plaintext = 0; plaintext < limit; plaintext++)
    //plaintext = rand();
    do
    {
        sayac++;

        // clock the lfsr to generate another plaintext.
        // 64-bit m-LFSR taps: 64 63 61 60; characteristic polynomial: x^64 + x^63 + x^61 + x^60 + 1
        plaintext = (plaintext >> 1) ^ (unsigned long long)((0 - (plaintext & 1u)) & 0xD800000000000000u);

        t_plaintext = n2t(plaintext, 64);

        // apply inverse IP to eliminate the IP in the DEs
        des_iIP(&t_plaintext);
        // encrypt the plaintext
        t_ciphertext = des_encrypt(t_plaintext,t_key);
        // apply IP to eliminate the inverse IP at the end of the DES
        des_IP(&t_ciphertext);

        // result is ciphertext
        ciphertext = t2n(t_ciphertext);

        // generate the second plaintext with the selected difference omegap
        plaintext2 = plaintext ^ omegap;

        // encrypt the new plaintext
        t_plaintext2 = n2t(plaintext2,64);

        des_iIP(&t_plaintext2);
        text t_ciphertext2 = des_encrypt(t_plaintext2,t_key);
        des_IP(&t_ciphertext2);

        // result is ciphertex2
        ciphertext2 = t2n(t_ciphertext2);

        // compute the difference between ciphertext and ciphertext2
        //, mask;
        cipherdiff = ciphertext ^ ciphertext2;

        // apply the inverse P to the cipherdiff to eliminate the effect of the permutation P at the end of the f function in a round of DES
        cipherdiffL = cipherdiff >> 32;
        t_cipherdiffL = n2t(cipherdiffL,32);
        t_cdLtemp = t_cipherdiffL;
        for(int x = 0; x<32; x++)
        {
            t_cipherdiffL.v[x] = t_cdLtemp.v[isp[x]-1];
        }
        cipherdiffL = t2n(t_cipherdiffL);
        cipherdiff = ((cipherdiff<<32)>>32) ^ (cipherdiffL<<32);

        // check for the cipherdiff if it satisfies the certain properties for our difference omegap
        if((cipherdiff & 0x00FFFFF0FFFFFFFFu) == 0x96000007L)
        {
            printf("\n\nPlaintext : 0x%016" PRIx64 "\nDifference: 0x%016" PRIx64 "\n\n",plaintext,cipherdiff);
            //printf("\n\nPlaintext (Hex) : %llx\nThe found ciphertext difference is:\n",plaintext);
            //t_cipherdiff = n2t(cipherdiff,64);
            //print_cipher(t_cipherdiff);

            RightC1[gecen] = ciphertext;
            RightC2[gecen] = ciphertext2;

            // only for the last attack, to check the right key at the end of the attack
            RightP1[gecen] = plaintext;
            RightP2[gecen] = plaintext2;

            gecen++;
            // if the right pair count is 4 then stop searching for the right pair.
            if (gecen>(RightPairCount-1)) break;
        }

        // show the percentage ofthe progress for finding right pairs.
        if(sayac % (limit/100) == 0) printf("%llu-", ((sayac*100)/limit)+1);

    }
    while(sayac < limit);

    if(gecen < RightPairCount)
    {
        printf("\n\nEnough right pairs couldn't be found. Please restart application to try again.\nPress any key to exit...");
        //getch();
        return 0;
    }

    printf("Found %d pairs. Starting to find the partial subkeys...", gecen);

    //START THE ATTACK TO RECOVER PARTIAL SUBKEY BITS
    //--------------------------------------------------------
    printf("\nPlease Wait...\n\n");

    // Reset the counter for the candidate partial subkeys.
    for(unsigned long long key = 0; key < (1<<18); key++)
    {
        Keys[key] = 0;
    }

    // look for every pair
    for(int i = 0; i <gecen; i++)
    {
        // look for every subkey which is 18-bit
        for(unsigned long long key = 0; key < (1<<12); key++)
        {
            for(unsigned long long key1 = 0; key1 < (1<<6); key1++)
            {
                // place the key in the corresponding place w.r.t. S-Boxes
                subkey = (key<<36) ^ key1;

                RC1 = RightC1[i];
                RC2 = RightC2[i];

                t_input1 = n2t(RC1,64);
                t_input2 = n2t(RC2,64);

                // apply 1 round encrytion to ciphertext pairs
                round_des(&t_input1, n2t(subkey,48));
                round_des(&t_input2, n2t(subkey,48));

                RC1 = t2n(t_input1);
                RC2 = t2n(t_input2);

                // compute the difference of C1 and C2
                XORresult = RC1 ^ RC2;

                // check the differece is as expected or not
                if(XORresult == omegap)
                {
                    // increase the counter for the corresponding subkey
                    Keys[((key1<<12) ^ key)]++;
                }
            }
        }
    }

    // write the partial subkey data for the subkeys which gives the highest count.
    printf("Candidates: \n");
    for(unsigned long long key = 0; key < (1<<18); key++)
    {
        if((Keys[key] == gecen) && (gecen > 0))
        {
            printf("Count: %d and the partial subkey bits: ", gecen);
            pSubKeys[AttackNo][PSKcounter] = key;
            PSKcounter++;
            print_binary(n2t(key,18),18);
        }
    }



//INTERSECT THE RESULTS TO FIND LAST ROUND KEY-----------------------------------------------------------------

    printf("\nStarting to find possible round keys...");

    unsigned long long RealKey[16];
    for(int z=0; z<16; z++) RealKey[z]=0;
    int sayacc = 0;

    for(int i=0; i<16; i++)
    {
        for(int j=0; j<16; j++)
        {
            for(int k=0; k<16; k++)
            {
                for(int l=0; l<16; l++)
                {
                    if((pSubKeys[0][i] != 0) && (pSubKeys[1][k] != 0) && (pSubKeys[2][j] != 0) && (pSubKeys[3][l] != 0))
                    {

                        if(
                            (pSubKeys[0][i]%(1<<6) == pSubKeys[2][j]>>12) &&
                            (pSubKeys[2][j]%(1<<6) == pSubKeys[1][k]>>12) &&
                            (pSubKeys[1][k]%(1<<6) == pSubKeys[3][l]>>12) &&
                            (pSubKeys[3][l]%(1<<6) == pSubKeys[0][i]>>12)
                        )
                        {
                            unsigned long long Temp = (((pSubKeys[3][l]%(1<<12))<<36)^((pSubKeys[0][i]%(1<<12))<<24)^((pSubKeys[2][j]%(1<<12))<<12)^(pSubKeys[1][k]%(1<<12)));

                            int check = 0;
                            for(int z=0; z<16; z++)
                            {
                                if(RealKey[z] == Temp)
                                {
                                    check = 1;
                                }

                            }

                            if(check == 0)
                            {
                                RealKey[sayacc] = Temp;
                                sayacc++;
                            }
                        }
                    }

                }
            }
        }
    }

    printf("\n\nCandidates for the 48-bit last round key:\n");
    for(int r=0; r<16; r++)
    {
        if(RealKey[r] != 0)
        {
            printf("Candidate Key %d : 0x%012" PRIx64 "\n", r+1,RealKey[r]);
        }
    }

//FIND REAL 56BIT KEY -----------------------------------------------------------------------------------------------

    printf("\nStarting to find the main key...\n");

    int MutluSayac;

    // look for every possible found round key
    for(int r=0; r<16; r++)
    {
        t_RealKey = n2t(RealKey[r],48);

        // brute force on the remaining 8-bits of the 56-bit main key
        for(int kk=0; kk<256; kk++)
        {
            t_kk = n2t(kk,8);

            // apply inverse PC2
            RealRealKey = des_ipc2(t_RealKey);

            // 8,17,21,24,34,37,42,53
            RealRealKey.v[8] = t_kk.v[0];
            RealRealKey.v[17] = t_kk.v[1];
            RealRealKey.v[21] = t_kk.v[2];
            RealRealKey.v[24] = t_kk.v[3];
            RealRealKey.v[34] = t_kk.v[4];
            RealRealKey.v[37] = t_kk.v[5];
            RealRealKey.v[42] = t_kk.v[6];
            RealRealKey.v[53] = t_kk.v[7];

            //Rotate n times right, if roound is 6 then shift number is 10
            //RealRealKey.size = 56;
            for(int rr=0;rr<R;rr++)
            {
                RealRealKey = des_rotRight(RealRealKey,sh[rr]);
            }

            // apply inverse PC1 to ready the key for the input of des.
            TestKey = des_ipc1(RealRealKey);

            MutluSayac = 0;

            for(int d=0; d<RightPairCount; d++)
            {

                t_TempP1 = n2t(RightP1[d],64);
                t_TempP2 = n2t(RightP2[d],64);

                des_iIP(&t_TempP1);
                t_TempC1 = des_encrypt(t_TempP1,TestKey);
                des_IP(&t_TempC1);

                des_iIP(&t_TempP2);
                t_TempC2 = des_encrypt(t_TempP2,TestKey);
                des_IP(&t_TempC2);

                TempC1 = t2n(t_TempC1);
                TempC2 = t2n(t_TempC2);

                if((TempC1 == RightC1[d]) && (TempC2 == RightC2[d]))
                {
                    MutluSayac++;
                }

                // If it is the correct key, then stop.
                if(MutluSayac == RightPairCount)
                {
                    MutluAnahtar = des_shrinkkey(TestKey);
                    break;
                }
            }
        }
    }

    printf("\nThe Main Key is: 0x%014" PRIx64, t2n(MutluAnahtar));

    t1 = time(NULL);

    time_t diff1 = t1-t0;

    printf("\n\nExecution Time: %ld seconds\n", diff1);

    printf("\n---The End---\n");//Press any button to exit.");

    //getch();
    return 0;
}
