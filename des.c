#include <stdio.h>
#include "des.h"

// 8,17,21,24,34,37,42,53
int iPC2[56] = {5,24,7,16,6,10,20,18,
              -1,12,3,15,23,1,9,19,
              2,-1,14,22,11,-1,13,4,
              -1,17,21,8,47,31,27,48,
              35,41,-1,46,28,-1,39,32,
              25,44,-1,37,34,43,29,36,
              38,45,33,26,42,-1,30,40
             };

// 7,15,23,31,39,47,55,63
int iPC1[64] = {8,16,24,56,52,44,36,-1,
              7,15,23,55,31,43,35,-1,
              6,14,22,54,50,42,34,-1,
              5,13,21,53,49,41,33,-1,
              4,12,20,28,48,40,32,-1,
              3,11,19,27,47,39,31,-1,
              2,10,18,26,46,38,30,-1,
              1,9,17,25,45,37,29,-1
             };


int R;
int s[8];
int S[8][64];
int ex[48] = {32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
              8, 9,10,11,12,13,12,13,14,15,16,17,
              16,17,18,19,20,21,20,21,22,23,24,25,
              24,25,26,27,28,29,28,29,30,31,32, 1
             };
int ip[64] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,
              62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
              57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,
              61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7
             };
int iip[64];
int sp[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
//int sp[32]  = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
int isp[32] = {9,17,23,31,13,28,2,18,24,16,30,6,26,20,10,1,8,14,25,3,4,29,11,19,32,12,22,7,5,27,15,21};
int sh[16]  = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
int kp[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,
              10,2,59,51,43,35,27,19,11,3,60,52,44,36,
              63,55,47,39,31,23,15,7,62,54,46,38,30,22,
              14,6,61,53,45,37,29,21,13,5,28,20,12,4
             };
int kt[48] = {14,17,11,24,1,5,3,28,15,6,21,10,
              23,19,12,4,26,8,16,7,27,20,13,2,
              41,52,31,37,47,55,30,40,51,45,33,48,
              44,49,39,56,34,53,46,42,50,36,29,32
             };

text des_expandkey(text input)
{

    int i,j;
    text output;

    output.size = 64;
    for(i=0; i<output.size; i++)
        output.v[i] = 0;

    for(i=0; i<8; i++)
        for(j=0; j<7; j++)
            output.v[i*8+j] = input.v[i*7+j];

    return output;
}

text des_shrinkkey(text input)
{

    int i,j;
    text output;

    output.size = 56;
    for(i=0; i<8; i++)
        for(j=0; j<7; j++)
            output.v[i*7+j] = input.v[i*8+j];

    return output;
}

void print_cipher(text ciphertext)
{

    int i;

    for(i=0; i<ciphertext.size; i++)
    {
        if((i != 0) & (i%4==0)) printf(" ");
        if((i != 0) & (i % 32 == 0)) printf("-");
        printf("%d",ciphertext.v[i]);
    }
    printf("\n");
}


void print_binary(text t, int d)
{

    int i;
    for(i=0; i<t.size; i++)
    {
        //if(!(i%d)) printf(" ");
        printf("%d",t.v[i]);
    }
    printf("\n");
}

text des_expand(text input)
{

    text cr;
    int i;
    cr.size = 48;
    for(i=0; i<cr.size; i++)
        cr.v[i] = input.v[ex[i]-1];

    return cr;
}

text des_sbox(int id, text b)
{

    int si,rank=0,val;
    text r;

    si = s[id];

    //printf("b: ");
    //for(i=0; i<b.size; i++)
    //	printf("%d",b.v[i]);
    //printf("  ");

    r.size = 4;
    rank += b.v[0]*32;
    rank += b.v[5]*16;
    rank += b.v[1]*8;
    rank += b.v[2]*4;
    rank += b.v[3]*2;
    rank += b.v[4]*1;

    //printf("rank: %d\t", rank);

    val = S[si][rank];
    //printf("si: %d  val: %d\n", si, val);


    r.v[3] = (val/1)%2;
    r.v[2] = (val/2)%2;
    r.v[1] = (val/4)%2;
    r.v[0] = (val/8)%2;

    return r;
}

text des_permute(text input)
{

    int i;
    text output;

    output.size = 32;
    for(i=0; i<input.size; i++)
        output.v[i] = input.v[sp[i]-1];

    return output;
}

text permutation(text *c)
{

    int i,j;
    text tmp,r;

    r.size = tmp.size = 32;
    for(i=0; i<8; i++)
        for(j=0; j<4; j++)
            tmp.v[i*4+j] = c[i].v[j];

    for(i=0; i<32; i++)
        r.v[i] = tmp.v[sp[i]-1];

    return r;
}

text des_ffunction(text input, text subkey)
{

    int i,j;
    text b[8], c[8], cr;

    cr = des_expand(input);
    //printf("E(R0):");
    //print_binary(cr,6);
    //printf("\t\texpanded...\n");

    for(i=0; i<cr.size; i++)
        cr.v[i] = cr.v[i] ^ subkey.v[i];
    //printf("K1+E(R0):");
    //print_binary(cr,6);

    for(i=0; i<8; i++)
    {
        b[i].size = 6;
        for(j=0; j<b[i].size; j++)
            b[i].v[j] = cr.v[i*6+j];
    }
    //printf("\t\tb found...\n");

    //printf("K1+E(R0): ");
    //for(i=0; i<8; i++) {
    //	for(j=0; j<b[i].size; j++)
    //		printf("%d",b[i].v[j]);
    //	printf(" ");
    //}
    //printf("\n");

    for(i=0; i<8; i++)
        c[i] = des_sbox(i, b[i]);

    //printf("\t\tsubstitution...\n");
    //printf("S(K1+E(R0)): ");
    //for(i=0; i<8; i++) {
    //	for(j=0; j<c[i].size; j++)
    //		printf("%d",c[i].v[j]);
    //	printf(" ");
    //}
    //printf("\n");

    return permutation(c);

}

void round_des(text *ciphertext, text subkey)
{

    int i;
    text Cl, Cr, Mv;

    Cl.size = Cr.size = 32;
    for(i=0; i<32; i++)
    {
        Cl.v[i] = ciphertext->v[i];
        Cr.v[i] = ciphertext->v[i+32];
    }
    //printf("CL:");
    //print_binary(Cl,4);
    //printf("CR:");
    //print_binary(Cr,4);

    //printf("\tpartitioned...\n");

    Mv = des_ffunction(Cr, subkey);
    //printf("f(R0,K1): ");
    //print_binary(Mv,4);

    //printf("\tf function...\n");
    for(i=0; i<32; i++)
    {
        ciphertext->v[i+32] = Cl.v[i] ^ Mv.v[i];
        ciphertext->v[i] = Cr.v[i];
    }
}

void print_sbox(int k)
{

    int i,j;

    printf("S%d:\n",k+1);
    for(i=0; i<4; i++)
    {
        for(j=0; j<16; j++)
            printf("%2d ",S[k][i*16+j]);
        printf("\n");
    }
    printf("\n\n");
}

void read_sbox()
{

    int i,j;
    char str[20];

    FILE *f = fopen("settings.in","r");

    fscanf(f, " %s %d", str, &R);
    fscanf(f, " %s", str);
    for(i=0; i<8; i++)
    {
        fscanf(f, " %d", &s[i]);
        s[i] --;
    }
    fclose(f);

    //printf("s order: ");
    //for(i=0; i<8; i++)
    //	printf("%d ", s[i]);
    //printf("\n");

    f = fopen("sbox.in","r");
    for(i=0; i<8; i++)
        for(j=0; j<64; j++)
            fscanf(f, " %d", &S[i][j]);
    fclose(f);

    //for(i=0; i<8; i++)
    //	print_sbox(i);
    //printf("Done\n");

}

void init_iip()
{

    int i;
    for(i=0; i<64; i++)
        iip[ip[i]-1] = i+1;
}

void des_initialize()
{

    read_sbox();
    init_iip();
}

void des_IP(text *ciphertext)
{

    int i;
    text tmp;

    tmp.size = 64;
    for(i=0; i<tmp.size; i++)
        tmp.v[i] = ciphertext->v[i];

    for(i=0; i<tmp.size; i++)
        ciphertext->v[i] = tmp.v[ip[i]-1];
}

void des_iIP(text *ciphertext)
{

    int i;
    text tmp;

    tmp.size = 64;
    for(i=0; i<tmp.size; i++)
        tmp.v[i] = ciphertext->v[i];

    for(i=0; i<tmp.size; i++)
        ciphertext->v[i] = tmp.v[iip[i]-1];
}

void des_shift(text *ciphertext)
{

    int i;
    text tmp;

    tmp = *ciphertext;
    for(i=0; i<tmp.size/2; i++)
    {

        ciphertext->v[i] = tmp.v[i+tmp.size/2];
        ciphertext->v[i+tmp.size/2] = tmp.v[i];
    }
}

text des_ipc1(text input)
{

    int i;
    text output;

    output.size = 64;
    for(i=0; i<output.size; i++)
        output.v[i] = 0;

    for(i=0; i<input.size; i++)
        output.v[kp[i]-1] = input.v[i];

    return output;
}

text des_ipc2(text input)
{

    int i;
    text output;

    output.size = 56;
    for(i=0; i<output.size; i++)
        output.v[i] = 0;

    for(i=0; i<input.size; i++)
        output.v[kt[i]-1] = input.v[i];

    return output;
}

// PC1
text des_initkey(text key)
{

    int i;
    text mkey;

    mkey.size = 56;
    for(i=0; i<mkey.size; i++)
        mkey.v[i] = key.v[kp[i]-1];

    return mkey;
}


text des_keyschedule(text *key, int round)
{

    int i,sha;
    text tmp;
    text rkey;

    sha = sh[round];
    tmp = *key;

    // left shift for Cn and Dn
    for(i=0; i<28; i++)
    {
        key->v[i] = tmp.v[(i+sha)%28];
        key->v[i + 28] = tmp.v[(i+sha)%28 + 28];
    }

    // PC2
    rkey.size = 48;
    for(i=0; i<rkey.size; i++)
        rkey.v[i] = key->v[kt[i]-1];

    //print_binary(*key);
    return rkey;
}

text des_encrypt(text plaintext, text key)
{

    text ciphertext, mkey;
    int round = 0;

    ciphertext = plaintext;
    mkey = des_initkey(key);
    //print_binary(mkey);
    //printf("key initialized...\n");

    des_IP(&ciphertext);

    //printf("IP: ");
    //print_binary(ciphertext,4);

    for(round=0; round<R; round++)
    {

        round_des(&ciphertext, des_keyschedule(&mkey,round));

        // debug
        //printf("%dth Round done...\n", round+1);
        //print_binary(ciphertext,4);

        //print_cipher(ciphertext);

    }

    des_shift(&ciphertext);
    //printf("Shifted...\n");
    //print_cipher(ciphertext);

    des_iIP(&ciphertext);

    //printf("Inverse Permutation...\n");
    //print_cipher(ciphertext);
    //print_binary(ciphertext,4);
    return ciphertext;
}

text des_encrypt2(text plaintext, text key)
{

    text ciphertext, mkey;
    int round = 0;

    ciphertext = plaintext;
    //mkey = des_initkey(key);
    mkey = key;

    //print_binary(mkey);
    //printf("key initialized...\n");

    des_IP(&ciphertext);

    //printf("IP: ");
    //print_binary(ciphertext,4);

    for(round=0; round<R; round++)
    {

        round_des(&ciphertext, des_keyschedule(&mkey,round));

        // debug
        //printf("%dth Round done...\n", round+1);
        //print_binary(ciphertext,4);

        //print_cipher(ciphertext);

    }

    des_shift(&ciphertext);
    //printf("Shifted...\n");
    //print_cipher(ciphertext);

    des_iIP(&ciphertext);

    //printf("Inverse Permutation...\n");
    //print_cipher(ciphertext);
    //print_binary(ciphertext,4);
    return ciphertext;
}


unsigned long long t2n(text input)
{

    int i;
    unsigned long long output;

    //printf("Input: ");
    //print_cipher(input);
    output = 0;
    for(i=0; i<input.size; i++)
    {
        output = (output*2) + input.v[i];
        //printf("Output: %lld\n", output);
    }


    return output;
}

text n2t(unsigned long long input, int size)
{

    int i;
    text output;

    output.size = size;
    for(i=output.size-1; i>=0; i--)
    {

        output.v[i] = input % 2;
        input = input >> 1;
    }

    return output;
}

text des_rotRight(text data, int tekrar)
{
    int i;
    text output;
    //output = data;
    output.size = 56;


    for(i=0;i<56;i++) output.v[i]=0;

    //int yarim = 28; //tmp.size/2;
    // right shift for Cn and Dn
    //for(int p=0; p<tekrar; p++)
    //{
        for(i=0; i<28; i++)
        {
            output.v[(i+tekrar)%28] = data.v[i];
            output.v[(i+tekrar)%28 + 28] = data.v[i + 28];
        }
    //}

    return output;
}
