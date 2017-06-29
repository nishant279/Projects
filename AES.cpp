/**
    Copyright © Nishant Kumar
**/
/** AES.cpp
  AES 128 bit Encryption and Decryption
**/

#include <bits/stdc++.h>
#include <windows.h>
#include <wincon.h>
#include <conio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;
#define NC 4 ///columns in a state
#define NB 4 ///32 bits word in key
#define KLEN 16 ///key length in bytes
#define NR 10 ///Rounds in AES128
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x11b)) ///This macro finds the product of {02} and the argument to xtime modulo {1b}
unsigned char round_key[176];
unsigned char key[16]; ///= {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
unsigned char plain_text[16];
unsigned char cipher_text[16];
unsigned char state[4][4];
string cipher_result = "";
string plain_result = "";

///All the functions used
unsigned char s_box(unsigned char);
unsigned char rs_box(unsigned char);
void key_expansion();
void add_round_key(unsigned char);
void sub_bytes();
void shift_rows();
void mix_column();
unsigned char multiply(unsigned char, unsigned char);
void inv_mix_column();
void inv_sub_bytes();
void inv_shift_rows();
void cipher();
void inv_cipher();
void out_cipher();
void out_plain();
void encrypt();
void decrypt();
void welcome();
void gotoxy(int , int );
void title();
void rectangle(int , int , int , int );

FILE *foc, *fop;

void welcome(){
    system("cls");
    rectangle(0, 0, 80, 23);
    gotoxy(27, 4);
    cout<<"AES ENCYPTION AND DECRYPTION";
    gotoxy(27, 5);
    for(int i = 0; i < 28; i++){
        cout<<(char)196;
    }
    gotoxy(27, 8);
    cout<<"Designed and Programmed by:";
    gotoxy(27, 9);
    for(int i = 0; i < 27; i++){
        cout<<(char)196;
    }
    gotoxy(34, 11);
    cout<<"Nishant Kumar";
    gotoxy(23, 20);
    cout<<"Press any key to continue...";
    getch();
}

void title()
{
    gotoxy(25,1);
    printf("AES Encryption and Decryption");
    gotoxy(1, 5);
    for(int i = 0; i < 78; i++){
      cout<<(char)196;
    }
    gotoxy(0, 6);
}

void rectangle(int x, int y, int a, int b){
    gotoxy(x, y);
    cout<<char(201);
    int i, j;
    for(i = x+1; i < a-1; i++){
        gotoxy(i, y);
        cout<<(char)205;
    }
    gotoxy(i, y);
    cout<<(char)187;
    for(j = y+1; j < b; j++){
        gotoxy(x, j);
        for(i = x; i < a; i++){
            if(i == x || i == a-1){
                gotoxy(i, j);
                cout<<(char)186;
            }
        }
    }
    gotoxy(x, j);
    cout<<(char)200;
    for(i = x+1; i < a-1; i++){
        gotoxy(i, j);
        cout<<(char)205;
    }
    gotoxy(i, j);
    cout<<(char)188;
}

void gotoxy(int x, int y)
{
  static HANDLE h = NULL;
  if(!h)
    h = GetStdHandle(STD_OUTPUT_HANDLE);
  COORD c = { x, y };
  SetConsoleCursorPosition(h,c);
}

unsigned char sbox[256] = {
    ///0     1     2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,//0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,//1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,//2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,//3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,//4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,//5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,//6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,//7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,//8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,//9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,//A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,//B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,//C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,//D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,//E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 //F
    };

unsigned char rsbox[256] = {
    ///0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,//0
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,//1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,//2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,//3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,//4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,//5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,//6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,//7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,//8
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,//9
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,//A
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,//B
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,//C
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,//D
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,//E
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d //F
};

unsigned char rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20,0x40, 0x80, 0x1b, 0x36};

unsigned char s_box(unsigned char num){
    return sbox[num];
}

unsigned char rs_box(unsigned char num){
    return rsbox[num];
}

void key_expansion(){
    unsigned char temp[4];
    /// First Round Calculation
    int i;
    for(i = 0; i < NB; i++){
        round_key[i*4] = key[i*4];
        round_key[i*4+1] = key[i*4+1];
        round_key[i*4+2] = key[i*4+2];
        round_key[i*4+3] = key[i*4+3];
    }
    ///Other round Calculation
    for(; i < (NC*(NR+1)); i++){
        for(int j = 0; j < 4; j++){
            temp[j] = round_key[(i-1)*4+j];
        }
        if(i % NB == 0){
            ///Rotation is performed using following block
            {
                int k = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = k;
            }
            ///Performing S-Box substitution on the four bytes
            {
                temp[0] = s_box(temp[0]);
                temp[1] = s_box(temp[1]);
                temp[2] = s_box(temp[2]);
                temp[3] = s_box(temp[3]);
            }
            ///temp[0] = temp[0] ^ rcon[i/NB];
            temp[0] = temp[0] ^ rcon[i/(KLEN/4)-1];
            ///printf("%.2x", rcon[i/(KLEN/4)-1]);
            ///printf("\n");
        }
        round_key[i*4] = round_key[(i-NB)*4] ^ temp[0];
        round_key[i*4+1] = round_key[(i-NB)*4+1] ^ temp[1];
        round_key[i*4+2] = round_key[(i-NB)*4+2] ^ temp[2];
        round_key[i*4+3] = round_key[(i-NB)*4+3] ^ temp[3];
    }
    /**for(int i = 0; i < 176; i++){
        printf("%.2x ", round_key[i]);
    }
    printf("\n");**/
}

void add_round_key(unsigned char round){
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[j][i] ^= round_key[(round*NC*4) + (i*NC) + j];
        }
    }
    /**printf("State matrix without any function\n");
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            printf("%.2x ", state[i][j]);
        }
        printf("\n");
    }**/
}

void sub_bytes(){
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[i][j] = s_box(state[i][j]);
        }
    }
    /**printf("State matrix after subBytes\n");
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            printf("%.2x ", state[i][j]);
        }
        printf("\n");
    }**/
}

void shift_rows(){
    unsigned char temp;
    ///1 shift left on row 2
    temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;
    ///2 shift left on row 3
    temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;
	temp  = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;
	///3 shift left on row 4
	temp = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = temp;
	/**printf("State matrix after shiftRows\n");
	for(int i = 0; i < 4; i++){
	    for(int j = 0; j < 4; j++){
	        printf("%.2x ", state[i][j]);
	    }
	    printf("\n");
	}**/
}

unsigned char multiply(unsigned char x, unsigned char y){
    return (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^
            ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

void mix_column(){
    for(int i = 0; i < 4; i++){
        unsigned char a = state[0][i];
        unsigned char b = state[1][i];
        unsigned char c = state[2][i];
        unsigned char d = state[3][i];
        state[0][i] = multiply(a, 0x02) ^ multiply(b, 0x03) ^ c ^ d;
        state[1][i] = a ^ multiply(b, 0x02) ^ multiply(c, 0x03) ^ d;
        state[2][i] = a ^ b ^ multiply(c, 0x02) ^ multiply(d, 0x03);
        state[3][i] = multiply(a, 0x03) ^ b ^ c ^ multiply(d, 0x02);
    }
    /**printf("State matrix after mixColum\n");
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            printf("%.2x ", state[i][j]);
        }
        printf("\n");
    }**/
}

void inv_mix_column(){
    for(int i = 0; i < 4; i++){
        unsigned char a = state[0][i];
        unsigned char b = state[1][i];
        unsigned char c = state[2][i];
        unsigned char d = state[3][i];
        state[0][i] = multiply(a, 0x0e) ^ multiply(b, 0x0b) ^ multiply(c, 0x0d) ^ multiply(d, 0x09);
        state[1][i] = multiply(a, 0x09) ^ multiply(b, 0x0e) ^ multiply(c, 0x0b) ^ multiply(d, 0x0d);
        state[2][i] = multiply(a, 0x0d) ^ multiply(b, 0x09) ^ multiply(c, 0x0e) ^ multiply(d, 0x0b);
        state[3][i] = multiply(a, 0x0b) ^ multiply(b, 0x0d) ^ multiply(c, 0x09) ^ multiply(d, 0x0e);
    }
    /**printf("State matrix after invMixColumn\n");
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            printf("%.2x ", state[i][j]);
        }
        printf("\n");
    }**/
}

void inv_shift_rows(){
    unsigned char temp;
    ///1 shift right on row 2
    temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;
    ///2 shift right on row 3
    temp = state[2][3];
	state[2][3] = state[2][1];
	state[2][1] = temp;
	temp = state[2][2];
	state[2][2] = state[2][0];
	state[2][0] = temp;
	///3 shift right on row 4
	temp = state[3][3];
	state[3][3] = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = temp;
	/**printf("State matrix after invShiftRows\n");
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            printf("%.2x ", state[i][j]);
        }
        printf("\n");
    }**/
}

void inv_sub_bytes(){
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[i][j] = rs_box(state[i][j]);
        }
    }
    /**printf("State matrix after invSubBytes\n");
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            printf("%.2x ", state[i][j]);
        }
        printf("\n");
    }**/
}

void cipher(){
    add_round_key(0); ///adding the first round key to the states before starting the rounds
    ///Following loop runs from 1 to NR-1
    for(int rounds = 1; rounds < NR; rounds++){
        sub_bytes();
        shift_rows();
        mix_column();
        add_round_key(rounds);
    }
    ///The last round performs the following operations
    sub_bytes();
    shift_rows();
    add_round_key(NR);
	for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            cipher_text[4*i+j] = state[j][i];
        }
    }
}

void inv_cipher(){
    add_round_key(NR); ///adding the first round key to the states before starting the rounds
    ///Following loop runs from NR-1 to 1
    for(int rounds = NR-1; rounds > 0; rounds--){
        inv_shift_rows();
        inv_sub_bytes();
        add_round_key(rounds);
        inv_mix_column();
    }
    ///The last round performs the following operation
    inv_shift_rows();
    inv_sub_bytes();
    add_round_key(0);
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            plain_text[4*i+j] = state[j][i];
        }
    }
}

void out_cipher_in_file(){
    foc = fopen("ciphertextresult.txt", "w");
    for(int i = 0; i < 16; i++){
        fprintf(foc, "%.2x ", cipher_text[i]);
    }
    fclose(foc);
}

void out_plain_in_file(){
    fop = fopen("plaintextresult.txt", "w");
    for(int i = 0; i < 16; i++){
        fprintf(fop, "%.2x ", plain_text[i]);
    }
    fclose(fop);
}

/*void out_cipher(){
    foc = fopen("ciphertextresult.txt", "r");
    unsigned char c[16];
    for(int i = 0; i < 16; i++){
        fscanf(foc, "%x", &c[i]);
        cipher_result += (char)c[i];
    }
    cout<<cipher_result<<endl;
    fclose(foc);
}*/
void out_cipher(){
    unsigned char c[16];
    foc = fopen("ciphertextresult.txt", "r");
    for(int i = 0; i < 16; i++){
        fscanf(foc, "%x", &c[i]);
        cipher_result = cipher_result + (char)c[i];
    }
    cout<<cipher_result<<endl;
    /**
    for(int i = 0; i < 16; i++){
        printf("%.2x ", c[i]);
    }**/
}

void out_plain(){

}

void encrypt(){
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[j][i] = plain_text[i*4+j];
        }
    }
    key_expansion();
    cipher();
    out_cipher_in_file();
    out_cipher();
}

void decrypt(){
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            state[j][i] = cipher_text[i*4+j];
        }
    }
    key_expansion();
    inv_cipher();
    out_plain();
}

int main(){
    string choice;
    /**FILE *fpk, *fpl;
    string keystring, ptstring;
    cout<<"Enter 128 - bit key: ";
    getline(cin, keystring);
    fpk = fopen("key.txt", "w");
    for(int i = 0; i < keystring.length(); i++){
     fprintf(fpk, "%.2x ", keystring[i]);
    }
    fclose(fpk);
    cout<<"Enter Plain Text: ";
    getline(cin, ptstring);
    fpl = fopen("plaintext.txt", "w");
    for(int i = 0; i < ptstring.length(); i++){
    fprintf(fpl, "%.2x ", ptstring[i]);
    }
    fclose(fpl);
    fpk = fopen("key.txt", "r");
    for(int i = 0; i < keystring.length(); i++){
     fscanf(fpk, "%x", &key[i]);
    }
    fpl = fopen("plaintext.txt", "r");
    for(int i = 0; i < ptstring.length(); i++){
     fscanf(fpl, "%x", &plain_text[i]);
    }
    cout<<"The encryption is being performed...\n";
    ///key_expansion();
    encrypt();
    **/
    welcome();
    system("cls");
    title();
    do{
        cout<<"Choose\n1. Encrypt\n2. Decrypt\n3. Exit\n";
        getline(cin, choice);
        FILE *fpk, *fpl;
        string keystring, ptstring;
        if(choice == "1"){
            cout<<"Enter 128 - bit key: ";
            getline(cin, keystring);
            fpk = fopen("key.txt", "w");
            for(int i = 0; i < keystring.length(); i++){
                fprintf(fpk, "%.2x ", keystring[i]);
            }
            fclose(fpk);
            cout<<"Enter Plain Text: ";
            getline(cin, ptstring);
            fpl = fopen("plaintext.txt", "w");
            for(int i = 0; i < ptstring.length(); i++){
                fprintf(fpl, "%.2x ", ptstring[i]);
            }
            fclose(fpl);
            fpk = fopen("key.txt", "r");
            for(int i = 0; i < keystring.length(); i++){
                fscanf(fpk, "%x", &key[i]);
            }
            fpl = fopen("plaintext.txt", "r");
            for(int i = 0; i < ptstring.length(); i++){
                fscanf(fpl, "%x", &plain_text[i]);
            }
            cout<<"The encryption is being performed...\n";
            encrypt();
        }
        else if(choice == "2"){
            cout<<"Enter 128 - bit key in hexadecimal form:\n";
            for(int i = 0; i < 16; i++){
                scanf("%x", &key[i]);
            }
            cout<<"Enter cipher text to be decrypted in hexadecimal form:\n";
            for(int i = 0; i < 16; i++){
                scanf("%x", &cipher_text[i]);
            }
            cout<<"The decryption is being performed...\n";
            decrypt();
        }
        else if(choice == "3"){
            exit(0);
        }
        else{
            cout<<"Oops! You have entered wrong choice.\n";
        }
    }while(choice != "3");
    /**FILE *ky, *cp;
    ky = fopen("key.txt", "r");
    unsigned char msg[16], msg1[16];
    for(int i = 0; i < 16; i++){
    	fscanf(ky, "%x", &key[i]);
    	//key[i] = msg[i];
    }
    cp = fopen("plaintext.txt", "r");
    for(int i = 0; i < 16; i++){
    	fscanf(cp, "%x", &plain_text[i]);
    	//plain_text[i] = msg1[i];
    }
    encrypt();
    getline(cin, key);
    FILE *fp = fopen("plaintext.txt", "w");
    for(int i = 0; i < key.length(); i++)
    {
        fprintf(fp, "%.2x ", key[i]);
    }**/
  ///  unsigned char a;
/// scanf("%x", )
    return 0;
}
