#include <mcrypt.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <sched.h>
#include <omp.h>
/*
int encrypt(
    void* buffer,
    int buffer_len, 
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("rijndael-256", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}

  mcrypt_generic_init(td, key, key_len, IV);
  mcrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}
*/
char* static_buffer;
int decrypt(
    void* buffer,
    int buffer_len,
    char* IV, 
    char* key,
    int key_len 
){
  MCRYPT td = mcrypt_module_open("rijndael-256", NULL, "cbc", NULL);
  int blocksize = mcrypt_enc_get_block_size(td);
  if( buffer_len % blocksize != 0 ){return 1;}
  
  mcrypt_generic_init(td, key, key_len, IV);
  mdecrypt_generic(td, buffer, buffer_len);
  mcrypt_generic_deinit (td);
  mcrypt_module_close(td);
  
  return 0;
}

void display(char* ciphertext, int len){
  int v;
  for (v=0; v<len; v++){
    printf("%d ", ciphertext[v]);
  }
  printf("\n");
}

int main()
{
  MCRYPT td, td2;
  const char cipherbyte[] = { 0x75, 0xA0, 0xE4, 0x80, 0x8C, 0x47, 0x3E, 0x69, 0x83, 0xBB, 0xF5, 0x81, 0xA8, 0x01, 0xEB, 0x4C, 0x1C, 0x1A, 0xDC, 0x4C, 0xE7, 0x60, 0x2E, 0x60, 0x23, 0xBE, 0x68, 0xCB, 0x5C, 0x4B, 0x10, 0xB5, 0x76, 0xD6, 0xFE, 0xD0, 0x49, 0x01, 0xBA, 0xC7, 0x7D, 0xC0, 0x77, 0x81, 0x1A, 0x29, 0x22, 0x81 }; 
  const char alphabet[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'}; 
  char* cipher = (char*)(cipherbyte);
  char* IV =  "892a686f2828b854516bb1774db6d254";
  char key[16] = "00000000c3d7a58c";
  int keysize = 16; 
  char* buffer;
  char* plaintext;
  int buffer_len = 51;
  int q,w,e,r,t,y,u,i; 
  regex_t regex;
  int ret1,_FLAG=0;
  buffer = calloc(1, buffer_len);
  strncpy(buffer, cipher, buffer_len);
  static_buffer = calloc(1, buffer_len);
  strcpy(static_buffer,buffer);
  plaintext = calloc(1, buffer_len);
  ret1 = regcomp(&regex, "^[a-zA-Z0-9,.!? ]*$",0);
  printf("cipher:  "); display(buffer , buffer_len);
  #pragma omp parallel for private(w,e,r,t,y,u,i,key) shared(buffer,static_buffer,ret1,plaintext)
   for(w=0;w<=15;w++)
    for(e=0;e<=15;e++)
     for(r=0;r<=15;r++)
      for(t=0;t<=15;t++)
       for(y=0;y<=15;y++)
        for(u=0;u<=15;u++)
         for(i=0;i<=15;i++){
		key[0]=alphabet[sched_getcpu()];
		key[1]=alphabet[w];
		key[2]=alphabet[e];
		key[3]=alphabet[r];
		key[4]=alphabet[t];
		key[5]=alphabet[y];
		key[6]=alphabet[u];
		key[7]=alphabet[i];
		strcpy(buffer,static_buffer);
  		decrypt(buffer, buffer_len, IV, key, keysize);
  		ret1=regexec(&regex,buffer,0,NULL,0);
		//printf("Working:%d - w:%d e:%d r:%d t:%d y:%d u:%d i:%d\n",sched_getcpu(),w,e,r,t,y,u,i);        
	        if(!ret1) {
			strcpy(plaintext,buffer);
			printf("decrypt: %s\n", plaintext);
			_FLAG=1;
		}
   }
  if(!_FLAG){
   printf("\n\n2nd half\n\n");
   #pragma omp parallel for private(w,e,r,t,y,u,i,key) shared(buffer)
   for(w=0;w<=15;w++)
    for(e=0;e<=15;e++)
     for(r=0;r<=15;r++)
      for(t=0;t<=15;t++)
       for(y=0;y<=15;y++)
        for(u=0;u<=15;u++)
         for(i=0;i<=15;i++){
		key[0]=alphabet[sched_getcpu()+8];
		key[1]=alphabet[w];
		key[2]=alphabet[e];
		key[3]=alphabet[r];
		key[4]=alphabet[t];
		key[5]=alphabet[y];
		key[6]=alphabet[u];
		key[7]=alphabet[i];

  		decrypt(buffer, buffer_len, IV, key, keysize);
  		ret1=regexec(&regex,buffer,0,NULL,0);
		//printf("Working:%d - w:%d e:%d r:%d t:%d y:%d u:%d i:%d\n",sched_getcpu(),w,e,r,t,y,u,i); 
	        if(!ret1) {
			strcpy(plaintext,buffer);
			printf("decrypt: %s\n", plaintext);
			_FLAG=1;
		}
   }
  }
  printf("===============================\n\n%s\n===============================\n",plaintext);
  return 0;
}


