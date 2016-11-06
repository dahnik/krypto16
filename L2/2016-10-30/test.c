#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <regex.h>
#include "pcre.h"
#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif


/**
 * Encrypt or decrypt, depending on flag 'should_encrypt'
 */
int en_de_crypt(pcre *re,int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec) {

    const unsigned BUFSIZE=4096;
    unsigned char *read_buf = malloc(BUFSIZE);
    unsigned char *cipher_buf;
    unsigned blocksize;
    int out_len,i;
    int rc;
    int ovector[blocksize];
    EVP_CIPHER_CTX ctx;
    //const char *pattern = "^[A-Ża-ż0-9,. ]+";
    EVP_CipherInit(&ctx, EVP_aes_256_cbc(), ckey, ivec, should_encrypt);
    blocksize = EVP_CIPHER_CTX_block_size(&ctx);
    cipher_buf = malloc(BUFSIZE + blocksize);
    while (1) {

        // Read in data in blocks until EOF. Update the ciphering with each read.
        int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
        EVP_CipherUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead);
	//printf("%s\n",cipher_buf);
	if(should_encrypt== FALSE){
		rc = pcre_exec (
		re,                   /* the compiled pattern */
		0,                    /* no extra data - pattern was not studied */
		cipher_buf,                  /* the string to match */
		strlen(cipher_buf),          /* the length of the string */
		0,                    /* start at offset 0 in the subject */
		0,                    /* default options */
		ovector,              /* output vector for substring information */
		blocksize);           /* number of elements in the output vector */
		//printf("\n%s \t===>%d ",cipher_buf,rc);
		if ((rc < 0) || (rc > 1)) {
			switch (rc) {
			    case PCRE_ERROR_NOMATCH:
				//printf("String didn't match");
				break;

			    default:
				//printf("Error while matching: %d\n", rc);
				break;
			}
		
			return 0;
	    	}
	}
	//for (i = 0; i < rc; i++) {
        //	printf("%2d: %.*s\n", i, ovector[2*i+1] - ovector[2*i], cipher_buf + ovector[2*i]);
    	//}
	printf("\n%s \t===>%d \n==========================================\n",cipher_buf,rc);
	//fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

	if (numRead < BUFSIZE) { // EOF
	    break;
	}

    }

    // Now cipher the final block and write it out.

    EVP_CipherFinal(&ctx, cipher_buf, &out_len);
    //fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
    // Free memory
    fprintf(ofp,"%s",cipher_buf);
    //free(cipher_buf);
   // free(read_buf);
    return 1;
}

int main(int argc, char *argv[]) {
			   //"b254af7d646a4dcff14b33844fb1eda7a2b84158cd99d8034e50b875e64dadf6";
    unsigned char ckey[64] = "00000000646a4dcff14b33844fb1eda7a2b84158cd99d8034e50b875e64dadf6";
    unsigned char ivec[] = "f4c5b5f6ddd329234c4d7a7d31ffaa09";
    FILE *fIN, *fOUT;
    const char alphabet[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'}; 
    const char *error;
    int erroffset,bit,_flag=0;
    pcre *re;
    char cont;
    char* pattern = "^[A-Ża-ż0-9,. ]+[A-Ża-ż0-9,. ]+[A-Ża-ż0-9,. ]+[A-Ża-ż0-9,. ]+[A-Ża-ż0-9,. ]+[A-Ża-ż0-9,. ]+[A-Ża-ż0-9,. ]+[A-Ża-ż0-9,. ]+";//"^[A-Ża-ż0-9,. ]+.?[A-Ża-ż0-9,. ]+$";
    if (argc != 2) {
        printf("Usage: <executable> <bit #>");
        return -1;
    }
    bit = atoi(argv[1]);
    printf("%d",bit);
    re = pcre_compile(pattern,PCRE_UTF8,&error,&erroffset,0);
    if (!re) {
        printf("pcre_compile failed (offset: %d), %s\n", erroffset, error);
        return -1;
    }
    //Encrypt

    //fIN = fopen("plain.txt", "rb"); //File to be encrypted; plain text
    //fOUT = fopen("cyphertext.txt", "wb"); //File to be written; cipher text

    //en_de_crypt(re,TRUE, fIN, fOUT, ckey, ivec);

    //fclose(fIN);
    //fclose(fOUT);

    //Decrypt
    int q,w,e,r,t,y,u,i;
    //#pragma omp parallel for private(q,w,e,r,t,y,u,ckey) shared(_flag,re,fIN,fOUT)
     q=bit;
      for(w=0;w<15;w++)
       for(e=0;e<15;e++)
        for(r=0;r<15;r++)       
	 for(t=0;t<15;t++)
          for(y=0;y<16;y++)
           for(u=0;u<16;u++)
            for(i=0;i<16;i++){
	     printf("Working:%d - q:%d w:%d e:%d r:%d t:%d y:%d u:%d i:%d\n",sched_getcpu(),q,w,e,r,t,y,u,i); 
	     if(cont=='s'){
		w=15;e=15;r=15;t=15;y=15;u=15;i=15;
	     }
	     ckey[0]=alphabet[q];
	     ckey[1]=alphabet[w];
	     ckey[2]=alphabet[e];
	     ckey[3]=alphabet[r];
	     ckey[4]=alphabet[t];
	     ckey[5]=alphabet[y];
	     ckey[6]=alphabet[u];
	     ckey[7]=alphabet[i];

	     fIN = fopen("cyphertext.txt", "rb"); //File to be read; cipher text
	     fOUT = fopen("decrypted.txt", "wb"); //File to be written; cipher text
	     _flag=en_de_crypt(re,FALSE, fIN, fOUT, ckey, ivec);
	     if(_flag){ printf("[c] to continue | [s] to skip\n"); cont=getchar();}
	     
	     fclose(fIN);
	     fclose(fOUT);
      	   }
    free(re);
    return 0;
}
