#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void initialize_fips(int mode) {
    if(FIPS_mode_set(mode)) {
        fprintf(stdout, "FUNCTION: %s, LOG: FIPS MODE SET TO %d\n", __func__, mode);
    }
    else {
        fprintf(stderr, "FUNCTION: %s, LOG: FIPS MODE NOT SET %d", __func__, mode);
        ERR_load_crypto_strings();
        fprintf(stderr, ", ERROR: ");
        ERR_print_errors_fp(stderr);
    }
}

void print_hex(FILE *out, const char *s) {
  while(*s)
    fprintf(out, "%02x", (unsigned char) *s++);
    fprintf(out, "\n");
}

int str2hex(const char hexstring[], unsigned char * val, int *len) {
    const char *pos = hexstring;
    size_t count = 0;

    if (strlen(hexstring) % 2 == 1) return 0;

     /* WARNING: no sanitization or error-checking whatsoever */
    for (count = 0; count < strlen(hexstring)/2; count++) {
        sscanf(pos, "%2hhx", &val[count]);
        pos += 2;
    }
    *len = strlen(hexstring) / 2;

    return 1;
}

void main(int argc, char *argv[])
{
    initialize_fips(1);

    unsigned char *key_str = (unsigned char *)"example key 1234example key 1234";
    unsigned char *iv_str = (unsigned char *)"0123456789012341";
    unsigned char *plaintext = (unsigned char *)"exampleplaintextexampleplaintext";
    unsigned char *mode = (unsigned char *)"cbc";
    unsigned char key[1024];
    unsigned char iv[1024];
    int key_len = 0, iv_len = 0;
    unsigned char ciphertext[1024];
    unsigned char decryptedtext[1024];
    int decryptedtext_len = 0, ciphertext_len = 0;

    if (argc >= 3) {
      key_str = argv[1];
      iv_str  = argv[2];

      if (argc >= 4) {
        plaintext = argv[3];
      }

      if (argc >= 5) {
        mode = argv[4];
      }
    } else {
        fprintf(stderr, "USAGE: %s [key] [iv] [plain-text] [mode]\nBy default mode is 'cbc'\n", argv[0]);
        return 1;
    }

    /* Convert key and iv from string to hex */
    if (!str2hex(key_str, key, &key_len)) {
        printf("ERROR");
        return;
    }

    if (!str2hex(iv_str, iv, &iv_len)) {
        printf("ERROR");
        return;
    }

    /* Encrypt the plaintext */
    fprintf(stdout, "\nEncryption:\n");

    ciphertext_len = encdec(plaintext, strlen(plaintext), key, key_len, iv, ciphertext, mode, 1);

    /* Do something useful with the ciphertext here */
    fprintf(stdout, "Plaintext: %s\n", plaintext);
    fprintf(stdout, "KEY: ");
    print_hex(stdout, key);
    fprintf(stdout, "IV: ");
    print_hex(stdout, iv);
    fprintf(stdout, "Ciphertext : ");
    print_hex(stdout, ciphertext);

    /* Decrypt the ciphertext */
    fprintf(stdout, "\nDecryption:\n");

    decryptedtext_len = encdec(ciphertext, ciphertext_len, key, key_len, iv, decryptedtext, mode, 0);

    if(decryptedtext_len < 0)
    {
        /* Verify error */
        printf("Decrypted text failed to verify\n");
    }
    else
    {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is: ");
        printf("%s\n", decryptedtext);
    }

    /* Remove error strings */
    ERR_free_strings();

}

int encdec(unsigned char *plaintext, int plaintext_len, unsigned char *key, int key_len,
            unsigned char *iv, unsigned char *ciphertext, unsigned char *mode, int enc) {

    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0, ciphertext_len = 0;

    /* Create and initialise the context */
    ctx = malloc(sizeof(EVP_CIPHER_CTX));
    FIPS_cipher_ctx_init(ctx);

    /* Initialise the encryption operation. */
    const EVP_CIPHER *evpCipher;
    switch (key_len) {
    case 16:
        if (strcmp(mode,"cbc")==0) {
            evpCipher = FIPS_evp_aes_128_cbc();
        } else if (strcmp(mode,"ctr")==0) {
            evpCipher = FIPS_evp_aes_128_ctr();
        } else if (strcmp(mode,"gcm")==0) {
            evpCipher = FIPS_evp_aes_128_gcm();
        } else if (strcmp(mode,"ecb")==0) {
            evpCipher = FIPS_evp_aes_128_ecb();
        } else {
            fprintf(stderr, "invalid mode\n");
            return 0;
        }
        break;
    case 24:
        if (strcmp(mode,"cbc")==0) {
            evpCipher = FIPS_evp_aes_192_cbc();
        } else if (strcmp(mode,"ctr")==0) {
            evpCipher = FIPS_evp_aes_192_ctr();
        } else if (strcmp(mode,"gcm")==0) {
            evpCipher = FIPS_evp_aes_192_gcm();
        } else if (strcmp(mode,"ecb")==0) {
            evpCipher = FIPS_evp_aes_192_ecb();
        } else {
            fprintf(stderr, "invalid mode\n");
            return 0;
        }
        break;
    case 32:
        if (strcmp(mode,"cbc")==0) {
            evpCipher = FIPS_evp_aes_256_cbc();
        } else if (strcmp(mode,"ctr")==0) {
            evpCipher = FIPS_evp_aes_256_ctr();
        } else if (strcmp(mode,"gcm")==0) {
            evpCipher = FIPS_evp_aes_256_gcm();
        } else if (strcmp(mode,"ecb")==0) {
            evpCipher = FIPS_evp_aes_256_ecb();
        } else {
            fprintf(stderr, "invalid mode\n");
            return 0;
        }
        break;
    default:
        fprintf(stderr, "invalid aes key len\n");
        return 0;
    }

    if(FIPS_cipherinit(ctx, evpCipher, NULL, NULL, enc) <= 0) {
      fprintf(stderr, "FIPS_cipherinit failed (1)\n");
      return 0;
    }

    /* Set IV length if default 12 bytes (96 bits) is not appropriate for GCM mode */
    if(strcmp(mode,"gcm")==0)
        if(1 != FIPS_cipher_ctx_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, strlen(iv), NULL))
            fprintf(stderr, "FIPS_cipher_ctx_ctrl GCM_SET_IVLEN failed. \n");

    /* Initialise key and IV */
    if(FIPS_cipherinit(ctx, NULL, key, iv, enc) <= 0) {
      fprintf(stderr, "FIPS_cipherinit failed (2)\n");
      return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (plaintext_len % key_len != 0) {
        fprintf(stderr, "Error : plaintext is not a multiple of blocksize\n");
        return 0;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output. */
    if(plaintext) {
        if(1 != EVP_CipherUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
          fprintf(stderr, "EVP_CipherUpdate failed \n");
        }

        ciphertext_len = len;
    }

    /* Finalise the cryption. Normally ciphertext bytes may be written at this stage */
    if(1 != EVP_CipherFinal_ex(ctx, ciphertext + len, &len)) {
      fprintf(stderr, "EVP_CipherFinal_ex failed \n");
    }
    ciphertext_len += len;

    /* Clean up */
    FIPS_cipher_ctx_free(ctx);

    return ciphertext_len;
}