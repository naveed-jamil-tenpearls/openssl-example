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

void handleErrors() {


}

void main(int argc, char *argv[])
{
    initialize_fips(1);

    unsigned char tag[16] = "0123456789012341";
    unsigned char *key_str = (unsigned char *)"example key 1234example key 1234";
    unsigned char *iv_str = (unsigned char *)"0123456789012341";
    unsigned char *plaintext = (unsigned char *)"exampleplaintext";
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
        fprintf(stderr, "USAGE: %s [key] [iv] [plain-text] [mode]\nMode is 'ccm'\n", argv[0]);
        return;
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

    ciphertext_len = encryptccm(plaintext, strlen(plaintext), key, iv, ciphertext, tag, key_len);

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

    decryptedtext_len = decryptccm(ciphertext, ciphertext_len, key, iv, decryptedtext, tag, key_len);

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


int encryptccm(unsigned char *plaintext, int plaintext_len, unsigned char *key,
 unsigned char *iv,	unsigned char *ciphertext, unsigned char* tag, int key_len)
{
	EVP_CIPHER_CTX *ctx;

	int len;

	int ciphertext_len;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  const EVP_CIPHER *evpCipher;
  switch (key_len) {
  case 16:
        evpCipher = FIPS_evp_aes_128_ccm();
        break;
  case 24:
        evpCipher = FIPS_evp_aes_192_ccm();
        break;
  case 32:
        evpCipher = FIPS_evp_aes_256_ccm();
        break;
  default:
        fprintf(stderr, "invalid aes key len\n");
        return 0;
  }

	/* Initialise the encryption operation. */
	if(1 != EVP_EncryptInit_ex(ctx, evpCipher, NULL, NULL, NULL))
		handleErrors();

	/* Setting IV len to 7. Not strictly necessary as this is the default
	 * but shown here for the purposes of this example */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
		handleErrors();

	/* Set tag length */
	EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, NULL);

	/* Initialise key and IV */
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can only be called once for this
	 */

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		handleErrors();
	ciphertext_len = len;

	/* Finalise the encryption. Normally ciphertext bytes may be written at
	 * this stage, but this does not occur in CCM mode
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 14, tag))
		handleErrors();

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

int decryptccm(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv,
	unsigned char *plaintext, unsigned char* tag, int key_len)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;
	int ret;

	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  const EVP_CIPHER *evpCipher;
  switch (key_len) {
  case 16:
        evpCipher = FIPS_evp_aes_128_ccm();
        break;
  case 24:
        evpCipher = FIPS_evp_aes_192_ccm();
        break;
  case 32:
        evpCipher = FIPS_evp_aes_256_ccm();
        break;
  default:
        fprintf(stderr, "invalid aes key len\n");
        return 0;
  }

	/* Initialise the decryption operation. */
	if(1 != EVP_DecryptInit_ex(ctx, evpCipher, NULL, NULL, NULL))
		handleErrors();

	/* Setting IV len to 7. Not strictly necessary as this is the default
	 * but shown here for the purposes of this example */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, 7, NULL))
		handleErrors();

	/* Set expected tag value. */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, 14, tag))
		handleErrors();

	/* Initialise key and IV */
	if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */

	 ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);

	plaintext_len = len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		/* Success */
		return plaintext_len;
	}
	else
	{
		/* Verify failed */
		return -1;
	}
}
