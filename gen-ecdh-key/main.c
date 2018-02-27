#include <openssl/evp.h>
#include <openssl/ec.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

//Initialize
void initialize_fips(int mode){
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

//Show status
void fips_mode(){
    if(FIPS_mode()){
        fprintf(stdout, "FUNCTION: %s, LOG: FIPS MODE ENABLE\n", __func__);
    } else {
        fprintf(stdout, "FUNCTION: %s, LOG: FIPS MODE DISABLE\n", __func__);
    }
}


int main() {
    //fips mode *ON*
    initialize_fips(1);
    //check self test status
    fips_mode();

    //fips mode *OFF*
    initialize_fips(0);
    //check self test status
    fips_mode();

	EC_KEY *ec1 = NULL, *ec2 = NULL;
	EVP_PKEY *pkey = NULL;
	const EC_POINT *ecp = NULL;
	BIGNUM *x = NULL, *y = NULL, *d = NULL;
	unsigned char *ztmp = NULL;
	int rv = 1;
	size_t i;
	BIO *outbio  = NULL;
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	int curve = 713;
	const unsigned char x1[] = {
	0x23,0xff,0x15,0x91,0x83,0xd6,0xad,0x98,0x93,0x98,0xbd,0x2e,
	0x01,0xeb,0x5a,0x45,0xe2,0x2a,0xf9,0xc5,0x3b,0x37,0xe1,0x87,
	0x32,0xa5,0x16,0x5f };
	size_t x1len = sizeof(x1);
	const unsigned char y1[] = {
	0x5e,0x70,0xb7,0x9d,0x9e,0x55,0x2d,0x67,0x4e,0x29,0xa4,0x9d,
	0x06,0x81,0x11,0xb4,0xb4,0xab,0xe2,0xdf,0xdc,0xe4,0xf1,0x69,
	0x55,0x54,0xe3,0x37 };
	size_t y1len = sizeof(y1);
	const unsigned char d1[] = {
	0xd7,0xdc,0x9c,0x53,0x04,0x72,0x67,0x59,0x92,0x80,0x9e,0x6f,
	0xdd,0xe6,0x0b,0x35,0x09,0xe0,0x95,0x45,0xe6,0x13,0x0e,0x22,
	0x43,0x6a,0x63,0xef };
	size_t d1len = sizeof(d1);
	const unsigned char x2[] = {
	0x3c,0x81,0x15,0x16,0xab,0xa6,0xad,0xd7,0xe5,0xf3,0xea,0x1f,
	0x88,0x57,0x43,0x29,0x35,0x6f,0x0a,0xd2,0x38,0xc7,0x11,0x8a,
	0x90,0xd1,0x46,0x63 };
	size_t x2len = sizeof(x2);
	const unsigned char y2[] = {
	0x4a,0x87,0x54,0x7b,0x7d,0x69,0xdd,0xb8,0x48,0x73,0xb2,0x1e,
	0x33,0xfa,0xf6,0x32,0xb4,0x25,0x73,0x55,0x87,0x08,0x16,0xd2,
	0xdd,0xa6,0x77,0xcf };
	size_t y2len = sizeof(y2);
	const unsigned char z[] = {
	0x84,0x37,0xcf,0x6d,0xfa,0x58,0xbd,0x1f,0x47,0x15,0x45,0x1f,
	0x2c,0x20,0x53,0x7a,0xf4,0xb0,0xe6,0x19,0xcc,0xa9,0x30,0xc6,
	0x5c,0x1a,0xf2,0xdd };
	size_t zlen = sizeof(z);

	ztmp = OPENSSL_malloc(zlen);

    EC_KEY *myecc   = NULL;

	int eccgrp = OBJ_txt2nid("secp224r1");
    myecc = EC_KEY_new_by_curve_name(eccgrp);
	FIPS_ec_key_generate_key(myecc);

	x = BN_bin2bn(x1, x1len, x);
	y = BN_bin2bn(y1, y1len, y);
	d = BN_bin2bn(d1, d1len, d);

	if (!x || !y || !d || !ztmp)
		{
		rv = -1;
		goto err;
		}

	ec1 = EC_KEY_new_by_curve_name(curve);
	if (!ec1)
		{
		rv = -1;
		goto err;
		}
	EC_KEY_set_flags(ec1, EC_FLAG_COFACTOR_ECDH);

	if (!EC_KEY_set_public_key_affine_coordinates(ec1, x, y))
		{
		rv = -1;
		goto err;
		}

	if (!EC_KEY_set_private_key(ec1, d))
		{
		rv = -1;
		goto err;
		}
	ec1 = myecc;
    const EC_GROUP *ecgrp = EC_KEY_get0_group(ec1);
	pkey=EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pkey,ec1);
    BIO_printf(outbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
	BIO_printf(outbio, "ECC Key type: %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));

    /* ---------------------------------------------------------- *
    * Here we print the private/public key data in PEM format.   *
    * ---------------------------------------------------------- */
	PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL);

	x = BN_bin2bn(x2, x2len, x);
	y = BN_bin2bn(y2, y2len, y);

	if (!x || !y)
		{
		rv = -1;
		goto err;
		}

	ec2 = EC_KEY_new_by_curve_name(curve);
	if (!ec2)
		{
		rv = -1;
		goto err;
		}
	EC_KEY_set_flags(ec1, EC_FLAG_COFACTOR_ECDH);

	if (!EC_KEY_set_public_key_affine_coordinates(ec2, x, y))
		{
		rv = -1;
		goto err;
		}

	ecp = EC_KEY_get0_public_key(ec2);
	if (!ecp)
		{
		rv = -1;
		goto err;
		}

	PEM_write_bio_PUBKEY(outbio, pkey);
	
	if (!ECDH_compute_key(ztmp, zlen, ecp, ec1, 0))
		{
		rv = -1;
		goto err;
		}

	BIO_printf(outbio, "Secret : ");

	for(i = 0; i < sizeof(ztmp); i++)
	{
    	if (i > 0) printf(":");
    	BIO_printf(outbio, "%02X", ztmp[i]);
	}
    BIO_printf(outbio, "\n");

	BIO_printf(outbio, "Expected Secret : ");
	for(i = 0; i < sizeof(ztmp); i++)
	{
    	if (i > 0) printf(":");
    	BIO_printf(outbio, "%02X", ztmp[i]);
	}
    BIO_printf(outbio, "\n");

	err:
		if (x)
			BN_clear_free(x);
		if (y)
			BN_clear_free(y);
		if (d)
			BN_clear_free(d);
		if (ec1)
			EC_KEY_free(ec1);
		if (ec2)
			EC_KEY_free(ec2);
		if (ztmp)
			OPENSSL_free(ztmp);

    return 0;
}

