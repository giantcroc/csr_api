#define TestAlone
#include "sgx.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

typedef ByteString BYTE_STRING;
void show_data(BYTE_STRING data)
{
    for(CK_ULONG i=0;i<data.byte_size;i++)
    {
        printf("%x ",data.bytes[i]);
    }
    printf("\n");
}

int add_ext(STACK_OF(X509_EXTENSION) *exts, int nid, const char* subvalue)
{
    X509_EXTENSION  *pSubExt = NULL;
    pSubExt = X509V3_EXT_conf_nid(NULL, NULL, nid, subvalue);
    sk_X509_EXTENSION_push(exts, pSubExt);
    return 0;
}
bool gen_X509Req(SGXContext& sgxcontext,CK_OBJECT_HANDLE pubkey)
{
	int				ret = 0;
	RSA				*r = NULL;
	BIGNUM			*bne = NULL;

	int				nVersion = 0;
	int				bits = 2048;
	unsigned long	e = RSA_F4;
    int length =0;

	X509_REQ		*x509_req = NULL;
	X509_NAME		*x509_name = NULL;
	EVP_PKEY		*pKey = NULL;
	BIO				*bio = NULL, *bio_err = NULL;

	const char		*szCommon = "localhost";

	const char		*szPath = "x509Req.pem";

    char* pem=NULL;

    CK_RV status = CKR_OK;

    RSA* openssl_rsa = NULL;
    BIGNUM * bn_modulus = NULL;
    BIGNUM * bn_public_exponent = NULL;
    int success = 0;

    EVP_PKEY* evp_pkey = NULL;
    ByteString modulus,exponent;

     /* Add various extensions: standard extensions */
	STACK_OF(X509_EXTENSION)  *exts = sk_X509_EXTENSION_new_null();

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
		goto free_all;
	}

	// 2. set version of x509 req
	x509_req = X509_REQ_new();
	ret = X509_REQ_set_version(x509_req, nVersion);
	if (ret != 1){
		goto free_all;
	}

	// 3. set subject of x509 req
	x509_name = X509_REQ_get_subject_name(x509_req);

	ret = X509_NAME_add_entry_by_txt(x509_name,"CN", MBSTRING_ASC, (const unsigned char*)szCommon, -1, -1, 0);
	if (ret != 1){
		goto free_all;
	}

	/* Standard extenions */
	add_ext(exts, NID_basic_constraints, "CA:FALSE");

	add_ext(exts, NID_key_usage, "Digital Signature,Non Repudiation,Key Encipherment");
    
    add_ext(exts, NID_ext_key_usage, "TLS Web Client Authentication, TLS Web Server Authentication");

    add_ext(exts, NID_subject_alt_name, "IP:127.0.0.1,IP:::1");

    X509_REQ_add_extensions(x509_req, exts);

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

	// 4. set public key of x509 req
	pKey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pKey, r);
	r = NULL;	// will be free rsa when EVP_PKEY_free(pKey)

	ret = X509_REQ_set_pubkey(x509_req, pKey);
	if (ret != 1){
		goto free_all;
	}

	// 5. set sign key of x509 req
	ret = X509_REQ_sign(x509_req, pKey, EVP_sha256());	// return x509_req->signature->length
	if (ret <= 0){
		goto free_all;
	}

    status = sgxcontext.GetPublicKey(pubkey,&modulus,&exponent);
    if (status != CKR_OK) {
        printf("Error get pubkey\n");
    } 
    else{
        show_data(modulus);
        show_data(exponent);
    }

    openssl_rsa = RSA_new();
     bn_modulus = BN_bin2bn(modulus.bytes, static_cast<int>(modulus.byte_size), nullptr);
     bn_public_exponent = BN_bin2bn(exponent.bytes,
                                        static_cast<int>(exponent.byte_size),
                                        nullptr);
     success = RSA_set0_key(openssl_rsa, bn_modulus, bn_public_exponent, nullptr);

     evp_pkey = EVP_PKEY_new();

    /* Add public key to certificate request */
    EVP_PKEY_assign(evp_pkey, EVP_PKEY_RSA, openssl_rsa);

    X509_REQ_set_pubkey(x509_req, evp_pkey);
    EVP_PKEY_free(evp_pkey);

	bio = BIO_new(BIO_s_mem());
	ret = PEM_write_bio_X509_REQ(bio, x509_req);
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    length = bptr->length;
    pem = (char *) malloc(length + 1);
    if (NULL == pem) {
        BIO_free(bio);
        return NULL;    
    }

    memset(pem, 0, length + 1);
    BIO_read(bio, pem, length);

    printf("%s\n",pem);
	// 6. free
free_all:
	X509_REQ_free(x509_req);
	BIO_free(bio);

	EVP_PKEY_free(pKey);
	BN_free(bne);

	return (ret == 1);
}
int main()
{
    std::string libpath="/usr/local/lib/libp11sgx.so";
    std::string tokenlabel="my_token_label";
    std::string so_pin="my_so_pin";
    std::string user_pin="my_usr_pin";
    std::string keylabel="rsa";
    std::string ecparam="P-256";
    CK_RV status = CKR_OK;
    CK_OBJECT_HANDLE privkey;
    CK_OBJECT_HANDLE pubkey;
    CK_ULONG object_count =0;

    SGXContext sgxcontext(libpath,tokenlabel,so_pin,user_pin);
    status = sgxcontext.SGXInit();
    if (status != CKR_OK) {
        return 0;
    } 

    status = sgxcontext.FindKeyPair(&privkey, &pubkey, keylabel,object_count);
    if (status != CKR_OK) {
        return 0;
    } 
    if(object_count==0)
    {
        status = sgxcontext.CreateRSAKeyPair(&privkey, &pubkey, keylabel,2048,true);
        if (status != CKR_OK) {
            return 0;
        } 
    }
    else if(object_count>1)
    {
        return 0;
    }
    gen_X509Req(sgxcontext,pubkey);

    return 0;
}
