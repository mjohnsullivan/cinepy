/*
 * Calculates the certificate thumbprint of PEM-encoded X.509 document
 * Adapted from dc-thumbprint.c in http://www.dcimovies.com/DCI_CTP_v1_1.pdf
 *
 * Updated to handle PEM files already loaded into a char array
 *
 */
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
typedef unsigned char byte_t;

#define CHUNK 2048 /* Chunk size for reading bytes from a file */

/*
 * Encode a byte array to base64
 */
char* encodeBase64(byte_t* in_buf, int in_len, char* out_buf, int out_len)
{
  BIO *bmem, *b64;
  BUF_MEM *bptr;
  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, in_buf, in_len);
  if ( BIO_flush(b64) != 1 )
    {
      fprintf(stderr, "write to buffer failed.\n");
      return 0; }
  BIO_get_mem_ptr(b64, &bptr);
  if ( bptr->length + 1 > out_len )
    {
      fprintf(stderr, "encoding exceeds buffer length.\n");
      return 0; }
  memcpy((byte_t*)out_buf, bptr->data, bptr->length-1);
  out_buf[bptr->length-1] = 0;
  return out_buf;
}

/*
 * Creates an X509 certificate from a PEM file
 * stored in a string
 */
static X509 *loadCertFromMem(char *data, int data_len)
{
    BIO *bio;
    X509 *certificate;

    bio = BIO_new(BIO_s_mem());
    int cert_len = BIO_write(bio,(const void*)data, data_len);

    if (cert_len != data_len)
        fprintf(stderr, "Error creating BIO version of pem\n");

    if( (certificate = PEM_read_bio_X509(bio, NULL, 0, NULL)) == 0)
        fprintf(stderr, "Error getting cert\n");

    return certificate;
}

/*
 * Calculate a thumbprint from an X509 cert
 */
char* calc_thumbprint_from_string(char* pem, int pem_len)
{
    X509 *cert;
    byte_t  sha_value[20];     /* buffer for resulting thumbprint digest */
    char    sha_base64[64];    /* buffer for Base64 version of the thumbprint digest */
    byte_t  p_key_buf[8192];   /* buffer holds DER encoded certificate body */
    size_t  length;
    byte_t* p = p_key_buf;
    SHA_CTX SHA;

    cert = loadCertFromMem(pem, pem_len);
    OpenSSL_add_all_digests();
      
    if ( i2d_X509_CINF(cert->cert_info, &p) == 0 )
      {
        fprintf(stderr, "i2d_X509_CINF error\n");
        return 4; 
      }
    length = p - p_key_buf;
    if ( length > 8192 )
      {
        fprintf(stderr, "i2d_X509_CINF value exceeds buffer length\n");
        return 5;
      }
    SHA1_Init(&SHA);
    SHA1_Update(&SHA, p_key_buf, length);
    SHA1_Final(sha_value, &SHA);
    if ( encodeBase64(sha_value, 20, sha_base64, 64) == 0 )
      return NULL;
    return sha_base64;
}

int main(int argc, char** argv)
{
    FILE* fp;
    if ( argc != 2 )
      {
        fprintf(stderr, "USAGE: dc-thumbprint cert-file.pem\n");
        return 1; }
    if ( (fp = fopen (argv[1], "r")) == 0 )
      {
        perror("fopen");
        return 2;
      }
    // Load in the cert
    size_t nread;
    size_t pos = 0;
    unsigned char* buf = malloc(CHUNK);
    unsigned char* pem = NULL;
    while( (nread = fread(buf, 1, CHUNK, fp)) > 0)
    {
        // Copy the buffer into the PEM array
        if (!pem)
	    pem = malloc(nread);
	else {
	    pem = realloc(pem, nread);
	    printf("Reallocating memory");
	}
	int i;
	for (i=0;i<nread;i++)
	{
	    pem[i+pos] = buf[i];
	}
	pos += nread;
    }
    fclose(fp);
    printf("Thumbprint: %s", calc_thumbprint_from_string(pem, pos));
    return 0;
}
