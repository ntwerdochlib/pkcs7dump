#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

void show_errors(int line);

int main(int argc, char **argv)
{
	PKCS7 *p7 = NULL;
	BIO *in = BIO_new(BIO_s_file());
	BIO *out = BIO_new(BIO_s_file());
	STACK_OF(X509) *certs = NULL;
	int i;
	int ret = 0;

	if (argc < 2) {
		printf("%s [PKCS7 Certificate]\n", argv[0]);
		return 4;
	}

	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	BIO_set_fp(out, stdout, BIO_NOCLOSE);
	BIO_read_filename(in, argv[1]);
	p7 = d2i_PKCS7_bio(in, NULL);
	if (!p7) {
		p7 = PEM_read_bio_PKCS7(in, NULL, NULL, NULL);
		if (!p7) {
			BIO_printf(out, "Failed to load PKCS7 certificate.\n");
			ret = 1;
			goto end;
		}
	}

	i = OBJ_obj2nid(p7->type);
	show_errors(__LINE__);
	switch (i) {
		case NID_pkcs7_signed:
			printf("Certificate is signed.\n");
			certs = p7->d.sign->cert;
			break;

		case NID_pkcs7_signedAndEnveloped:
			printf("Certificate is signed and enveloped.\n");
			certs = p7->d.signed_and_enveloped->cert;
			break;

		default:
			printf("Unsupported type: %d\n", i);
			break;
	}

	const int numcerts = sk_X509_num(certs);
	printf("%d Certificates found.\n", numcerts);
	PKCS7_print_ctx(out, p7, 0, NULL);

end:
	if (ret > 0) {
		printf("ERROR: %d\n", ret);
		show_errors(__LINE__);
	}

	if (p7) {
		PKCS7_free(p7);
	}
	BIO_free(in);
	BIO_free_all(out);
	return ret;
}

void show_errors(int line)
{
	BIO *out = BIO_new(BIO_s_file());
	BIO_set_fp(out, stdout, BIO_NOCLOSE);
	char errstr[256] = {0};
	int error = ERR_get_error();
	if (error) {
		BIO_printf(out, "Error occured at: %d\n", line);
	}
	while (error) {
		BIO_printf(out, "%s\n", ERR_error_string(error, &errstr[0]));
		error = ERR_get_error();
	}
}
