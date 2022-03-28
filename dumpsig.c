#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

void show_errors(int line);
int show_pkcs7(const char* data, const int len);

int main(int argc, char *argv[])
{
	char *addr = NULL;
	int fd = -1;
	struct stat sb;

	if (argc < 2) {
		printf("%s [File]\n", argv[0]);
		return 0;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd == -1)  {
		printf("Failed to open %s\n", argv[1]);
		return 1;
	}

	if (fstat(fd, &sb) == -1) {
		printf("Failed to get file size.\n");
		return 1;
	}

	addr = (char*)mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		printf("Failed to map file.\n");
	}

#if 0
	// 06 08 2B 06 01 05 05 07
	const char* sig = "\x06\x08\x2B\x06\x01\x05\x05\x07";
	const size_t sig_len = 8;
#else
  //                   06  09  2A  86  48  86  F7  0D  01  07 02
	const char* sig = "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02";
	const size_t sig_len = 11; //strlen(sig);
#endif
	/*
	for (int i = 0; i < sig_len; ++i) {
		printf("%2.2x ", sig[i]);
	}
	printf("\n");
	*/
	char* sig_start = NULL;
	size_t sig_bytes = 0;
	size_t sig_offset = 0;
	for (size_t i=sb.st_size-sig_len-1; i > 0; i-=1) {
		//printf(".");
		if (addr[i] == sig[0]) {
			if (memcmp(&addr[i], sig, sig_len) == 0) {
				sig_start = &addr[i-4];
				sig_offset = i - 4;
				sig_bytes = sb.st_size - sig_offset;
				printf("Found signature at: %#x Bytes: %x\n", sig_offset, sig_bytes);
				break;
			}
		}
	}

	if (sig_start) {
		show_pkcs7(sig_start, sig_bytes);
#if 1
		int f = open("signature.der", O_WRONLY);
		if (f > -1) {
			write(f, sig_start, sig_bytes);
			close(f);
		}
#endif
	}

	munmap(addr, sb.st_size);

	close(fd);

	return 0;
}

int show_pkcs7(const char* data, const int len)
{
	PKCS7 *p7 = NULL;
	BIO *in = BIO_new(BIO_s_mem());
	BIO *out = BIO_new(BIO_s_file());
	STACK_OF(X509) *certs = NULL;
	int i;
	int ret = 0;
	int numcerts;

	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();

	BIO_set_fp(out, stdout, BIO_NOCLOSE);
	BIO_write(in, data, len);
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

	if (certs) {
		numcerts = sk_X509_num(certs);
		printf("%d Certificates found.\n", numcerts);
#if 0
		PKCS7_print_ctx(out, p7, 0, NULL);
#else
		for (int i=0; i < numcerts; ++i) {
			X509* cert = sk_X509_value(certs, i);
			BIO_printf(out, "\nPKCS7 Certificate %d\n\n", i);
			if (cert) {
				X509_print(out, cert);
			}
		}
#endif
	}

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
