.SUFFIXES: .c
SHELL = /bin/bash
PROGRAM = pkcs7dump
PKCS7_CERT=test-p7b.cer
PVK_CERT=test-pvk.cer
PVK_CERT_FORM=DER
OPENSSL_CFLAGS=$(shell pkg-config --cflags libcrypto)
OPENSSL_LIBS=$(shell pkg-config --libs libcrypto) -ldl
CFLAGS = -g $(OPENSSL_CFLAGS)
LDFLAGS = $(OPENSSL_LIBS)

SRCS = pkcs7dump.c
OBJS=$(SRCS:.c=.o)

all : $(PROGRAM)

.c.o:
	g++ -c $(CFLAGS) $<

dumpsig : dumpsig.o
	g++ $(CFLAGS)-o $@ $? $(LDFLAGS) 

$(PROGRAM) : $(OBJS)
	gcc $(CFLAGS)-o $@ $? $(LDFLAGS) 

.SAMESHELL:
clean:
	-for f in $(OBJS); do if [[ -e $$f ]]; then rm $$f; fi; done
	-[[ -e $(PROGRAM) ]] && rm $(PROGRAM)

.SAMESHELL:
run : $(PROGRAM)
	./$(PROGRAM) $(PKCS7_CERT)
	openssl cms -in test.enc -inform DER -inkey $(PVK_CERT) -keyform $(PVK_CERT_FORM) -decrypt

.SAMESHELL:
test : $(PROGRAM)
	./$(PROGRAM) $(PKCS7_CERT)

dump : pkcs7dump
	./$? $(PKCS7_CERT)

