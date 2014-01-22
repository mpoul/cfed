/* cfed_spki.h
 *
 * hlavičková funkce pro cfed_spki.c*/

#ifndef _CFED_SPKIGEN_H
#define _CFED_SPKIGEN_H

#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

/* vygeneruj par RSA klicu pevne delky 512b */
int cfed_gen_spki(NETSCAPE_SPKI **spki, EVP_PKEY **p_key);

#endif
