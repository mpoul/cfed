/* cfed_spkigen.c
 *
 * generuje pár RSA klíčů*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cfed_spkigen.h"

int SPKI_set_pubkey(NETSCAPE_SPKI *x, EVP_PKEY *pkey);
//#define RSA_F4	0x10001
#define EVP_PKEY_assign_RSA(pkey,rsa) EVP_PKEY_assign((pkey),EVP_PKEY_RSA,\
					(char *)(rsa))

int cfed_gen_spki(NETSCAPE_SPKI **spki, EVP_PKEY **pkey)
{
	RSA *rsa=NULL;
	int ok=0,i;
	/* pro ucely demonstrace staci napevno, pozdeji zmenit*/
	char buf[128] = "challengePassword";

	(*pkey)=EVP_PKEY_new();
	 
		/* Generate an RSA key, the random state should have been seeded
		 * with lots of calls to RAND_seed(....) */
		fprintf(stderr,"generating RSA key, could take some time...\n");
		if ((rsa=RSA_generate_key(512,RSA_F4,NULL,NULL)) == NULL) goto err;
	
	if (!EVP_PKEY_assign_RSA((*pkey),rsa)) goto err;
	rsa=NULL;

	/* lets make the spki and set the public key and challenge */
	if ((*spki=NETSCAPE_SPKI_new()) == NULL) goto err;

	if (!SPKI_set_pubkey((*spki),(*pkey))) goto err;

	i=strlen(buf);
	if (i > 0) buf[--i]='\0';
	if (!ASN1_STRING_set((ASN1_STRING *)(*spki)->spkac->challenge,
		buf,i)) goto err;

	if (!NETSCAPE_SPKI_sign(*spki,*pkey,EVP_md5())) goto err;

	ok=1;
err:
	if (!ok)
		{
		fprintf(stderr,"something bad happened....");
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "\n");
		return 1;
		}
	return 0;
	}
/* While I have a 
 * X509_set_pubkey() and X509_REQ_set_pubkey(), SPKI_set_pubkey() does
 * not currently exist so here is a version of it.
 * The next SSLeay release will probably have
 * X509_set_pubkey(),
 * X509_REQ_set_pubkey() and
 * NETSCAPE_SPKI_set_pubkey()
 * as macros calling the same function */
int SPKI_set_pubkey(x,pkey)
NETSCAPE_SPKI *x;
EVP_PKEY *pkey;
	{
	int ok=0;
	X509_PUBKEY *pk;
	X509_ALGOR *a;
	ASN1_OBJECT *o;
	unsigned char *s,*p;
	int i;

	if (x == NULL) return(0);

	if ((pk=X509_PUBKEY_new()) == NULL) goto err;
	a=pk->algor;

	/* set the algorithm id */
	if ((o=OBJ_nid2obj(pkey->type)) == NULL) goto err;
	ASN1_OBJECT_free(a->algorithm);
	a->algorithm=o;

	/* Set the parameter list */
	if ((a->parameter == NULL) || (a->parameter->type != V_ASN1_NULL))
		{
		ASN1_TYPE_free(a->parameter);
		a->parameter=ASN1_TYPE_new();
		a->parameter->type=V_ASN1_NULL;
		}
	i=i2d_PublicKey(pkey,NULL);
	if ((s=(unsigned char *)malloc(i+1)) == NULL) goto err;
	p=s;
	i2d_PublicKey(pkey,&p);
	if (!ASN1_BIT_STRING_set(pk->public_key,s,i)) goto err;
	free(s);

	X509_PUBKEY_free(x->spkac->pubkey);
	x->spkac->pubkey=pk;
	pk=NULL;
	ok=1;
err:
	if (pk != NULL) X509_PUBKEY_free(pk);
	return(ok);
	}

