/*
 * Copyright (c) 2009 Atheme Development Group
 * Rights to this code are as documented in doc/LICENSE.
 *
 * Raw SHA1 password encryption, as used by e.g. Anope 1.8.
 * Hash functions are not designed to encrypt passwords directly,
 * but we need this to convert some Anope databases.
 */

#include "atheme.h"

#ifdef HAVE_OPENSSL

#include <openssl/sha.h>

DECLARE_MODULE_V1
(
	"crypto/saltedsha1", false, _modinit, _moddeinit,
	PACKAGE_STRING,
	"Atheme Development Group <http://www.atheme.org>"
);

#define RAWSHA1_PREFIX "$rawsha1$"

static const char *find_salt(const char *salt)
{
    char *orig_salt = NULL;

    if ((orig_salt = strstr(salt, "$salt$")) != NULL)
	{
	       salt = orig_salt + 6;
    }

	return salt;
}

static char *salt_key(const char *key, const char *salt)
{
	char *salted_key = NULL;
	int salted_key_size;

	salted_key_size = strlen(key) + strlen(salt) + 1;
	salted_key = smalloc(salted_key_size);

	snprintf(salted_key, salted_key_size, "%s%s", key, salt);

	return salted_key;
}

static const char *saltedsha1_crypt_string(const char *key, const char *salt)
{
	static char output[2 * SHA_DIGEST_LENGTH + sizeof(RAWSHA1_PREFIX) + 32];
	SHA_CTX ctx;
	unsigned char digest[SHA_DIGEST_LENGTH];
	int i;
	char *salted_key = NULL;

	salt = find_salt(salt); 
	salted_key = salt_key(key, salt);

	SHA1_Init(&ctx);
	SHA1_Update(&ctx, salted_key, strlen(salted_key));
	SHA1_Final(digest, &ctx);

	strcpy(output, RAWSHA1_PREFIX);
	for (i = 0; i < SHA_DIGEST_LENGTH; i++)
		sprintf(output + sizeof(RAWSHA1_PREFIX) - 1 + i * 2, "%02x",
				255 & digest[i]);

	strcat(output, "$salt$");
	strcat(output, salt);

	free(salted_key);

	return output;
}

void _modinit(module_t *m)
{
	crypt_string = &saltedsha1_crypt_string;

	crypto_module_loaded = true;
}

void _moddeinit(void)
{
	crypt_string = &generic_crypt_string;

	crypto_module_loaded = false;
}

#endif /* HAVE_OPENSSL */

/* vim:cinoptions=>s,e0,n0,f0,{0,}0,^0,=s,ps,t0,c3,+s,(2s,us,)20,*30,gs,hs
 * vim:ts=8
 * vim:sw=8
 * vim:noexpandtab
 */
