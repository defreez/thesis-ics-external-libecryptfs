/**
 * Copyright (C) 2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *		Tyler Hicks <tyhicks@ou.edu>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <errno.h>
#include <mntent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mount.h>
#include <getopt.h>
#include <sys/types.h>
#include <keyutils.h>
#include <sys/ipc.h>
#include <sys/param.h>
#include <openssl/evp.h>
#include "../include/ecryptfs.h"

int ecryptfs_verbosity = 0;

void ecryptfs_get_versions(int *major, int *minor, int *file_version)
{
	*major = ECRYPTFS_VERSION_MAJOR;
	*minor = ECRYPTFS_VERSION_MINOR;
	if (file_version)
		*file_version = ECRYPTFS_SUPPORTED_FILE_VERSION;
}

inline void to_hex(char *dst, char *src, int src_size)
{
	int x;

	for (x = 0; x < src_size; x++)
		sprintf(&dst[x*2], "%.2x", (unsigned char)src[x] );
	dst[src_size*2] = '\0';
}

void from_hex(char *dst, char *src, int dst_size)
{
        int x;
        char tmp[3] = { 0, };

        for (x = 0; x < dst_size; x++) {
                tmp[0] = src[x * 2];
                tmp[1] = src[x * 2 + 1];
                dst[x] = (char)strtol(tmp, NULL, 16);
        }
}

int do_hash(char *src, int src_size, char *dst, char *algo)
{
        EVP_MD_CTX mdctx;
        const EVP_MD *md;
        unsigned int md_len;
        int rc; 

        OpenSSL_add_all_digests();

        rc = 0;
        md = EVP_get_digestbyname(algo);    
        if (!md) {
                fprintf(stderr, "Unable to get digest %s\n", algo);
                rc = 1;
                goto out;
        }   
    
        EVP_MD_CTX_init(&mdctx);
        EVP_DigestInit_ex(&mdctx, md, NULL);
        EVP_DigestUpdate(&mdctx, src, src_size);
        EVP_DigestFinal_ex(&mdctx, (unsigned char*)dst, &md_len);

        EVP_cleanup();
out:
        return rc;    
}

/* Read ecryptfs private mount from file
 * Allocate and return a string
 */
char *ecryptfs_fetch_private_mnt(char *pw_dir) {
	char *mnt_file = NULL;
	char *mnt_default = NULL;
	char *mnt = NULL;
	FILE *fh = NULL;
	/* Construct mnt file name */
	if (asprintf(&mnt_default, "%s/%s", pw_dir, ECRYPTFS_PRIVATE_DIR) < 0
			|| mnt_default == NULL) {
		perror("asprintf");
		return NULL;
	}
	if (
			asprintf(&mnt_file, "%s/.ecryptfs/%s.mnt", pw_dir, ECRYPTFS_PRIVATE_DIR) < 0
			|| mnt_file == NULL) {
		perror("asprintf");
		return NULL;
	}
	fh = fopen(mnt_file, "r");
	if (fh == NULL) {
		mnt = mnt_default;
	} else {
		flockfile(fh);
		if ((mnt = (char *)malloc(MAXPATHLEN+1)) == NULL) {
			perror("malloc");
			return NULL;
		}
		if (fgets(mnt, MAXPATHLEN, fh) == NULL) {
			mnt = mnt_default;
		} else {
			/* Ensure that mnt doesn't contain newlines */
			mnt = strtok(mnt, "\n");
		}
		fclose(fh);
	}
	if (mnt_file != NULL)
		free(mnt_file);
	if (mnt_default != NULL && mnt != mnt_default)
		free(mnt_default);
	return mnt;
}

/**
 * TODO: We need to support more hash algs
 * @fekek: ECRYPTFS_MAX_KEY_BYTES bytes of allocated memory
 *
 * @passphrase A NULL-terminated char array
 *
 * @salt A salt
 *
 * @passphrase_sig An allocated char array into which the generated
 * signature is written; PASSWORD_SIG_SIZE bytes should be allocated
 *
 */
int
generate_passphrase_sig(char *passphrase_sig, char *fekek,
                        char *salt, char *passphrase)
{
        char salt_and_passphrase[ECRYPTFS_MAX_PASSPHRASE_BYTES
                                 + ECRYPTFS_SALT_SIZE];
        int passphrase_size;
        char *alg = "sha512";
        int dig_len = SHA512_DIGEST_LENGTH;
        char buf[SHA512_DIGEST_LENGTH];
        int hash_iterations = ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS;
        int rc = 0;

        passphrase_size = strlen(passphrase);
        if (passphrase_size > ECRYPTFS_MAX_PASSPHRASE_BYTES) {
                passphrase_sig = NULL;
                fprintf(stderr, "Passphrase too large (%d bytes)\n",
                       passphrase_size);
                return -EINVAL;
        }
        memcpy(salt_and_passphrase, salt, ECRYPTFS_SALT_SIZE);
        memcpy((salt_and_passphrase + ECRYPTFS_SALT_SIZE), passphrase,
                passphrase_size);
        if ((rc = do_hash(salt_and_passphrase,
                          (ECRYPTFS_SALT_SIZE + passphrase_size), buf, alg))) {
                return rc;
        }
        hash_iterations--;
        while (hash_iterations--) {
                if ((rc = do_hash(buf, dig_len, buf, alg))) {
                        return rc;
                }
        }
        memcpy(fekek, buf, ECRYPTFS_MAX_KEY_BYTES);
        if ((rc = do_hash(buf, dig_len, buf, alg))) {
                return rc;
        }
        to_hex(passphrase_sig, buf, ECRYPTFS_SIG_SIZE);
        return 0;
}

/**
 * @return Zero on success
 */
int
generate_payload(struct ecryptfs_auth_tok *auth_tok, char *passphrase_sig,
		 char *salt, char *session_key_encryption_key)
{
	int rc = 0;
	int major, minor;

	memset(auth_tok, 0, sizeof(struct ecryptfs_auth_tok));
	ecryptfs_get_versions(&major, &minor, NULL);
	auth_tok->version = (((uint16_t)(major << 8) & 0xFF00)
			     | ((uint16_t)minor & 0x00FF));
	auth_tok->token_type = ECRYPTFS_PASSWORD;
	strncpy((char *)auth_tok->token.password.signature, passphrase_sig,
		ECRYPTFS_PASSWORD_SIG_SIZE);
	memcpy(auth_tok->token.password.salt, salt, ECRYPTFS_SALT_SIZE);
	memcpy(auth_tok->token.password.session_key_encryption_key,
	       session_key_encryption_key, ECRYPTFS_MAX_KEY_BYTES);
	/* TODO: Make the hash parameterizable via policy */
	auth_tok->token.password.session_key_encryption_key_bytes =
		ECRYPTFS_MAX_KEY_BYTES;
	auth_tok->token.password.flags |=
		ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET;
	/* The kernel code will encrypt the session key. */
	auth_tok->session_key.encrypted_key[0] = 0;
	auth_tok->session_key.encrypted_key_size = 0;
	/* Default; subject to change by kernel eCryptfs */
	auth_tok->token.password.hash_algo = PGP_DIGEST_ALGO_SHA512;
	auth_tok->token.password.flags &= ~(ECRYPTFS_PERSISTENT_PASSWORD);
	return rc;
}

static struct ecryptfs_ctx_ops ctx_ops;

struct ecryptfs_ctx_ops *cryptfs_get_ctx_opts (void)
{
	return &ctx_ops;
}

