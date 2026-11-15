/*
 * torture_krl.c - unit tests for OpenSSH KRL (Key Revocation List) support
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2026 by the libssh contributors
 *
 * The SSH Library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or (at your
 * option) any later version.
 *
 * The SSH Library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with the SSH Library; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 */

#include "config.h"

#define LIBSSH_STATIC

#include <stdio.h>
#include <string.h>
#include <time.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include <libssh/priv.h>
#include <libssh/buffer.h>
#include <libssh/crypto.h>
#include <libssh/krl.h>
#include <libssh/pki.h>
#include <libssh/session.h>
#include <libssh/string.h>
#include <libssh/wrapper.h>

#include "torture.h"

#define ED25519_B64 \
    "AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"
#define RSA_B64 \
    "AAAAB3NzaC1yc2EAAAADAQABAAABAQDD7g+vV5cvxxGN0Ldmda4WZCPgRaxV1tV+1KRZoGUNUI61h0X4bmmGaAPRQBCz4G1d9bawqDqEqnpFWazrxBU5cQtISSjzuDJKovLGliky/ShTszee1Thszg3qVNk9gGOWj7jn/HDaOxRlp003Bp47MOdnMnK/oftllFDfY2fF5IRpE6sSIGtg2ZDtF95TV5/9W2oMOIAy8u/83tuibYlNPa1X/von5LgdaPLn6Bk16bQKIhAhlMtFZH8MBYEWe4ZtOGaSWKOsK9MM/RTMlwPi6PkfoHNl4MCMupjx+CdLXwbQEt9Ww+bBIaCui2VWBEiruVbIgJh0W2Tal0e2BzYZ"

#define KRL_TMP_FILE "/tmp/torture_krl_XXXXXX"

static ssh_key test_ed25519_key(void)
{
    ssh_key key = NULL;
    int rc;

    rc = ssh_pki_import_pubkey_base64(ED25519_B64, SSH_KEYTYPE_ED25519, &key);
    assert_int_equal(rc, SSH_OK);

    return key;
}

static ssh_key test_rsa_key(void)
{
    ssh_key key = NULL;
    int rc;

    rc = ssh_pki_import_pubkey_base64(RSA_B64, SSH_KEYTYPE_RSA, &key);
    assert_int_equal(rc, SSH_OK);

    return key;
}

static ssh_string test_key_blob(ssh_key key)
{
    ssh_string blob = NULL;
    int rc;

    rc = ssh_pki_export_pubkey_blob(key, &blob);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(blob);

    return blob;
}

/* Append integers in network (big endian) byte order, as stored in a KRL */
static void tb_add_u8(ssh_buffer b, uint8_t v)
{
    int rc = ssh_buffer_pack(b, "b", v);
    assert_int_equal(rc, SSH_OK);
}

static void tb_add_u32(ssh_buffer b, uint32_t v)
{
    int rc = ssh_buffer_pack(b, "d", v);
    assert_int_equal(rc, SSH_OK);
}

static void tb_add_u64(ssh_buffer b, uint64_t v)
{
    int rc = ssh_buffer_pack(b, "q", v);
    assert_int_equal(rc, SSH_OK);
}

static void tb_add_ssh_string(ssh_buffer b, ssh_string s)
{
    int rc = ssh_buffer_pack(b, "S", s);
    assert_int_equal(rc, SSH_OK);
}

static void tb_add_data_string(ssh_buffer b, const void *data, size_t len)
{
    tb_add_u32(b, (uint32_t)len);
    if (len > 0) {
        int rc = ssh_buffer_add_data(b, data, len);
        assert_int_equal(rc, 0);
    }
}

/* Start a KRL buffer: magic, header, empty reserved and comment */
static ssh_buffer krl_start(uint64_t generated_date)
{
    ssh_buffer b = ssh_buffer_new();
    int rc;

    assert_non_null(b);
    rc = ssh_buffer_add_data(b, "SSHKRL\n", 8); /* 8th byte is '\0' */
    assert_int_equal(rc, 0);
    tb_add_u32(b, 0); /* format version */
    tb_add_u64(b, 1); /* krl version */
    tb_add_u64(b, generated_date);
    tb_add_u64(b, 0); /* flags */
    tb_add_u32(b, 0); /* reserved */
    tb_add_u32(b, 0); /* comment */

    return b;
}

static void krl_add_section(ssh_buffer krl, uint8_t type, ssh_buffer data)
{
    tb_add_u8(krl, type);
    tb_add_u32(krl, ssh_buffer_get_len(data));
    {
        int rc = ssh_buffer_add_buffer(krl, data);
        assert_int_equal(rc, 0);
    }
}

static void krl_add_key_section(ssh_buffer krl, ssh_string key_blob)
{
    ssh_buffer section = ssh_buffer_new();
    int rc;

    assert_non_null(section);
    tb_add_ssh_string(section, key_blob);
    krl_add_section(krl, SSH_KRL_SECTION_KEYS, section);
    SSH_BUFFER_FREE(section);
    (void)rc;
}

static void krl_add_hash_section(ssh_buffer krl,
                                 uint8_t type,
                                 const unsigned char *hash,
                                 size_t hash_len)
{
    ssh_buffer section = ssh_buffer_new();
    int rc;

    assert_non_null(section);
    rc = ssh_buffer_add_data(section, hash, hash_len);
    assert_int_equal(rc, 0);
    krl_add_section(krl, type, section);
    SSH_BUFFER_FREE(section);
}

/* Add a certificate subsection (serial list, range, bitmap or key id) */
static void krl_add_cert_subsection(ssh_buffer krl,
                                    uint8_t subtype,
                                    ssh_buffer subdata)
{
    ssh_buffer section = NULL;
    int rc;

    /* The certificates section holds a list of subsections. For the tests
     * we only ever put a single subsection per certificates section. */
    section = ssh_buffer_new();
    assert_non_null(section);
    tb_add_u8(section, subtype);
    tb_add_u32(section, ssh_buffer_get_len(subdata));
    rc = ssh_buffer_add_buffer(section, subdata);
    assert_int_equal(rc, 0);

    krl_add_section(krl, SSH_KRL_SECTION_CERTIFICATES, section);
    SSH_BUFFER_FREE(section);
}

static void krl_add_cert_serial_list(ssh_buffer krl,
                                     ssh_string ca_blob,
                                     const uint64_t *serials,
                                     size_t nserials)
{
    ssh_buffer sub = ssh_buffer_new();
    size_t i;
    int rc;

    assert_non_null(sub);
    tb_add_ssh_string(sub, ca_blob);
    for (i = 0; i < nserials; i++) {
        tb_add_u64(sub, serials[i]);
    }
    (void)rc;
    krl_add_cert_subsection(krl, SSH_KRL_SECTION_CERT_SERIAL_LIST, sub);
    SSH_BUFFER_FREE(sub);
}

static void krl_add_cert_serial_range(ssh_buffer krl,
                                      ssh_string ca_blob,
                                      uint64_t lo,
                                      uint64_t hi)
{
    ssh_buffer sub = ssh_buffer_new();
    int rc;

    assert_non_null(sub);
    tb_add_ssh_string(sub, ca_blob);
    tb_add_u64(sub, lo);
    tb_add_u64(sub, hi);
    (void)rc;
    krl_add_cert_subsection(krl, SSH_KRL_SECTION_CERT_SERIAL_RANGE, sub);
    SSH_BUFFER_FREE(sub);
}

static void krl_add_cert_serial_bitmap(ssh_buffer krl,
                                       ssh_string ca_blob,
                                       uint64_t offset,
                                       const unsigned char *bitmap,
                                       size_t bitmap_len)
{
    ssh_buffer sub = ssh_buffer_new();
    int rc;

    assert_non_null(sub);
    tb_add_ssh_string(sub, ca_blob);
    tb_add_u64(sub, offset);
    tb_add_data_string(sub, bitmap, bitmap_len);
    (void)rc;
    krl_add_cert_subsection(krl, SSH_KRL_SECTION_CERT_SERIAL_BITMAP, sub);
    SSH_BUFFER_FREE(sub);
}

static void krl_add_cert_key_id(ssh_buffer krl,
                                ssh_string ca_blob,
                                const char *key_id)
{
    ssh_buffer sub = ssh_buffer_new();
    ssh_string id = NULL;
    int rc;

    assert_non_null(sub);
    tb_add_ssh_string(sub, ca_blob);
    id = ssh_string_from_char(key_id);
    assert_non_null(id);
    tb_add_ssh_string(sub, id);
    SSH_STRING_FREE(id);
    (void)rc;
    krl_add_cert_subsection(krl, SSH_KRL_SECTION_CERT_KEY_ID, sub);
    SSH_BUFFER_FREE(sub);
}

/* Build a ssh-ed25519-cert-v01@openssh.com certificate blob */
static ssh_string cert_build_blob(ssh_string ca_blob,
                                  uint64_t serial,
                                  const char *key_id)
{
    ssh_buffer b = ssh_buffer_new();
    ssh_buffer sig = NULL;
    ssh_string s = NULL;
    unsigned char nonce[32] = {0};
    unsigned char pk[32] = {0};
    unsigned char sig_blob[64] = {0};
    ssh_string cert = NULL;
    int rc;

    assert_non_null(b);

    /* cert key type */
    s = ssh_string_from_char("ssh-ed25519-cert-v01@openssh.com");
    assert_non_null(s);
    tb_add_ssh_string(b, s);
    SSH_STRING_FREE(s);

    /* nonce */
    s = ssh_string_new(sizeof(nonce));
    assert_non_null(s);
    memcpy(ssh_string_data(s), nonce, sizeof(nonce));
    tb_add_ssh_string(b, s);
    SSH_STRING_FREE(s);

    /* ed25519 public key */
    s = ssh_string_new(sizeof(pk));
    assert_non_null(s);
    memcpy(ssh_string_data(s), pk, sizeof(pk));
    tb_add_ssh_string(b, s);
    SSH_STRING_FREE(s);

    /* serial, cert type (host = 2), key id */
    tb_add_u64(b, serial);
    tb_add_u32(b, 2);
    s = ssh_string_from_char(key_id);
    assert_non_null(s);
    tb_add_ssh_string(b, s);
    SSH_STRING_FREE(s);

    /* valid principals (empty), valid after, valid before */
    tb_add_u32(b, 0);
    tb_add_u64(b, 0);
    tb_add_u64(b, UINT64_MAX);

    /* critical options, extensions, reserved (all empty) */
    tb_add_u32(b, 0);
    tb_add_u32(b, 0);
    tb_add_u32(b, 0);

    /* signature (CA) key */
    tb_add_ssh_string(b, ca_blob);

    /* signature */
    sig = ssh_buffer_new();
    assert_non_null(sig);
    s = ssh_string_from_char("ssh-ed25519");
    assert_non_null(s);
    tb_add_ssh_string(sig, s);
    SSH_STRING_FREE(s);
    s = ssh_string_new(sizeof(sig_blob));
    assert_non_null(s);
    memcpy(ssh_string_data(s), sig_blob, sizeof(sig_blob));
    tb_add_ssh_string(sig, s);
    SSH_STRING_FREE(s);

    tb_add_u32(b, ssh_buffer_get_len(sig));
    rc = ssh_buffer_add_buffer(b, sig);
    assert_int_equal(rc, 0);
    SSH_BUFFER_FREE(sig);

    cert = ssh_string_new(ssh_buffer_get_len(b));
    assert_non_null(cert);
    memcpy(ssh_string_data(cert), ssh_buffer_get(b), ssh_buffer_get_len(b));
    SSH_BUFFER_FREE(b);

    return cert;
}

static ssh_key cert_import(ssh_string ca_blob, uint64_t serial,
                           const char *key_id)
{
    ssh_string cert_blob = NULL;
    ssh_key cert = NULL;
    int rc;

    cert_blob = cert_build_blob(ca_blob, serial, key_id);
    rc = ssh_pki_import_cert_blob(cert_blob, &cert);
    SSH_STRING_FREE(cert_blob);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(cert);

    return cert;
}

/* Write a KRL buffer into a new temporary file, return the file path */
static char *krl_write_temp_file(ssh_buffer krl)
{
    char *path = NULL;
    FILE *fp = NULL;
    size_t nwritten;

    path = torture_create_temp_file(KRL_TMP_FILE);
    assert_non_null(path);

    fp = fopen(path, "w");
    assert_non_null(fp);
    nwritten = fwrite(ssh_buffer_get(krl),
                      1,
                      ssh_buffer_get_len(krl),
                      fp);
    assert_int_equal(nwritten, ssh_buffer_get_len(krl));
    fclose(fp);

    return path;
}

static void torture_krl_key_revoked(void **state)
{
    ssh_krl krl = NULL;
    ssh_buffer krl_buf = NULL;
    ssh_key key = NULL;
    ssh_key other = NULL;
    ssh_string blob = NULL;
    int rc;

    (void)state;

    key = test_ed25519_key();
    other = test_rsa_key();
    blob = test_key_blob(key);

    krl_buf = krl_start((uint64_t)time(NULL));
    krl_add_key_section(krl_buf, blob);

    rc = ssh_krl_import_blob(NULL,
                             ssh_buffer_get(krl_buf),
                             ssh_buffer_get_len(krl_buf),
                             &krl);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(krl);

    rc = ssh_krl_key_is_revoked(krl, key);
    assert_int_equal(rc, 1);

    rc = ssh_krl_key_is_revoked(krl, other);
    assert_int_equal(rc, 0);

    ssh_krl_free(krl);
    SSH_BUFFER_FREE(krl_buf);
    SSH_STRING_FREE(blob);
    ssh_key_free(key);
    ssh_key_free(other);
}

static void torture_krl_hash_sha1_revoked(void **state)
{
    ssh_krl krl = NULL;
    ssh_buffer krl_buf = NULL;
    ssh_key key = NULL;
    ssh_string blob = NULL;
    unsigned char hash[SHA_DIGEST_LEN];
    int rc;

    (void)state;

    key = test_ed25519_key();
    blob = test_key_blob(key);

    rc = sha1(ssh_string_data(blob), ssh_string_len(blob), hash);
    assert_int_equal(rc, SSH_OK);

    krl_buf = krl_start((uint64_t)time(NULL));
    krl_add_hash_section(krl_buf,
                         SSH_KRL_SECTION_FINGERPRINT_SHA1,
                         hash,
                         sizeof(hash));

    rc = ssh_krl_import_blob(NULL,
                             ssh_buffer_get(krl_buf),
                             ssh_buffer_get_len(krl_buf),
                             &krl);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_krl_key_is_revoked(krl, key);
    assert_int_equal(rc, 1);

    ssh_krl_free(krl);
    SSH_BUFFER_FREE(krl_buf);
    SSH_STRING_FREE(blob);
    ssh_key_free(key);
}

static void torture_krl_hash_sha256_revoked(void **state)
{
    ssh_krl krl = NULL;
    ssh_buffer krl_buf = NULL;
    ssh_key key = NULL;
    ssh_key other = NULL;
    ssh_string blob = NULL;
    unsigned char hash[SHA256_DIGEST_LEN];
    int rc;

    (void)state;

    key = test_ed25519_key();
    other = test_rsa_key();
    blob = test_key_blob(key);

    rc = sha256(ssh_string_data(blob), ssh_string_len(blob), hash);
    assert_int_equal(rc, SSH_OK);

    krl_buf = krl_start((uint64_t)time(NULL));
    krl_add_hash_section(krl_buf,
                         SSH_KRL_SECTION_FINGERPRINT_SHA256,
                         hash,
                         sizeof(hash));

    rc = ssh_krl_import_blob(NULL,
                             ssh_buffer_get(krl_buf),
                             ssh_buffer_get_len(krl_buf),
                             &krl);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_krl_key_is_revoked(krl, key);
    assert_int_equal(rc, 1);

    rc = ssh_krl_key_is_revoked(krl, other);
    assert_int_equal(rc, 0);

    ssh_krl_free(krl);
    SSH_BUFFER_FREE(krl_buf);
    SSH_STRING_FREE(blob);
    ssh_key_free(key);
    ssh_key_free(other);
}

static void torture_krl_cert_serial_list(void **state)
{
    ssh_krl krl = NULL;
    ssh_buffer krl_buf = NULL;
    ssh_key ca = NULL;
    ssh_key other_ca = NULL;
    ssh_string ca_blob = NULL;
    ssh_string other_ca_blob = NULL;
    ssh_key cert_revoked = NULL;
    ssh_key cert_ok = NULL;
    ssh_key cert_other_ca = NULL;
    uint64_t serials[] = {42, 42, 7}; /* duplicated serial on purpose */
    int rc;

    (void)state;

    ca = test_ed25519_key();
    other_ca = test_rsa_key();
    ca_blob = test_key_blob(ca);
    other_ca_blob = test_key_blob(other_ca);

    cert_revoked = cert_import(ca_blob, 42, "some-cert");
    cert_ok = cert_import(ca_blob, 43, "some-cert");
    cert_other_ca = cert_import(other_ca_blob, 42, "some-cert");

    krl_buf = krl_start((uint64_t)time(NULL));
    krl_add_cert_serial_list(krl_buf, ca_blob, serials, 3);

    rc = ssh_krl_import_blob(NULL,
                             ssh_buffer_get(krl_buf),
                             ssh_buffer_get_len(krl_buf),
                             &krl);
    assert_int_equal(rc, SSH_OK);

    /* serial 42 is revoked for our CA */
    rc = ssh_krl_key_is_revoked(krl, cert_revoked);
    assert_int_equal(rc, 1);

    /* serial 43 is not in the list */
    rc = ssh_krl_key_is_revoked(krl, cert_ok);
    assert_int_equal(rc, 0);

    /* serial 42 signed by another CA is not revoked */
    rc = ssh_krl_key_is_revoked(krl, cert_other_ca);
    assert_int_equal(rc, 0);

    ssh_krl_free(krl);
    SSH_BUFFER_FREE(krl_buf);
    SSH_STRING_FREE(ca_blob);
    SSH_STRING_FREE(other_ca_blob);
    ssh_key_free(cert_revoked);
    ssh_key_free(cert_ok);
    ssh_key_free(cert_other_ca);
    ssh_key_free(ca);
    ssh_key_free(other_ca);
}

static void torture_krl_cert_serial_range(void **state)
{
    ssh_krl krl = NULL;
    ssh_buffer krl_buf = NULL;
    ssh_key ca = NULL;
    ssh_string ca_blob = NULL;
    ssh_key cert_in = NULL;
    ssh_key cert_out = NULL;
    int rc;

    (void)state;

    ca = test_ed25519_key();
    ca_blob = test_key_blob(ca);

    cert_in = cert_import(ca_blob, 15, "cert");
    cert_out = cert_import(ca_blob, 21, "cert");

    krl_buf = krl_start((uint64_t)time(NULL));
    krl_add_cert_serial_range(krl_buf, ca_blob, 10, 20);

    rc = ssh_krl_import_blob(NULL,
                             ssh_buffer_get(krl_buf),
                             ssh_buffer_get_len(krl_buf),
                             &krl);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_krl_key_is_revoked(krl, cert_in);
    assert_int_equal(rc, 1);

    rc = ssh_krl_key_is_revoked(krl, cert_out);
    assert_int_equal(rc, 0);

    ssh_krl_free(krl);
    SSH_BUFFER_FREE(krl_buf);
    SSH_STRING_FREE(ca_blob);
    ssh_key_free(cert_in);
    ssh_key_free(cert_out);
    ssh_key_free(ca);
}

static void torture_krl_cert_serial_bitmap(void **state)
{
    ssh_krl krl = NULL;
    ssh_buffer krl_buf = NULL;
    ssh_key ca = NULL;
    ssh_string ca_blob = NULL;
    ssh_key cert_100 = NULL;
    ssh_key cert_101 = NULL;
    ssh_key cert_102 = NULL;
    /* bits 0 and 2 set: serials offset+0 and offset+2 revoked */
    unsigned char bitmap[] = {0x05};
    int rc;

    (void)state;

    ca = test_ed25519_key();
    ca_blob = test_key_blob(ca);

    cert_100 = cert_import(ca_blob, 100, "cert");
    cert_101 = cert_import(ca_blob, 101, "cert");
    cert_102 = cert_import(ca_blob, 102, "cert");

    krl_buf = krl_start((uint64_t)time(NULL));
    krl_add_cert_serial_bitmap(krl_buf, ca_blob, 100, bitmap, sizeof(bitmap));

    rc = ssh_krl_import_blob(NULL,
                             ssh_buffer_get(krl_buf),
                             ssh_buffer_get_len(krl_buf),
                             &krl);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_krl_key_is_revoked(krl, cert_100);
    assert_int_equal(rc, 1);

    rc = ssh_krl_key_is_revoked(krl, cert_101);
    assert_int_equal(rc, 0);

    rc = ssh_krl_key_is_revoked(krl, cert_102);
    assert_int_equal(rc, 1);

    ssh_krl_free(krl);
    SSH_BUFFER_FREE(krl_buf);
    SSH_STRING_FREE(ca_blob);
    ssh_key_free(cert_100);
    ssh_key_free(cert_101);
    ssh_key_free(cert_102);
    ssh_key_free(ca);
}

static void torture_krl_cert_key_id(void **state)
{
    ssh_krl krl = NULL;
    ssh_buffer krl_buf = NULL;
    ssh_key ca = NULL;
    ssh_string ca_blob = NULL;
    ssh_key cert_bad = NULL;
    ssh_key cert_good = NULL;
    int rc;

    (void)state;

    ca = test_ed25519_key();
    ca_blob = test_key_blob(ca);

    cert_bad = cert_import(ca_blob, 1, "compromised-cert");
    cert_good = cert_import(ca_blob, 1, "honest-cert");

    krl_buf = krl_start((uint64_t)time(NULL));
    krl_add_cert_key_id(krl_buf, ca_blob, "compromised-cert");

    rc = ssh_krl_import_blob(NULL,
                             ssh_buffer_get(krl_buf),
                             ssh_buffer_get_len(krl_buf),
                             &krl);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_krl_key_is_revoked(krl, cert_bad);
    assert_int_equal(rc, 1);

    rc = ssh_krl_key_is_revoked(krl, cert_good);
    assert_int_equal(rc, 0);

    ssh_krl_free(krl);
    SSH_BUFFER_FREE(krl_buf);
    SSH_STRING_FREE(ca_blob);
    ssh_key_free(cert_bad);
    ssh_key_free(cert_good);
    ssh_key_free(ca);
}

static void torture_krl_bad_magic(void **state)
{
    ssh_krl krl = NULL;
    unsigned char data[64] = {0};
    int rc;

    (void)state;

    memcpy(data, "NOTAKRL!", 8);
    rc = ssh_krl_import_blob(NULL, data, sizeof(data), &krl);
    assert_int_equal(rc, SSH_ERROR);
    assert_null(krl);
}

static void torture_krl_bad_version(void **state)
{
    ssh_krl krl = NULL;
    ssh_buffer krl_buf = NULL;
    int rc;

    (void)state;

    krl_buf = ssh_buffer_new();
    assert_non_null(krl_buf);
    rc = ssh_buffer_add_data(krl_buf, "SSHKRL\n", 8);
    assert_int_equal(rc, 0);
    tb_add_u32(krl_buf, 77); /* unsupported format version */

    rc = ssh_krl_import_blob(NULL,
                             ssh_buffer_get(krl_buf),
                             ssh_buffer_get_len(krl_buf),
                             &krl);
    assert_int_equal(rc, SSH_ERROR);
    assert_null(krl);

    SSH_BUFFER_FREE(krl_buf);
}

static void torture_krl_truncated(void **state)
{
    ssh_krl krl = NULL;
    ssh_buffer krl_buf = NULL;
    ssh_key key = NULL;
    ssh_string blob = NULL;
    size_t full_len;
    int rc;

    (void)state;

    key = test_ed25519_key();
    blob = test_key_blob(key);

    krl_buf = krl_start((uint64_t)time(NULL));
    krl_add_key_section(krl_buf, blob);
    full_len = ssh_buffer_get_len(krl_buf);

    /* Cut the KRL in the middle of the keys section */
    rc = ssh_krl_import_blob(NULL,
                             ssh_buffer_get(krl_buf),
                             full_len - 5,
                             &krl);
    assert_int_equal(rc, SSH_ERROR);
    assert_null(krl);

    SSH_BUFFER_FREE(krl_buf);
    SSH_STRING_FREE(blob);
    ssh_key_free(key);
}

static void torture_krl_unknown_section(void **state)
{
    ssh_krl krl = NULL;
    ssh_buffer krl_buf = NULL;
    ssh_buffer section = NULL;
    int rc;

    (void)state;

    krl_buf = krl_start((uint64_t)time(NULL));
    section = ssh_buffer_new();
    assert_non_null(section);
    krl_add_section(krl_buf, 0x7f, section); /* unknown section type */
    SSH_BUFFER_FREE(section);

    /* Unknown sections must not be silently skipped */
    rc = ssh_krl_import_blob(NULL,
                             ssh_buffer_get(krl_buf),
                             ssh_buffer_get_len(krl_buf),
                             &krl);
    assert_int_equal(rc, SSH_ERROR);
    assert_null(krl);

    SSH_BUFFER_FREE(krl_buf);
}

static void torture_krl_bad_file(void **state)
{
    ssh_session session = NULL;
    ssh_krl krl = NULL;
    int rc;

    (void)state;

    session = ssh_new();
    assert_non_null(session);

    rc = ssh_krl_import_file(session, "/tmp/torture_krl_no_such_file", &krl);
    assert_int_equal(rc, SSH_ERROR);
    assert_null(krl);

    rc = ssh_session_krl_add_file(session, "/tmp/torture_krl_no_such_file");
    assert_int_equal(rc, SSH_ERROR);

    ssh_free(session);
}

static void torture_krl_multiple_krls(void **state)
{
    ssh_session session = NULL;
    ssh_buffer krl1_buf = NULL;
    ssh_buffer krl2_buf = NULL;
    char *path1 = NULL;
    char *path2 = NULL;
    ssh_key key1 = NULL;
    ssh_key key2 = NULL;
    ssh_string blob1 = NULL;
    ssh_string blob2 = NULL;
    int rc;

    (void)state;

    key1 = test_ed25519_key();
    key2 = test_rsa_key();
    blob1 = test_key_blob(key1);
    blob2 = test_key_blob(key2);

    krl1_buf = krl_start((uint64_t)time(NULL));
    krl_add_key_section(krl1_buf, blob1);
    path1 = krl_write_temp_file(krl1_buf);

    krl2_buf = krl_start((uint64_t)time(NULL));
    krl_add_key_section(krl2_buf, blob2);
    path2 = krl_write_temp_file(krl2_buf);

    session = ssh_new();
    assert_non_null(session);

    rc = ssh_session_krl_add_file(session, path1);
    assert_int_equal(rc, SSH_OK);
    rc = ssh_session_krl_add_file(session, path2);
    assert_int_equal(rc, SSH_OK);

    /* Keys revoked by any of the configured KRLs are reported revoked */
    rc = ssh_session_key_is_revoked(session, key1);
    assert_int_equal(rc, 1);
    rc = ssh_session_key_is_revoked(session, key2);
    assert_int_equal(rc, 1);

    ssh_free(session);

    /* A session without KRLs revokes nothing */
    session = ssh_new();
    assert_non_null(session);
    rc = ssh_session_key_is_revoked(session, key1);
    assert_int_equal(rc, 0);
    ssh_free(session);

    unlink(path1);
    unlink(path2);
    SAFE_FREE(path1);
    SAFE_FREE(path2);
    SSH_BUFFER_FREE(krl1_buf);
    SSH_BUFFER_FREE(krl2_buf);
    SSH_STRING_FREE(blob1);
    SSH_STRING_FREE(blob2);
    ssh_key_free(key1);
    ssh_key_free(key2);
}

static void torture_krl_update(void **state)
{
    ssh_session session = NULL;
    ssh_buffer krl_buf = NULL;
    char *path = NULL;
    ssh_key key = NULL;
    ssh_string blob = NULL;
    int rc;

    (void)state;

    key = test_ed25519_key();
    blob = test_key_blob(key);

    /* First KRL revokes the key */
    krl_buf = krl_start((uint64_t)time(NULL));
    krl_add_key_section(krl_buf, blob);
    path = krl_write_temp_file(krl_buf);
    SSH_BUFFER_FREE(krl_buf);

    session = ssh_new();
    assert_non_null(session);

    rc = ssh_session_krl_add_file(session, path);
    assert_int_equal(rc, SSH_OK);
    rc = ssh_session_key_is_revoked(session, key);
    assert_int_equal(rc, 1);

    /* Update: the same path now provides a KRL that revokes nothing */
    krl_buf = krl_start((uint64_t)time(NULL));
    {
        FILE *fp = fopen(path, "w");
        size_t nwritten;
        assert_non_null(fp);
        nwritten = fwrite(ssh_buffer_get(krl_buf),
                          1,
                          ssh_buffer_get_len(krl_buf),
                          fp);
        assert_int_equal(nwritten, ssh_buffer_get_len(krl_buf));
        fclose(fp);
    }
    SSH_BUFFER_FREE(krl_buf);

    rc = ssh_session_krl_add_file(session, path);
    assert_int_equal(rc, SSH_OK);
    rc = ssh_session_key_is_revoked(session, key);
    assert_int_equal(rc, 0);

    ssh_free(session);
    unlink(path);
    SAFE_FREE(path);
    SSH_STRING_FREE(blob);
    ssh_key_free(key);
}

static void torture_krl_expired(void **state)
{
    ssh_session session = NULL;
    ssh_buffer krl_buf = NULL;
    char *path = NULL;
    ssh_key key = NULL;
    ssh_string blob = NULL;
    int rc;

    (void)state;

    key = test_ed25519_key();
    blob = test_key_blob(key);

    /* KRL generated in 1970 revokes the key */
    krl_buf = krl_start(1);
    krl_add_key_section(krl_buf, blob);
    path = krl_write_temp_file(krl_buf);
    SSH_BUFFER_FREE(krl_buf);

    session = ssh_new();
    assert_non_null(session);

    rc = ssh_session_krl_add_file(session, path);
    assert_int_equal(rc, SSH_OK);

    /* Without an expiration policy the KRL applies */
    rc = ssh_session_key_is_revoked(session, key);
    assert_int_equal(rc, 1);

    /* With a max age the stale KRL fails closed instead of being skipped */
    ssh_session_set_krl_max_age(session, 3600);
    rc = ssh_session_key_is_revoked(session, key);
    assert_int_equal(rc, SSH_ERROR);

    ssh_free(session);
    unlink(path);
    SAFE_FREE(path);
    SSH_STRING_FREE(blob);
    ssh_key_free(key);
}

static void torture_krl_known_hosts_revoked(void **state)
{
    ssh_session session = NULL;
    ssh_buffer krl_buf = NULL;
    char *krl_path = NULL;
    char *kh_path = NULL;
    ssh_key key = NULL;
    ssh_string blob = NULL;
    enum ssh_known_hosts_e krc;
    FILE *fp = NULL;
    int rc;

    (void)state;

    key = test_ed25519_key();
    blob = test_key_blob(key);

    /* known_hosts file trusting the key */
    kh_path = torture_create_temp_file(KRL_TMP_FILE);
    assert_non_null(kh_path);
    fp = fopen(kh_path, "w");
    assert_non_null(fp);
    fprintf(fp, "localhost ssh-ed25519 %s\n", ED25519_B64);
    fclose(fp);

    /* KRL revoking the key */
    krl_buf = krl_start((uint64_t)time(NULL));
    krl_add_key_section(krl_buf, blob);
    krl_path = krl_write_temp_file(krl_buf);
    SSH_BUFFER_FREE(krl_buf);

    session = ssh_new();
    assert_non_null(session);
    rc = ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    assert_int_equal(rc, SSH_OK);
    rc = ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, kh_path);
    assert_int_equal(rc, SSH_OK);

    session->current_crypto = crypto_new();
    assert_non_null(session->current_crypto);
    session->current_crypto->server_pubkey = ssh_key_dup(key);
    assert_non_null(session->current_crypto->server_pubkey);

    /* Without a KRL the host is known and trusted */
    krc = ssh_session_get_known_hosts_entry(session, NULL);
    assert_int_equal(krc, SSH_KNOWN_HOSTS_OK);

    /* With a KRL revoking the key, the host is reported revoked even
     * though the known_hosts file trusts it */
    rc = ssh_session_krl_add_file(session, krl_path);
    assert_int_equal(rc, SSH_OK);
    krc = ssh_session_get_known_hosts_entry(session, NULL);
    assert_int_equal(krc, SSH_KNOWN_HOSTS_REVOKED);

    ssh_free(session);
    unlink(krl_path);
    unlink(kh_path);
    SAFE_FREE(krl_path);
    SAFE_FREE(kh_path);
    SSH_STRING_FREE(blob);
    ssh_key_free(key);
}

int torture_run_tests(void)
{
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_krl_key_revoked),
        cmocka_unit_test(torture_krl_hash_sha1_revoked),
        cmocka_unit_test(torture_krl_hash_sha256_revoked),
        cmocka_unit_test(torture_krl_cert_serial_list),
        cmocka_unit_test(torture_krl_cert_serial_range),
        cmocka_unit_test(torture_krl_cert_serial_bitmap),
        cmocka_unit_test(torture_krl_cert_key_id),
        cmocka_unit_test(torture_krl_bad_magic),
        cmocka_unit_test(torture_krl_bad_version),
        cmocka_unit_test(torture_krl_truncated),
        cmocka_unit_test(torture_krl_unknown_section),
        cmocka_unit_test(torture_krl_bad_file),
        cmocka_unit_test(torture_krl_multiple_krls),
        cmocka_unit_test(torture_krl_update),
        cmocka_unit_test(torture_krl_expired),
        cmocka_unit_test(torture_krl_known_hosts_revoked),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();

    return rc;
}
