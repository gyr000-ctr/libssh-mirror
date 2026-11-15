/*
 * krl.h - OpenSSH Key Revocation List (KRL) support
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

#ifndef KRL_H_
#define KRL_H_

#include "config.h"

#include <stdint.h>

#include "libssh/libssh.h"
#include "libssh/priv.h"
#include "libssh/pki.h"
#include "libssh/misc.h"
#include "libssh/string.h"

/* Limits to keep the parsed representation of a KRL bounded. The file itself
 * is additionally capped by SSH_KRL_MAX_FILE_SIZE. */
#define SSH_KRL_MAX_FILE_SIZE SSH_MAX_CONFIG_FILE_SIZE
#define SSH_KRL_MAX_SECTIONS 4096
#define SSH_KRL_MAX_CERT_SUBSECTIONS 4096
#define SSH_KRL_MAX_SERIALS (1U << 20)
#define SSH_KRL_MAX_RANGES (1U << 16)
#define SSH_KRL_MAX_BITMAPS (1U << 16)
#define SSH_KRL_MAX_BITMAP_LEN (1U << 20)
#define SSH_KRL_MAX_KEY_IDS (1U << 16)
#define SSH_KRL_MAX_KEY_ID_LEN 1024
#define SSH_KRL_MAX_KEYS (1U << 16)
#define SSH_KRL_MAX_KEY_BLOB_LEN MAX_PUBKEY_SIZE
#define SSH_KRL_MAX_HASHES (1U << 20)

/* KRL on-disk format constants (see PROTOCOL.krl in OpenSSH) */
#define SSH_KRL_MAGIC "SSHKRL\n"
#define SSH_KRL_MAGIC_LEN 8 /* magic including the terminating NUL byte */
#define SSH_KRL_FORMAT_VERSION 0

#define SSH_KRL_SECTION_CERTIFICATES 1
#define SSH_KRL_SECTION_KEYS 2
#define SSH_KRL_SECTION_FINGERPRINT_SHA1 3
#define SSH_KRL_SECTION_FINGERPRINT_SHA256 4
#define SSH_KRL_SECTION_SIGNATURE 5
#define SSH_KRL_SECTION_EXTENSION 255

#define SSH_KRL_SECTION_CERT_SERIAL_LIST 0x20
#define SSH_KRL_SECTION_CERT_SERIAL_RANGE 0x21
#define SSH_KRL_SECTION_CERT_SERIAL_BITMAP 0x22
#define SSH_KRL_SECTION_CERT_KEY_ID 0x23

struct ssh_krl_serial_range_st {
    uint64_t lo;
    uint64_t hi;
};

struct ssh_krl_serial_bitmap_st {
    uint64_t offset;
    unsigned char *bitmap;
    size_t len;
};

struct ssh_krl_ca_section_st {
    ssh_string ca_key; /* CA public key blob */
    struct ssh_list *serials;  /* uint64_t pointers */
    struct ssh_list *ranges;   /* struct ssh_krl_serial_range_st pointers */
    struct ssh_list *bitmaps;  /* struct ssh_krl_serial_bitmap_st pointers */
    struct ssh_list *key_ids;  /* ssh_string */
};

struct ssh_krl_struct {
    uint64_t krl_version;
    uint64_t generated_date;
    struct ssh_list *keys;        /* ssh_string revoked key blobs */
    struct ssh_list *ca_sections; /* struct ssh_krl_ca_section_st pointers */
    unsigned char *sha1_hashes;   /* n_sha1 * SHA_DIGEST_LEN bytes */
    size_t n_sha1;
    unsigned char *sha256_hashes; /* n_sha256 * SHA256_DIGEST_LEN bytes */
    size_t n_sha256;
};

/* Entry of the per-session list of KRLs */
struct ssh_krl_entry_st {
    char *path; /* NULL for anonymously added KRLs */
    ssh_krl krl;
};

void ssh_krl_entry_free(struct ssh_krl_entry_st *entry);

#endif /* KRL_H_ */
