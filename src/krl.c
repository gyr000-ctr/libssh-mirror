/*
 * krl.c - OpenSSH Key Revocation List (KRL) support
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libssh/krl.h"
#include "libssh/buffer.h"
#include "libssh/crypto.h"
#include "libssh/dh.h"
#include "libssh/misc.h"
#include "libssh/options.h"
#include "libssh/pki.h"
#include "libssh/priv.h"
#include "libssh/session.h"
#include "libssh/string.h"
#include "libssh/wrapper.h"

/**
 * @addtogroup libssh_session
 *
 * @{
 */

/*
 * Bounded cursor over a byte buffer used to parse the KRL. All multi-byte
 * integers are big endian as per PROTOCOL.krl.
 */
struct krl_reader {
    const unsigned char *data;
    size_t len;
    size_t off;
};

static size_t krl_reader_remaining(const struct krl_reader *r)
{
    return r->len - r->off;
}

static int krl_read_bytes(struct krl_reader *r,
                          const unsigned char **ptr,
                          size_t len)
{
    if (krl_reader_remaining(r) < len) {
        return SSH_ERROR;
    }
    *ptr = r->data + r->off;
    r->off += len;
    return SSH_OK;
}

static int krl_read_u8(struct krl_reader *r, uint8_t *v)
{
    const unsigned char *p = NULL;

    if (krl_read_bytes(r, &p, 1) != SSH_OK) {
        return SSH_ERROR;
    }
    *v = p[0];
    return SSH_OK;
}

static int krl_read_u32(struct krl_reader *r, uint32_t *v)
{
    const unsigned char *p = NULL;

    if (krl_read_bytes(r, &p, 4) != SSH_OK) {
        return SSH_ERROR;
    }
    *v = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    return SSH_OK;
}

static int krl_read_u64(struct krl_reader *r, uint64_t *v)
{
    uint32_t hi, lo;

    if (krl_read_u32(r, &hi) != SSH_OK || krl_read_u32(r, &lo) != SSH_OK) {
        return SSH_ERROR;
    }
    *v = ((uint64_t)hi << 32) | lo;
    return SSH_OK;
}

/* Read an SSH string. The returned pointer aliases the reader buffer and
 * must be copied if it has to outlive it. */
static int krl_read_string(struct krl_reader *r,
                           const unsigned char **ptr,
                           size_t *len)
{
    uint32_t slen;

    if (krl_read_u32(r, &slen) != SSH_OK) {
        return SSH_ERROR;
    }
    if (krl_read_bytes(r, ptr, slen) != SSH_OK) {
        return SSH_ERROR;
    }
    *len = slen;
    return SSH_OK;
}

static int krl_skip_string(struct krl_reader *r)
{
    const unsigned char *ptr = NULL;
    size_t len = 0;

    return krl_read_string(r, &ptr, &len);
}

static void ssh_krl_ca_section_free(struct ssh_krl_ca_section_st *ca)
{
    struct ssh_iterator *it = NULL;

    if (ca == NULL) {
        return;
    }

    SSH_STRING_FREE(ca->ca_key);

    if (ca->serials != NULL) {
        for (it = ssh_list_get_iterator(ca->serials);
             it != NULL;
             it = ssh_list_get_iterator(ca->serials)) {
            uint64_t *serial = ssh_iterator_value(uint64_t *, it);
            SAFE_FREE(serial);
            ssh_list_remove(ca->serials, it);
        }
        ssh_list_free(ca->serials);
    }

    if (ca->ranges != NULL) {
        for (it = ssh_list_get_iterator(ca->ranges);
             it != NULL;
             it = ssh_list_get_iterator(ca->ranges)) {
            struct ssh_krl_serial_range_st *range =
                ssh_iterator_value(struct ssh_krl_serial_range_st *, it);
            SAFE_FREE(range);
            ssh_list_remove(ca->ranges, it);
        }
        ssh_list_free(ca->ranges);
    }

    if (ca->bitmaps != NULL) {
        for (it = ssh_list_get_iterator(ca->bitmaps);
             it != NULL;
             it = ssh_list_get_iterator(ca->bitmaps)) {
            struct ssh_krl_serial_bitmap_st *bitmap =
                ssh_iterator_value(struct ssh_krl_serial_bitmap_st *, it);
            if (bitmap != NULL) {
                SAFE_FREE(bitmap->bitmap);
                SAFE_FREE(bitmap);
            }
            ssh_list_remove(ca->bitmaps, it);
        }
        ssh_list_free(ca->bitmaps);
    }

    if (ca->key_ids != NULL) {
        for (it = ssh_list_get_iterator(ca->key_ids);
             it != NULL;
             it = ssh_list_get_iterator(ca->key_ids)) {
            ssh_string key_id = ssh_iterator_value(ssh_string, it);
            SSH_STRING_FREE(key_id);
            ssh_list_remove(ca->key_ids, it);
        }
        ssh_list_free(ca->key_ids);
    }

    SAFE_FREE(ca);
}

/**
 * @brief Free a KRL structure.
 *
 * @param[in]  krl      The KRL to free.
 */
void ssh_krl_free(ssh_krl krl)
{
    struct ssh_iterator *it = NULL;

    if (krl == NULL) {
        return;
    }

    if (krl->keys != NULL) {
        for (it = ssh_list_get_iterator(krl->keys);
             it != NULL;
             it = ssh_list_get_iterator(krl->keys)) {
            ssh_string key = ssh_iterator_value(ssh_string, it);
            SSH_STRING_FREE(key);
            ssh_list_remove(krl->keys, it);
        }
        ssh_list_free(krl->keys);
    }

    if (krl->ca_sections != NULL) {
        for (it = ssh_list_get_iterator(krl->ca_sections);
             it != NULL;
             it = ssh_list_get_iterator(krl->ca_sections)) {
            struct ssh_krl_ca_section_st *ca =
                ssh_iterator_value(struct ssh_krl_ca_section_st *, it);
            ssh_krl_ca_section_free(ca);
            ssh_list_remove(krl->ca_sections, it);
        }
        ssh_list_free(krl->ca_sections);
    }

    SAFE_FREE(krl->sha1_hashes);
    SAFE_FREE(krl->sha256_hashes);
    SAFE_FREE(krl);
}

/**
 * @internal
 *
 * @brief Free an entry of the per-session KRL list.
 */
void ssh_krl_entry_free(struct ssh_krl_entry_st *entry)
{
    if (entry == NULL) {
        return;
    }
    SAFE_FREE(entry->path);
    ssh_krl_free(entry->krl);
    SAFE_FREE(entry);
}

static ssh_krl ssh_krl_new(void)
{
    ssh_krl krl = NULL;

    krl = calloc(1, sizeof(struct ssh_krl_struct));
    if (krl == NULL) {
        return NULL;
    }

    krl->keys = ssh_list_new();
    krl->ca_sections = ssh_list_new();
    if (krl->keys == NULL || krl->ca_sections == NULL) {
        ssh_krl_free(krl);
        return NULL;
    }

    return krl;
}

/* Find or create the CA section matching the given CA key blob */
static struct ssh_krl_ca_section_st *
krl_get_ca_section(ssh_krl krl, const unsigned char *ca_key, size_t ca_key_len)
{
    struct ssh_krl_ca_section_st *ca = NULL;
    struct ssh_iterator *it = NULL;

    for (it = ssh_list_get_iterator(krl->ca_sections);
         it != NULL;
         it = it->next) {
        ca = ssh_iterator_value(struct ssh_krl_ca_section_st *, it);
        if (ca->ca_key != NULL &&
            ssh_string_len(ca->ca_key) == ca_key_len &&
            memcmp(ssh_string_data(ca->ca_key), ca_key, ca_key_len) == 0) {
            return ca;
        }
    }

    ca = calloc(1, sizeof(struct ssh_krl_ca_section_st));
    if (ca == NULL) {
        return NULL;
    }
    ca->ca_key = ssh_string_new(ca_key_len);
    if (ca->ca_key == NULL) {
        SAFE_FREE(ca);
        return NULL;
    }
    memcpy(ssh_string_data(ca->ca_key), ca_key, ca_key_len);

    if (ssh_list_append(krl->ca_sections, ca) != SSH_OK) {
        SSH_STRING_FREE(ca->ca_key);
        SAFE_FREE(ca);
        return NULL;
    }

    return ca;
}

static int krl_parse_cert_serial_list(ssh_krl krl,
                                      struct krl_reader *r,
                                      size_t *total_serials)
{
    const unsigned char *ca_key = NULL;
    size_t ca_key_len = 0;
    struct ssh_krl_ca_section_st *ca = NULL;

    if (krl_read_string(r, &ca_key, &ca_key_len) != SSH_OK) {
        return SSH_ERROR;
    }
    if (ca_key_len == 0 || ca_key_len > SSH_KRL_MAX_KEY_BLOB_LEN) {
        return SSH_ERROR;
    }
    if (krl_reader_remaining(r) % 8 != 0) {
        return SSH_ERROR;
    }

    ca = krl_get_ca_section(krl, ca_key, ca_key_len);
    if (ca == NULL) {
        return SSH_ERROR;
    }
    if (ca->serials == NULL) {
        ca->serials = ssh_list_new();
        if (ca->serials == NULL) {
            return SSH_ERROR;
        }
    }

    while (krl_reader_remaining(r) > 0) {
        uint64_t serial;
        uint64_t *copy = NULL;

        if (krl_read_u64(r, &serial) != SSH_OK) {
            return SSH_ERROR;
        }
        /* Duplicated serials are harmless: keep the parse bounded but do
         * not reject the KRL */
        if (*total_serials >= SSH_KRL_MAX_SERIALS) {
            return SSH_ERROR;
        }
        (*total_serials)++;

        copy = malloc(sizeof(uint64_t));
        if (copy == NULL) {
            return SSH_ERROR;
        }
        *copy = serial;
        if (ssh_list_append(ca->serials, copy) != SSH_OK) {
            SAFE_FREE(copy);
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}

static int krl_parse_cert_serial_range(ssh_krl krl,
                                       struct krl_reader *r,
                                       size_t *total_ranges)
{
    const unsigned char *ca_key = NULL;
    size_t ca_key_len = 0;
    struct ssh_krl_ca_section_st *ca = NULL;
    struct ssh_krl_serial_range_st *range = NULL;

    if (krl_read_string(r, &ca_key, &ca_key_len) != SSH_OK) {
        return SSH_ERROR;
    }
    if (ca_key_len == 0 || ca_key_len > SSH_KRL_MAX_KEY_BLOB_LEN) {
        return SSH_ERROR;
    }

    ca = krl_get_ca_section(krl, ca_key, ca_key_len);
    if (ca == NULL) {
        return SSH_ERROR;
    }
    if (ca->ranges == NULL) {
        ca->ranges = ssh_list_new();
        if (ca->ranges == NULL) {
            return SSH_ERROR;
        }
    }

    if (*total_ranges >= SSH_KRL_MAX_RANGES) {
        return SSH_ERROR;
    }
    (*total_ranges)++;

    range = calloc(1, sizeof(struct ssh_krl_serial_range_st));
    if (range == NULL) {
        return SSH_ERROR;
    }
    if (krl_read_u64(r, &range->lo) != SSH_OK ||
        krl_read_u64(r, &range->hi) != SSH_OK) {
        SAFE_FREE(range);
        return SSH_ERROR;
    }
    if (range->lo > range->hi) {
        /* Invalid range: fail safe */
        SAFE_FREE(range);
        return SSH_ERROR;
    }
    if (krl_reader_remaining(r) != 0) {
        SAFE_FREE(range);
        return SSH_ERROR;
    }

    if (ssh_list_append(ca->ranges, range) != SSH_OK) {
        SAFE_FREE(range);
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int krl_parse_cert_serial_bitmap(ssh_krl krl,
                                        struct krl_reader *r,
                                        size_t *total_bitmaps)
{
    const unsigned char *ca_key = NULL;
    const unsigned char *bitmap_data = NULL;
    size_t ca_key_len = 0;
    size_t bitmap_len = 0;
    struct ssh_krl_ca_section_st *ca = NULL;
    struct ssh_krl_serial_bitmap_st *bitmap = NULL;

    if (krl_read_string(r, &ca_key, &ca_key_len) != SSH_OK) {
        return SSH_ERROR;
    }
    if (ca_key_len == 0 || ca_key_len > SSH_KRL_MAX_KEY_BLOB_LEN) {
        return SSH_ERROR;
    }

    ca = krl_get_ca_section(krl, ca_key, ca_key_len);
    if (ca == NULL) {
        return SSH_ERROR;
    }
    if (ca->bitmaps == NULL) {
        ca->bitmaps = ssh_list_new();
        if (ca->bitmaps == NULL) {
            return SSH_ERROR;
        }
    }

    if (*total_bitmaps >= SSH_KRL_MAX_BITMAPS) {
        return SSH_ERROR;
    }
    (*total_bitmaps)++;

    bitmap = calloc(1, sizeof(struct ssh_krl_serial_bitmap_st));
    if (bitmap == NULL) {
        return SSH_ERROR;
    }
    if (krl_read_u64(r, &bitmap->offset) != SSH_OK ||
        krl_read_string(r, &bitmap_data, &bitmap_len) != SSH_OK) {
        SAFE_FREE(bitmap);
        return SSH_ERROR;
    }
    if (bitmap_len > SSH_KRL_MAX_BITMAP_LEN ||
        krl_reader_remaining(r) != 0) {
        SAFE_FREE(bitmap);
        return SSH_ERROR;
    }
    if (bitmap_len > 0) {
        bitmap->bitmap = malloc(bitmap_len);
        if (bitmap->bitmap == NULL) {
            SAFE_FREE(bitmap);
            return SSH_ERROR;
        }
        memcpy(bitmap->bitmap, bitmap_data, bitmap_len);
        bitmap->len = bitmap_len;
    }

    if (ssh_list_append(ca->bitmaps, bitmap) != SSH_OK) {
        SAFE_FREE(bitmap->bitmap);
        SAFE_FREE(bitmap);
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int krl_parse_cert_key_id(ssh_krl krl,
                                 struct krl_reader *r,
                                 size_t *total_key_ids)
{
    const unsigned char *ca_key = NULL;
    const unsigned char *key_id = NULL;
    size_t ca_key_len = 0;
    size_t key_id_len = 0;
    struct ssh_krl_ca_section_st *ca = NULL;
    ssh_string copy = NULL;

    if (krl_read_string(r, &ca_key, &ca_key_len) != SSH_OK ||
        krl_read_string(r, &key_id, &key_id_len) != SSH_OK) {
        return SSH_ERROR;
    }
    if (ca_key_len == 0 || ca_key_len > SSH_KRL_MAX_KEY_BLOB_LEN ||
        key_id_len > SSH_KRL_MAX_KEY_ID_LEN ||
        krl_reader_remaining(r) != 0) {
        return SSH_ERROR;
    }

    ca = krl_get_ca_section(krl, ca_key, ca_key_len);
    if (ca == NULL) {
        return SSH_ERROR;
    }
    if (ca->key_ids == NULL) {
        ca->key_ids = ssh_list_new();
        if (ca->key_ids == NULL) {
            return SSH_ERROR;
        }
    }

    if (*total_key_ids >= SSH_KRL_MAX_KEY_IDS) {
        return SSH_ERROR;
    }
    (*total_key_ids)++;

    copy = ssh_string_new(key_id_len);
    if (copy == NULL) {
        return SSH_ERROR;
    }
    if (key_id_len > 0) {
        memcpy(ssh_string_data(copy), key_id, key_id_len);
    }
    if (ssh_list_append(ca->key_ids, copy) != SSH_OK) {
        SSH_STRING_FREE(copy);
        return SSH_ERROR;
    }

    return SSH_OK;
}

static int krl_parse_certificates_section(ssh_krl krl,
                                          const unsigned char *data,
                                          size_t len)
{
    struct krl_reader r = {data, len, 0};
    size_t nsections = 0;
    size_t total_serials = 0;
    size_t total_ranges = 0;
    size_t total_bitmaps = 0;
    size_t total_key_ids = 0;
    int rc = SSH_ERROR;

    while (krl_reader_remaining(&r) > 0) {
        const unsigned char *subdata = NULL;
        size_t sublen = 0;
        struct krl_reader sub;
        uint8_t type;

        if (++nsections > SSH_KRL_MAX_CERT_SUBSECTIONS) {
            return SSH_ERROR;
        }

        if (krl_read_u8(&r, &type) != SSH_OK ||
            krl_read_string(&r, &subdata, &sublen) != SSH_OK) {
            return SSH_ERROR;
        }

        sub.data = subdata;
        sub.len = sublen;
        sub.off = 0;

        switch (type) {
        case SSH_KRL_SECTION_CERT_SERIAL_LIST:
            rc = krl_parse_cert_serial_list(krl, &sub, &total_serials);
            break;
        case SSH_KRL_SECTION_CERT_SERIAL_RANGE:
            rc = krl_parse_cert_serial_range(krl, &sub, &total_ranges);
            break;
        case SSH_KRL_SECTION_CERT_SERIAL_BITMAP:
            rc = krl_parse_cert_serial_bitmap(krl, &sub, &total_bitmaps);
            break;
        case SSH_KRL_SECTION_CERT_KEY_ID:
            rc = krl_parse_cert_key_id(krl, &sub, &total_key_ids);
            break;
        default:
            /* Unknown certificate subsection: fail safe */
            SSH_LOG(SSH_LOG_WARN,
                    "Unknown KRL certificate subsection type %u", type);
            return SSH_ERROR;
        }
        if (rc != SSH_OK) {
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}

static int krl_parse_keys_section(ssh_krl krl,
                                  const unsigned char *data,
                                  size_t len)
{
    struct krl_reader r = {data, len, 0};
    size_t nkeys = 0;

    while (krl_reader_remaining(&r) > 0) {
        const unsigned char *key_data = NULL;
        size_t key_len = 0;
        ssh_string copy = NULL;

        if (++nkeys > SSH_KRL_MAX_KEYS) {
            return SSH_ERROR;
        }
        if (krl_read_string(&r, &key_data, &key_len) != SSH_OK) {
            return SSH_ERROR;
        }
        if (key_len == 0 || key_len > SSH_KRL_MAX_KEY_BLOB_LEN) {
            return SSH_ERROR;
        }

        copy = ssh_string_new(key_len);
        if (copy == NULL) {
            return SSH_ERROR;
        }
        memcpy(ssh_string_data(copy), key_data, key_len);
        if (ssh_list_append(krl->keys, copy) != SSH_OK) {
            SSH_STRING_FREE(copy);
            return SSH_ERROR;
        }
    }

    return SSH_OK;
}

static int krl_parse_fingerprint_section(unsigned char **hashes,
                                         size_t *n_hashes,
                                         size_t hash_len,
                                         size_t max_hashes,
                                         const unsigned char *data,
                                         size_t len)
{
    size_t count;

    if (len % hash_len != 0) {
        return SSH_ERROR;
    }
    count = len / hash_len;
    if (count == 0) {
        return SSH_OK;
    }
    if (count > max_hashes || *n_hashes > max_hashes - count) {
        return SSH_ERROR;
    }

    /* Several sections of the same type are merged */
    {
        unsigned char *tmp = realloc(*hashes, (*n_hashes + count) * hash_len);
        if (tmp == NULL) {
            return SSH_ERROR;
        }
        *hashes = tmp;
    }
    memcpy(*hashes + *n_hashes * hash_len, data, len);
    *n_hashes += count;

    return SSH_OK;
}

/**
 * @brief Parse a KRL from a memory buffer.
 *
 * The parsed KRL is bounded in size (see SSH_KRL_MAX_* limits) and can be
 * reused for as many revocation checks as needed.
 *
 * @param[in]  session  The SSH session (used for error reporting, may be
 *                      NULL).
 * @param[in]  data     The KRL contents.
 * @param[in]  len      The length of the KRL contents.
 * @param[out] pkrl     A pointer to store the parsed KRL. Free it with
 *                      ssh_krl_free().
 *
 * @return SSH_OK on success, SSH_ERROR on error (invalid or unsupported
 *         KRL). A KRL that cannot be parsed is never silently ignored.
 */
int ssh_krl_import_blob(ssh_session session,
                        const unsigned char *data,
                        size_t len,
                        ssh_krl *pkrl)
{
    struct krl_reader r = {data, len, 0};
    const unsigned char *magic = NULL;
    ssh_krl krl = NULL;
    uint32_t format_version;
    uint64_t flags;
    size_t nsections = 0;
    int rc = SSH_ERROR;

    if (data == NULL || pkrl == NULL) {
        return SSH_ERROR;
    }
    *pkrl = NULL;

    if (krl_read_bytes(&r, &magic, SSH_KRL_MAGIC_LEN) != SSH_OK ||
        memcmp(magic, SSH_KRL_MAGIC, SSH_KRL_MAGIC_LEN - 1) != 0 ||
        magic[SSH_KRL_MAGIC_LEN - 1] != '\0') {
        SSH_LOG(SSH_LOG_WARN, "Invalid KRL magic");
        if (session != NULL) {
            ssh_set_error(session, SSH_FATAL, "Invalid KRL magic");
        }
        return SSH_ERROR;
    }

    if (krl_read_u32(&r, &format_version) != SSH_OK) {
        goto invalid;
    }
    if (format_version != SSH_KRL_FORMAT_VERSION) {
        SSH_LOG(SSH_LOG_WARN,
                "Unsupported KRL format version %u", format_version);
        if (session != NULL) {
            ssh_set_error(session,
                          SSH_FATAL,
                          "Unsupported KRL format version %u",
                          format_version);
        }
        return SSH_ERROR;
    }

    krl = ssh_krl_new();
    if (krl == NULL) {
        if (session != NULL) {
            ssh_set_error_oom(session);
        }
        return SSH_ERROR;
    }

    if (krl_read_u64(&r, &krl->krl_version) != SSH_OK ||
        krl_read_u64(&r, &krl->generated_date) != SSH_OK ||
        krl_read_u64(&r, &flags) != SSH_OK ||
        krl_skip_string(&r) != SSH_OK || /* reserved */
        krl_skip_string(&r) != SSH_OK) { /* comment */
        goto invalid;
    }

    while (krl_reader_remaining(&r) > 0) {
        const unsigned char *section_data = NULL;
        size_t section_len = 0;
        uint8_t type;

        if (++nsections > SSH_KRL_MAX_SECTIONS) {
            goto invalid;
        }

        if (krl_read_u8(&r, &type) != SSH_OK ||
            krl_read_string(&r, &section_data, &section_len) != SSH_OK) {
                goto invalid;
        }

        switch (type) {
        case SSH_KRL_SECTION_CERTIFICATES:
            rc = krl_parse_certificates_section(krl, section_data, section_len);
            break;
        case SSH_KRL_SECTION_KEYS:
            rc = krl_parse_keys_section(krl, section_data, section_len);
            break;
        case SSH_KRL_SECTION_FINGERPRINT_SHA1:
            rc = krl_parse_fingerprint_section(&krl->sha1_hashes,
                                               &krl->n_sha1,
                                               SHA_DIGEST_LEN,
                                               SSH_KRL_MAX_HASHES,
                                               section_data,
                                               section_len);
            break;
        case SSH_KRL_SECTION_FINGERPRINT_SHA256:
            rc = krl_parse_fingerprint_section(&krl->sha256_hashes,
                                               &krl->n_sha256,
                                               SHA256_DIGEST_LEN,
                                               SSH_KRL_MAX_HASHES,
                                               section_data,
                                               section_len);
            break;
        case SSH_KRL_SECTION_SIGNATURE:
            /* Signature over the KRL itself. We do not verify KRL
             * signatures; the section is skipped. */
            rc = SSH_OK;
            break;
        case SSH_KRL_SECTION_EXTENSION:
            /* Extensions are ignored */
            rc = SSH_OK;
            break;
        default:
            /* Unknown section: fail safe */
            SSH_LOG(SSH_LOG_WARN, "Unknown KRL section type %u", type);
            rc = SSH_ERROR;
            break;
        }
        if (rc != SSH_OK) {
            goto invalid;
        }
    }

    *pkrl = krl;
    return SSH_OK;

invalid:
    SSH_LOG(SSH_LOG_WARN, "Failed to parse KRL");
    if (session != NULL) {
        ssh_set_error(session, SSH_FATAL, "Failed to parse KRL: invalid file");
    }
    ssh_krl_free(krl);
    return SSH_ERROR;
}

/**
 * @brief Load and parse a KRL file.
 *
 * The file is parsed once and the resulting KRL can be reused for any
 * number of revocation checks; the file is not re-read on each check.
 *
 * @param[in]  session  The SSH session (used for error reporting, may be
 *                      NULL).
 * @param[in]  filename The path of the KRL file.
 * @param[out] pkrl     A pointer to store the parsed KRL. Free it with
 *                      ssh_krl_free().
 *
 * @return SSH_OK on success, SSH_ERROR if the file cannot be read or
 *         contains an invalid KRL.
 */
int ssh_krl_import_file(ssh_session session, const char *filename, ssh_krl *pkrl)
{
    FILE *fp = NULL;
    unsigned char *data = NULL;
    size_t len = 0;
    size_t nread;
    char err_msg[SSH_ERRNO_MSG_MAX] = {0};
    int rc = SSH_ERROR;

    if (filename == NULL || pkrl == NULL) {
        if (session != NULL) {
            ssh_set_error_invalid(session);
        }
        return SSH_ERROR;
    }
    *pkrl = NULL;

    fp = ssh_strict_fopen(filename, SSH_KRL_MAX_FILE_SIZE);
    if (fp == NULL) {
        if (session != NULL) {
            ssh_set_error(session,
                          SSH_FATAL,
                          "Cannot open KRL file %s: %s",
                          filename,
                          ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
        }
        return SSH_ERROR;
    }

    data = malloc(SSH_KRL_MAX_FILE_SIZE);
    if (data == NULL) {
        if (session != NULL) {
            ssh_set_error_oom(session);
        }
        goto out;
    }

    nread = fread(data, 1, SSH_KRL_MAX_FILE_SIZE, fp);
    if (ferror(fp)) {
        if (session != NULL) {
            ssh_set_error(session,
                          SSH_FATAL,
                          "Cannot read KRL file %s: %s",
                          filename,
                          ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
        }
        goto out;
    }
    len = nread;

    rc = ssh_krl_import_blob(session, data, len, pkrl);

out:
    SAFE_FREE(data);
    fclose(fp);
    return rc;
}

/*
 * Extract the serial number, key id and signature (CA) key from an
 * OpenSSH certificate blob.
 *
 * The cert blob layout is:
 *   string  cert key type
 *   string  nonce
 *   ...     public key fields (type specific)
 *   uint64  serial
 *   uint32  cert type
 *   string  key id
 *   string  valid principals
 *   uint64  valid after
 *   uint64  valid before
 *   string  critical options
 *   string  extensions
 *   string  reserved
 *   string  signature key
 *   string  signature
 */
static int krl_cert_get_fields(const unsigned char *blob,
                               size_t blob_len,
                               enum ssh_keytypes_e type,
                               uint64_t *serial,
                               ssh_string *key_id,
                               ssh_string *sig_key)
{
    struct krl_reader r = {blob, blob_len, 0};
    const unsigned char *ptr = NULL;
    size_t len = 0;
    uint32_t cert_type;
    uint64_t skip_u64;
    ssh_string id = NULL;
    ssh_string ca = NULL;
    int nskip, i;
    int rc = SSH_ERROR;

    switch (type) {
    case SSH_KEYTYPE_RSA_CERT01:
        /* e, n */
        nskip = 2;
        break;
    case SSH_KEYTYPE_ECDSA_P256_CERT01:
    case SSH_KEYTYPE_ECDSA_P384_CERT01:
    case SSH_KEYTYPE_ECDSA_P521_CERT01:
        /* curve name, public point */
        nskip = 2;
        break;
    case SSH_KEYTYPE_ED25519_CERT01:
        /* public key */
        nskip = 1;
        break;
    case SSH_KEYTYPE_SK_ECDSA_CERT01:
        /* curve name, public point, application */
        nskip = 3;
        break;
    case SSH_KEYTYPE_SK_ED25519_CERT01:
        /* public key, application */
        nskip = 2;
        break;
    default:
        return SSH_ERROR;
    }

    /* cert key type, nonce */
    if (krl_skip_string(&r) != SSH_OK || krl_skip_string(&r) != SSH_OK) {
        return SSH_ERROR;
    }
    /* public key fields */
    for (i = 0; i < nskip; i++) {
        if (krl_skip_string(&r) != SSH_OK) {
            return SSH_ERROR;
        }
    }
    /* serial, cert type, key id */
    if (krl_read_u64(&r, serial) != SSH_OK ||
        krl_read_u32(&r, &cert_type) != SSH_OK ||
        krl_read_string(&r, &ptr, &len) != SSH_OK) {
        return SSH_ERROR;
    }
    id = ssh_string_new(len);
    if (id == NULL) {
        return SSH_ERROR;
    }
    if (len > 0) {
        memcpy(ssh_string_data(id), ptr, len);
    }
    /* valid principals, valid after, valid before, critical options,
     * extensions, reserved */
    if (krl_skip_string(&r) != SSH_OK ||
        krl_read_u64(&r, &skip_u64) != SSH_OK ||
        krl_read_u64(&r, &skip_u64) != SSH_OK ||
        krl_skip_string(&r) != SSH_OK ||
        krl_skip_string(&r) != SSH_OK ||
        krl_skip_string(&r) != SSH_OK) {
        goto out;
    }
    /* signature key */
    if (krl_read_string(&r, &ptr, &len) != SSH_OK) {
        goto out;
    }
    ca = ssh_string_new(len);
    if (ca == NULL) {
        goto out;
    }
    if (len > 0) {
        memcpy(ssh_string_data(ca), ptr, len);
    }

    *key_id = id;
    *sig_key = ca;
    return SSH_OK;

out:
    SSH_STRING_FREE(id);
    SSH_STRING_FREE(ca);
    return rc;
}

static bool krl_serial_revoked(const struct ssh_krl_ca_section_st *ca,
                               uint64_t serial)
{
    struct ssh_iterator *it = NULL;

    if (ca->serials != NULL) {
        for (it = ssh_list_get_iterator(ca->serials);
             it != NULL;
             it = it->next) {
            uint64_t *s = ssh_iterator_value(uint64_t *, it);
            if (s != NULL && *s == serial) {
                return true;
            }
        }
    }

    if (ca->ranges != NULL) {
        for (it = ssh_list_get_iterator(ca->ranges);
             it != NULL;
             it = it->next) {
            struct ssh_krl_serial_range_st *range =
                ssh_iterator_value(struct ssh_krl_serial_range_st *, it);
            if (range != NULL && serial >= range->lo && serial <= range->hi) {
                return true;
            }
        }
    }

    if (ca->bitmaps != NULL) {
        for (it = ssh_list_get_iterator(ca->bitmaps);
             it != NULL;
             it = it->next) {
            struct ssh_krl_serial_bitmap_st *bitmap =
                ssh_iterator_value(struct ssh_krl_serial_bitmap_st *, it);
            uint64_t bit;

            if (bitmap == NULL || bitmap->bitmap == NULL) {
                continue;
            }
            if (serial < bitmap->offset) {
                continue;
            }
            bit = serial - bitmap->offset;
            if (bit / 8 >= bitmap->len) {
                continue;
            }
            if (bitmap->bitmap[bit / 8] & (1 << (bit % 8))) {
                return true;
            }
        }
    }

    return false;
}

static bool krl_key_id_revoked(const struct ssh_krl_ca_section_st *ca,
                               const ssh_string key_id)
{
    struct ssh_iterator *it = NULL;

    if (ca->key_ids == NULL || key_id == NULL || ssh_string_len(key_id) == 0)
    {
        return false;
    }

    for (it = ssh_list_get_iterator(ca->key_ids);
         it != NULL;
         it = it->next) {
        ssh_string revoked_id = ssh_iterator_value(ssh_string, it);
        if (revoked_id != NULL && ssh_string_cmp(revoked_id, key_id) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Check if a key or certificate is revoked by a KRL.
 *
 * Plain keys are matched against the revoked keys list and the SHA1/SHA256
 * fingerprint sections. Certificates are additionally matched against the
 * certificate sections: by serial number (list, range or bitmap) and by
 * key id, in both cases scoped to the CA that signed the certificate.
 *
 * @param[in]  krl  The KRL to check against.
 * @param[in]  key  The key or certificate to check.
 *
 * @return 1 if the key is revoked, 0 if it is not revoked, -1 on error.
 */
int ssh_krl_key_is_revoked(ssh_krl krl, ssh_key key)
{
    ssh_string blob = NULL;
    unsigned char hash[SHA256_DIGEST_LEN];
    struct ssh_iterator *it = NULL;
    size_t i;
    int rc;
    int revoked = 0;

    if (krl == NULL || key == NULL) {
        return -1;
    }

    rc = ssh_pki_export_pubkey_blob(key, &blob);
    if (rc != SSH_OK || blob == NULL) {
        return -1;
    }

    /* Explicitly revoked keys */
    for (it = ssh_list_get_iterator(krl->keys);
         it != NULL;
         it = it->next) {
        ssh_string revoked_key = ssh_iterator_value(ssh_string, it);
        if (revoked_key != NULL && ssh_string_cmp(revoked_key, blob) == 0) {
            revoked = 1;
            goto out;
        }
    }

    /* SHA1 fingerprints */
    if (krl->n_sha1 > 0) {
        rc = sha1(ssh_string_data(blob), ssh_string_len(blob), hash);
        if (rc != SSH_OK) {
            revoked = -1;
            goto out;
        }
        for (i = 0; i < krl->n_sha1; i++) {
            if (memcmp(krl->sha1_hashes + i * SHA_DIGEST_LEN,
                       hash,
                       SHA_DIGEST_LEN) == 0) {
                revoked = 1;
                goto out;
            }
        }
    }

    /* SHA256 fingerprints */
    if (krl->n_sha256 > 0) {
        rc = sha256(ssh_string_data(blob), ssh_string_len(blob), hash);
        if (rc != SSH_OK) {
            revoked = -1;
            goto out;
        }
        for (i = 0; i < krl->n_sha256; i++) {
            if (memcmp(krl->sha256_hashes + i * SHA256_DIGEST_LEN,
                       hash,
                       SHA256_DIGEST_LEN) == 0) {
                revoked = 1;
                goto out;
            }
        }
    }

    /* Certificate revocation, scoped to the signing CA */
    if (is_cert_type(key->type) && key->cert != NULL) {
        uint64_t serial = 0;
        ssh_string key_id = NULL;
        ssh_string sig_key = NULL;

        rc = krl_cert_get_fields(ssh_buffer_get(key->cert),
                                 ssh_buffer_get_len(key->cert),
                                 key->type,
                                 &serial,
                                 &key_id,
                                 &sig_key);
        if (rc != SSH_OK) {
            /* A certificate we cannot parse cannot be checked: fail safe */
            SSH_STRING_FREE(key_id);
            SSH_STRING_FREE(sig_key);
            revoked = -1;
            goto out;
        }

        for (it = ssh_list_get_iterator(krl->ca_sections);
             it != NULL;
             it = it->next) {
            struct ssh_krl_ca_section_st *ca =
                ssh_iterator_value(struct ssh_krl_ca_section_st *, it);

            if (ca == NULL || ca->ca_key == NULL || sig_key == NULL) {
                continue;
            }
            if (ssh_string_cmp(ca->ca_key, sig_key) != 0) {
                continue;
            }

            if (krl_serial_revoked(ca, serial) ||
                krl_key_id_revoked(ca, key_id)) {
                revoked = 1;
                break;
            }
        }

        SSH_STRING_FREE(key_id);
        SSH_STRING_FREE(sig_key);
    }

out:
    SSH_STRING_FREE(blob);
    return revoked;
}

/**
 * @brief Set the maximum accepted age of KRLs for a session.
 *
 * When set to a non-zero value, a KRL whose generated date is older than
 * the given number of seconds (or that is dated in the future) is
 * considered expired and any revocation check for the session fails
 * closed instead of silently skipping the outdated KRL.
 *
 * The default is 0, which disables the expiration check.
 *
 * @param[in]  session  The SSH session.
 * @param[in]  max_age  The maximum KRL age in seconds, 0 to disable.
 */
void ssh_session_set_krl_max_age(ssh_session session, uint64_t max_age)
{
    if (session == NULL) {
        return;
    }
    session->opts.krl_max_age = max_age;
}

static bool ssh_krl_is_expired(ssh_session session, ssh_krl krl)
{
    time_t now;

    if (session->opts.krl_max_age == 0) {
        return false;
    }

    now = time(NULL);
    if ((uint64_t)now < krl->generated_date) {
        /* KRL dated in the future cannot be trusted */
        return true;
    }
    if ((uint64_t)now - krl->generated_date > session->opts.krl_max_age) {
        return true;
    }

    return false;
}

/**
 * @brief Check if a key or certificate is revoked by one of the KRLs
 * attached to the session.
 *
 * @param[in]  session  The SSH session.
 * @param[in]  key      The key or certificate to check.
 *
 * @return 1 if the key is revoked, 0 if no KRL is configured or the key is
 *         not revoked, SSH_ERROR if a configured KRL cannot be used (for
 *         instance because it expired). In doubt, the check fails closed.
 */
int ssh_session_key_is_revoked(ssh_session session, ssh_key key)
{
    struct ssh_iterator *it = NULL;

    if (session == NULL || key == NULL) {
        return SSH_ERROR;
    }

    if (session->opts.krls == NULL) {
        return 0;
    }

    for (it = ssh_list_get_iterator(session->opts.krls);
         it != NULL;
         it = it->next) {
        struct ssh_krl_entry_st *entry =
            ssh_iterator_value(struct ssh_krl_entry_st *, it);
        int rc;

        if (entry == NULL || entry->krl == NULL) {
            continue;
        }

        if (ssh_krl_is_expired(session, entry->krl)) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "KRL %s is expired",
                          entry->path != NULL ? entry->path : "(memory)");
            return SSH_ERROR;
        }

        rc = ssh_krl_key_is_revoked(entry->krl, key);
        if (rc != 0) {
            if (rc < 0) {
                ssh_set_error(session,
                              SSH_REQUEST_DENIED,
                              "Failed to check key against KRL %s",
                              entry->path != NULL ? entry->path : "(memory)");
                return SSH_ERROR;
            }
            return 1;
        }
    }

    return 0;
}

static int ssh_session_krl_add_entry(ssh_session session,
                                     const char *path,
                                     ssh_krl krl)
{
    struct ssh_krl_entry_st *entry = NULL;
    struct ssh_iterator *it = NULL;

    if (session->opts.krls == NULL) {
        session->opts.krls = ssh_list_new();
        if (session->opts.krls == NULL) {
            ssh_set_error_oom(session);
            return SSH_ERROR;
        }
    }

    if (path != NULL) {
        /* Replace an existing KRL loaded from the same path so that KRL
         * updates take effect */
        for (it = ssh_list_get_iterator(session->opts.krls);
             it != NULL;
             it = it->next) {
            entry = ssh_iterator_value(struct ssh_krl_entry_st *, it);
            if (entry != NULL && entry->path != NULL &&
                strcmp(entry->path, path) == 0) {
                ssh_krl_free(entry->krl);
                entry->krl = krl;
                return SSH_OK;
            }
        }
    }

    entry = calloc(1, sizeof(struct ssh_krl_entry_st));
    if (entry == NULL) {
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }
    if (path != NULL) {
        entry->path = strdup(path);
        if (entry->path == NULL) {
            SAFE_FREE(entry);
            ssh_set_error_oom(session);
            return SSH_ERROR;
        }
    }
    entry->krl = krl;

    if (ssh_list_append(session->opts.krls, entry) != SSH_OK) {
        ssh_krl_entry_free(entry);
        ssh_set_error_oom(session);
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @brief Attach an already parsed KRL to a session.
 *
 * The session takes ownership of the KRL and frees it in ssh_free(). The
 * KRL is used by ssh_session_key_is_revoked() and by the known_hosts
 * verification functions, which then return SSH_KNOWN_HOSTS_REVOKED for
 * revoked server keys.
 *
 * @param[in]  session  The SSH session.
 * @param[in]  krl      The KRL to attach.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
int ssh_session_krl_add(ssh_session session, ssh_krl krl)
{
    if (session == NULL || krl == NULL) {
        if (session != NULL) {
            ssh_set_error_invalid(session);
        }
        return SSH_ERROR;
    }

    return ssh_session_krl_add_entry(session, NULL, krl);
}

/**
 * @brief Load a KRL file and attach it to a session.
 *
 * Several KRL files can be attached to the same session; a key is
 * considered revoked if any of them revokes it. Loading a KRL from a path
 * that was already loaded replaces the previous KRL, which allows to
 * update revocation information. The file is parsed once at load time and
 * is not re-read on subsequent checks.
 *
 * An invalid or unreadable KRL file is an error and is never silently
 * ignored.
 *
 * @param[in]  session  The SSH session.
 * @param[in]  filename The path of the KRL file.
 *
 * @return SSH_OK on success, SSH_ERROR on error.
 */
int ssh_session_krl_add_file(ssh_session session, const char *filename)
{
    ssh_krl krl = NULL;
    int rc;

    if (session == NULL || filename == NULL) {
        if (session != NULL) {
            ssh_set_error_invalid(session);
        }
        return SSH_ERROR;
    }

    rc = ssh_krl_import_file(session, filename, &krl);
    if (rc != SSH_OK) {
        return SSH_ERROR;
    }

    rc = ssh_session_krl_add_entry(session, filename, krl);
    if (rc != SSH_OK) {
        ssh_krl_free(krl);
        return SSH_ERROR;
    }

    return SSH_OK;
}

/** @} */
