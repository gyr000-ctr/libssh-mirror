/*
 * known_hosts: Host and public key verification.
 *
 * This file is part of the SSH Library
 *
 * Copyright (c) 2003-2009 by Aris Adamantiadis
 * Copyright (c) 2009-2017 by Andreas Schneider <asn@cryptomilk.org>
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

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <strings.h>
#endif

#include "libssh/priv.h"
#include "libssh/buffer.h"
#include "libssh/dh.h"
#include "libssh/session.h"
#include "libssh/options.h"
#include "libssh/misc.h"
#include "libssh/pki.h"
#include "libssh/libssh.h"
#include "libssh/dh.h"
#include "libssh/knownhosts.h"
#include "libssh/token.h"

#ifndef MAX_LINE_SIZE
#define MAX_LINE_SIZE 8192
#endif

/**
 * Markers that may prefix a known_hosts line, as introduced by OpenSSH:
 * "@cert-authority" and "@revoked".
 */
enum ssh_known_hosts_marker_e {
    SSH_KNOWN_HOSTS_MARKER_NONE = 0,
    SSH_KNOWN_HOSTS_MARKER_CERT_AUTHORITY,
    SSH_KNOWN_HOSTS_MARKER_REVOKED,
    /* The line carries a marker we do not understand */
    SSH_KNOWN_HOSTS_MARKER_UNKNOWN,
};

/**
 * @internal
 *
 * @brief Internal representation of a known_hosts entry.
 *
 * The public struct ssh_knownhosts_entry must stay ABI stable, so the marker
 * information is tracked separately in this wrapper.
 */
struct ssh_knownhosts_internal_entry {
    struct ssh_knownhosts_entry entry;
    enum ssh_known_hosts_marker_e marker;
};

static bool ssh_known_hosts_result_is_fatal(enum ssh_known_hosts_e rv)
{
    return rv == SSH_KNOWN_HOSTS_REVOKED ||
           rv == SSH_KNOWN_HOSTS_CERT_EXPIRED ||
           rv == SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA;
}

static void ssh_known_hosts_set_fatal_error(ssh_session session,
                                            enum ssh_known_hosts_e rv)
{
    switch (rv) {
    case SSH_KNOWN_HOSTS_REVOKED:
        ssh_set_error(session,
                      SSH_FATAL,
                      "The server host key or certificate has been revoked "
                      "in the known_hosts file");
        break;
    case SSH_KNOWN_HOSTS_CERT_EXPIRED:
        ssh_set_error(session,
                      SSH_FATAL,
                      "The server host certificate is expired or not yet "
                      "valid");
        break;
    case SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA:
        ssh_set_error(session,
                      SSH_FATAL,
                      "The server host certificate is not signed by a "
                      "trusted certificate authority");
        break;
    default:
        break;
    }
}

/**
 * @internal
 *
 * @brief Parse the optional marker at the beginning of a known_hosts line.
 *
 * Markers have the form "@marker" as the first whitespace separated token
 * of the line, the only markers defined by OpenSSH being "cert-authority"
 * and "revoked". Marker names are matched case insensitively.
 *
 * @param[in]  p        The line with leading spaces already skipped.
 * @param[out] marker   The detected marker.
 *
 * @return              A pointer to the remainder of the line after the
 *                      marker on success, NULL if the marker is malformed.
 *                      For lines without a marker, @p marker is set to
 *                      SSH_KNOWN_HOSTS_MARKER_NONE and @p p is returned.
 *                      Lines carrying an unsupported marker are reported as
 *                      SSH_KNOWN_HOSTS_MARKER_UNKNOWN.
 */
static const char *
ssh_known_hosts_parse_marker(const char *p,
                             enum ssh_known_hosts_marker_e *marker)
{
    const char *q = NULL;
    size_t len;

    *marker = SSH_KNOWN_HOSTS_MARKER_NONE;

    if (p[0] != '@') {
        return p;
    }

    q = p + 1;
    len = strcspn(q, " \t");
    if (len == 0) {
        /* A bare "@" is a malformed marker line */
        return NULL;
    }

    /* OpenSSH defines only single marker tokens. A comma indicates either an
     * empty marker or a marker combination with no defined semantics, so
     * treat it as malformed rather than silently dropping security policy. */
    if (memchr(q, ',', len) != NULL) {
        return NULL;
    }

    if (len == strlen("cert-authority") &&
        strncasecmp(q, "cert-authority", len) == 0) {
        *marker = SSH_KNOWN_HOSTS_MARKER_CERT_AUTHORITY;
    } else if (len == strlen("revoked") &&
               strncasecmp(q, "revoked", len) == 0) {
        *marker = SSH_KNOWN_HOSTS_MARKER_REVOKED;
    } else {
        *marker = SSH_KNOWN_HOSTS_MARKER_UNKNOWN;
    }

    /* Skip the marker token and the whitespace following it */
    q = p + 1 + len;
    while (*q == ' ' || *q == '\t') {
        q++;
    }
    if (*q == '\0') {
        /* Marker without an actual host entry */
        return NULL;
    }

    return q;
}

/**
 * @internal
 *
 * @brief Extract the validity period and principals of an OpenSSH certificate.
 *
 * The certificate blob layout (RFC-like, see PROTOCOL.certkeys) is:
 *   string type, string nonce, string cert public key, uint64 serial,
 *   uint32 type, string key id, string valid principals,
 *   uint64 valid after, uint64 valid before, string critical options,
 *   string extensions, string reserved, string signature key,
 *   string signature.
 *
 * @param[in]  cert_key      The imported certificate key.
 * @param[out] valid_after   Start of the validity period (unix time).
 * @param[out] valid_before  End of the validity period (unix time).
 * @param[out] principals    Newly allocated list of principal strings,
 *                           NULL if there are none. The caller owns the
 *                           buffer and must free it.
 *
 * @return SSH_OK on success, SSH_ERROR if the certificate is malformed.
 */
static int
ssh_known_hosts_cert_get_validity(const ssh_key cert_key,
                                  uint64_t *valid_after,
                                  uint64_t *valid_before,
                                  ssh_buffer *principals)
{
    ssh_buffer cert = NULL;
    ssh_string tmp_s = NULL;
    uint64_t raw64;
    uint32_t raw32;
    int rc = SSH_ERROR;

    if (cert_key == NULL || cert_key->cert == NULL ||
        !is_cert_type(cert_key->type)) {
        return SSH_ERROR;
    }

    cert = ssh_buffer_new();
    if (cert == NULL) {
        return SSH_ERROR;
    }

    if (ssh_buffer_add_buffer(cert, cert_key->cert) != SSH_OK) {
        goto out;
    }

    tmp_s = ssh_buffer_get_ssh_string(cert); /* type */
    SSH_STRING_FREE(tmp_s);
    tmp_s = ssh_buffer_get_ssh_string(cert); /* nonce */
    SSH_STRING_FREE(tmp_s);
    tmp_s = ssh_buffer_get_ssh_string(cert); /* certified public key */
    SSH_STRING_FREE(tmp_s);

    {
        /* Consume the serial (uint64) and certificate type (uint32) fields;
         * their values are not needed beyond the structural validation. */
        if (ssh_buffer_get_u64(cert, &raw64) != sizeof(uint64_t) ||
            ssh_buffer_get_u32(cert, &raw32) != sizeof(uint32_t)) {
            goto out;
        }
    }

    tmp_s = ssh_buffer_get_ssh_string(cert); /* key id */
    SSH_STRING_FREE(tmp_s);
    tmp_s = ssh_buffer_get_ssh_string(cert); /* valid principals blob */
    if (tmp_s == NULL) {
        goto out;
    }
    if (principals != NULL) {
        *principals = ssh_buffer_new();
        if (*principals == NULL) {
            SSH_STRING_FREE(tmp_s);
            goto out;
        }
        if (ssh_buffer_add_data(*principals,
                                ssh_string_data(tmp_s),
                                ssh_string_len(tmp_s)) != SSH_OK) {
            SSH_BUFFER_FREE(*principals);
            *principals = NULL;
            SSH_STRING_FREE(tmp_s);
            goto out;
        }
    }
    SSH_STRING_FREE(tmp_s);

    {
        uint64_t raw_after, raw_before;
        if (ssh_buffer_get_u64(cert, &raw_after) != sizeof(uint64_t) ||
            ssh_buffer_get_u64(cert, &raw_before) != sizeof(uint64_t)) {
            if (principals != NULL) {
                SSH_BUFFER_FREE(*principals);
                *principals = NULL;
            }
            goto out;
        }
        *valid_after = ntohll(raw_after);
        *valid_before = ntohll(raw_before);
    }

    rc = SSH_OK;

out:
    SSH_BUFFER_FREE(cert);
    return rc;
}

/**
 * @internal
 *
 * @brief Check that the connected host is among the certificate principals.
 *
 * A certificate without any principal is valid for any host. The host name
 * is compared without its port part, principals never carry ports.
 *
 * @param[in]  hosts_entry  The "host" or "[host]:port" string used for the
 *                          known_hosts lookup.
 * @param[in]  principals   The principals blob of the certificate.
 *
 * @return true if the host is authorized, false otherwise.
 */
static bool
ssh_known_hosts_cert_principal_matches(const char *hosts_entry,
                                       const ssh_buffer principals)
{
    ssh_string principal = NULL;
    char *bare_host = NULL;
    const char *host = hosts_entry;
    bool match = false;

    if (principals == NULL) {
        return false;
    }

    if (ssh_buffer_get_len(principals) == 0) {
        /* No principals means the certificate applies to every host */
        return true;
    }

    if (host[0] == '[') {
        const char *end = strchr(host, ']');
        if (end == NULL) {
            return false;
        }
        bare_host = strndup(host + 1, (size_t)(end - host - 1));
        if (bare_host == NULL) {
            return false;
        }
        host = bare_host;
    }

    while ((principal = ssh_buffer_get_ssh_string(principals)) != NULL) {
        char *pattern = NULL;
        size_t plen = ssh_string_len(principal);

        pattern = calloc(1, plen + 1);
        if (pattern == NULL) {
            SSH_STRING_FREE(principal);
            break;
        }
        memcpy(pattern, ssh_string_data(principal), plen);

        if (match_hostname(host, pattern, plen) == 1) {
            match = true;
        }
        SAFE_FREE(pattern);
        SSH_STRING_FREE(principal);
        if (match) {
            break;
        }
    }

    SAFE_FREE(bare_host);
    return match;
}

/**
 * @internal
 *
 * @brief Verify a host certificate against a certificate authority key.
 *
 * The check covers:
 *  - the certificate validity period against the current time,
 *  - that the certificate public key is the key presented by the server,
 *  - the CA signature over the certificate blob.
 *
 * @param[in]  session     The session, used for PKI signature verification.
 * @param[in]  server_key  The public key or certificate the server presented.
 * @param[in]  cert_key    The certificate as imported from the known_hosts
 *                         @cert-authority entry.
 * @param[in]  ca_key      The certificate authority public key.
 *
 * @return SSH_KNOWN_HOSTS_OK on success,
 *         SSH_KNOWN_HOSTS_CERT_EXPIRED if the certificate is outside its
 *         validity window,
 *         SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA for any other verification
 *         failure (signature mismatch, malformed certificate, ...).
 */
static enum ssh_known_hosts_e
ssh_known_hosts_verify_cert(ssh_session session,
                            const char *hosts_entry,
                            const ssh_key server_key,
                            const ssh_key cert_key,
                            const ssh_key ca_key)
{
    uint64_t valid_after = 0;
    uint64_t valid_before = 0;
    ssh_buffer principals = NULL;
    ssh_buffer cert_copy = NULL;
    ssh_buffer signed_data = NULL;
    ssh_string sig_blob = NULL;
    ssh_string tmp_s = NULL;
    ssh_signature sig = NULL;
    enum ssh_known_hosts_e rv = SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA;
    size_t cert_len;
    uint32_t sig_field_len;
    time_t now;
    int rc;

    if (!is_cert_type(cert_key->type) || cert_key->cert == NULL) {
        return SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA;
    }

    /* 1. Validity period and principals */
    rc = ssh_known_hosts_cert_get_validity(cert_key,
                                           &valid_after,
                                           &valid_before,
                                           &principals);
    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_WARN,
                "Failed to parse the validity period of the host "
                "certificate");
        return SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA;
    }

    now = time(NULL);
    if ((uint64_t)now < valid_after || (uint64_t)now >= valid_before) {
        SSH_LOG(SSH_LOG_WARN,
                "Host certificate is not valid at the current time "
                "(valid from %llu to %llu, now %lld)",
                (unsigned long long)valid_after,
                (unsigned long long)valid_before,
                (long long)now);
        rv = SSH_KNOWN_HOSTS_CERT_EXPIRED;
        goto cert_verify_out;
    }

    if (!ssh_known_hosts_cert_principal_matches(hosts_entry, principals)) {
        SSH_LOG(SSH_LOG_WARN,
                "Host certificate does not name the connected host '%s'",
                hosts_entry);
        goto cert_verify_out;
    }

    /* 2. The certificate must certify the key the server actually holds */
    if (ssh_key_type_plain(server_key->type) !=
        ssh_key_type_plain(cert_key->type)) {
        SSH_LOG(SSH_LOG_WARN,
                "Host certificate key type does not match the server key");
        goto cert_verify_out;
    }

    if (ssh_key_cmp(server_key, cert_key, SSH_KEY_CMP_PUBLIC) != 0) {
        SSH_LOG(SSH_LOG_WARN,
                "Host certificate does not certify the presented server key");
        goto cert_verify_out;
    }

    /* 3. Verify the CA signature. The signature covers the whole certificate
     * blob except for the trailing signature string. Work on a copy, the cert
     * buffer inside cert_key is shared and must not be mutated. */
    cert_copy = ssh_buffer_new();
    signed_data = ssh_buffer_new();
    if (cert_copy == NULL || signed_data == NULL) {
        goto cert_verify_out;
    }

    rc = ssh_buffer_add_buffer(cert_copy, cert_key->cert);
    if (rc != SSH_OK) {
        goto cert_verify_out;
    }
    cert_len = ssh_buffer_get_len(cert_copy);

    /* Walk the certificate fields in order; the signature is the final
     * string of the blob. */
    tmp_s = ssh_buffer_get_ssh_string(cert_copy); /* type */
    SSH_STRING_FREE(tmp_s);
    tmp_s = ssh_buffer_get_ssh_string(cert_copy); /* nonce */
    SSH_STRING_FREE(tmp_s);
    tmp_s = ssh_buffer_get_ssh_string(cert_copy); /* public key */
    SSH_STRING_FREE(tmp_s);
    if (ssh_buffer_pass_bytes(cert_copy, 8) != 8 ||       /* serial */
        ssh_buffer_pass_bytes(cert_copy, 4) != 4) {       /* type */
        goto cert_verify_out;
    }
    tmp_s = ssh_buffer_get_ssh_string(cert_copy); /* key id */
    SSH_STRING_FREE(tmp_s);
    tmp_s = ssh_buffer_get_ssh_string(cert_copy); /* principals */
    SSH_STRING_FREE(tmp_s);
    if (ssh_buffer_pass_bytes(cert_copy, 16) != 16) { /* validity window */
        goto cert_verify_out;
    }
    tmp_s = ssh_buffer_get_ssh_string(cert_copy); /* critical options */
    SSH_STRING_FREE(tmp_s);
    tmp_s = ssh_buffer_get_ssh_string(cert_copy); /* extensions */
    SSH_STRING_FREE(tmp_s);
    tmp_s = ssh_buffer_get_ssh_string(cert_copy); /* reserved */
    SSH_STRING_FREE(tmp_s);
    tmp_s = ssh_buffer_get_ssh_string(cert_copy); /* signature key */
    SSH_STRING_FREE(tmp_s);
    sig_blob = ssh_buffer_get_ssh_string(cert_copy); /* signature */
    if (sig_blob == NULL || ssh_buffer_get_len(cert_copy) != 0) {
        goto cert_verify_out;
    }

    sig_field_len = sizeof(uint32_t) + ssh_string_len(sig_blob);
    if (sig_field_len >= cert_len) {
        goto cert_verify_out;
    }

    rc = ssh_buffer_add_data(signed_data,
                             ssh_buffer_get(cert_key->cert),
                             cert_len - sig_field_len);
    if (rc != SSH_OK) {
        goto cert_verify_out;
    }

    rc = ssh_pki_import_signature_blob(sig_blob, ca_key, &sig);
    if (rc != SSH_OK || sig == NULL) {
        SSH_LOG(SSH_LOG_WARN,
                "Failed to parse the host certificate signature");
        goto cert_verify_out;
    }

    rc = ssh_pki_signature_verify(session,
                                  sig,
                                  ca_key,
                                  ssh_buffer_get(signed_data),
                                  ssh_buffer_get_len(signed_data));
    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_WARN,
                "Host certificate signature verification failed");
        goto cert_verify_out;
    }

    rv = SSH_KNOWN_HOSTS_OK;

cert_verify_out:
    ssh_signature_free(sig);
    SSH_STRING_FREE(sig_blob);
    SSH_BUFFER_FREE(cert_copy);
    SSH_BUFFER_FREE(signed_data);
    SSH_BUFFER_FREE(principals);
    return rv;
}

/**
 * @addtogroup libssh_session
 *
 * @{
 */

static int hash_hostname(const char *name,
                         unsigned char *salt,
                         unsigned int salt_size,
                         unsigned char **hash,
                         size_t *hash_size)
{
    int rc;
    HMACCTX mac_ctx = NULL;

    mac_ctx = hmac_init(salt, salt_size, SSH_HMAC_SHA1);
    if (mac_ctx == NULL) {
        return SSH_ERROR;
    }

    rc = hmac_update(mac_ctx, name, strlen(name));
    if (rc != 1)
        return SSH_ERROR;

    rc = hmac_final(mac_ctx, *hash, hash_size);
    if (rc != 1)
        return SSH_ERROR;

    return SSH_OK;
}

static int match_hashed_hostname(const char *host, const char *hashed_host)
{
    char *hashed = NULL;
    char *b64_hash = NULL;
    ssh_buffer salt = NULL;
    ssh_buffer hash = NULL;
    unsigned char hashed_buf[256] = {0};
    unsigned char *hashed_buf_ptr = hashed_buf;
    size_t hashed_buf_size = sizeof(hashed_buf);
    int cmp;
    int rc;
    int match = 0;

    cmp = strncmp(hashed_host, "|1|", 3);
    if (cmp != 0) {
        return 0;
    }

    hashed = strdup(hashed_host + 3);
    if (hashed == NULL) {
        return 0;
    }

    b64_hash = strchr(hashed, '|');
    if (b64_hash == NULL) {
        goto error;
    }
    *b64_hash = '\0';
    b64_hash++;

    salt = base64_to_bin(hashed);
    if (salt == NULL) {
        goto error;
    }

    hash = base64_to_bin(b64_hash);
    if (hash == NULL) {
        goto error;
    }

    rc = hash_hostname(host,
                       ssh_buffer_get(salt),
                       ssh_buffer_get_len(salt),
                       &hashed_buf_ptr,
                       &hashed_buf_size);
    if (rc != SSH_OK) {
        goto error;
    }

    if (hashed_buf_size != ssh_buffer_get_len(hash)) {
        goto error;
    }

    cmp = memcmp(hashed_buf, ssh_buffer_get(hash), hashed_buf_size);
    if (cmp == 0) {
        match = 1;
    }

error:
    free(hashed);
    SSH_BUFFER_FREE(salt);
    SSH_BUFFER_FREE(hash);

    return match;
}

/**
 * @brief Free an allocated ssh_knownhosts_entry.
 *
 * Use SSH_KNOWNHOSTS_ENTRY_FREE() to set the pointer to NULL.
 *
 * @param[in]  entry     The entry to free.
 */
void ssh_knownhosts_entry_free(struct ssh_knownhosts_entry *entry)
{
    if (entry == NULL) {
        return;
    }

    SAFE_FREE(entry->hostname);
    SAFE_FREE(entry->unparsed);
    ssh_key_free(entry->publickey);
    SAFE_FREE(entry->comment);
    SAFE_FREE(entry);
}

static void
ssh_knownhosts_internal_entry_free(struct ssh_knownhosts_internal_entry *ientry)
{
    if (ientry == NULL) {
        return;
    }

    ssh_knownhosts_entry_free(&ientry->entry);
}

/*
 * Move the embedded public entry out of its wrapper into a standalone
 * allocation the caller can free with ssh_knownhosts_entry_free(). The
 * wrapper shell is released; the owned strings and key are transferred, not
 * copied. Returns NULL on allocation failure, in which case nothing is
 * freed.
 */
static struct ssh_knownhosts_entry *
ssh_knownhosts_entry_detach(struct ssh_knownhosts_internal_entry *ientry)
{
    struct ssh_knownhosts_entry *out = NULL;

    if (ientry == NULL) {
        return NULL;
    }

    out = calloc(1, sizeof(struct ssh_knownhosts_entry));
    if (out == NULL) {
        return NULL;
    }

    *out = ientry->entry;
    /* Neutralize the embedded copy so freeing the wrapper does not release
     * the now-transferred owned data. */
    memset(&ientry->entry, 0, sizeof(ientry->entry));
    SAFE_FREE(ientry);

    return out;
}

static int known_hosts_read_line(FILE *fp,
                                 char *buf,
                                 size_t buf_size,
                                 size_t *buf_len,
                                 size_t *lineno)
{
    while (fgets(buf, (int)buf_size, fp) != NULL) {
        size_t len;
        if (buf[0] == '\0') {
            continue;
        }

        *lineno += 1;
        len = strlen(buf);
        if (buf_len != NULL) {
            *buf_len = len;
        }
        if (buf[len - 1] == '\n' || feof(fp)) {
            return 0;
        } else {
            errno = E2BIG;
            return -1;
        }
    }

    return -1;
}

static int
ssh_known_hosts_entries_compare(struct ssh_knownhosts_internal_entry *k1,
                                struct ssh_knownhosts_internal_entry *k2)
{
    int cmp;

    if (k1 == NULL || k2 == NULL) {
        return 1;
    }

    if (k1->marker != k2->marker) {
        return (int)k1->marker - (int)k2->marker;
    }

    cmp = strcmp(k1->entry.hostname, k2->entry.hostname);
    if (cmp != 0) {
        return cmp;
    }

    cmp = ssh_key_cmp(k1->entry.publickey,
                      k2->entry.publickey,
                      SSH_KEY_CMP_PUBLIC);
    if (cmp != 0) {
        return cmp;
    }

    return 0;
}

/**
 * @internal
 *
 * @brief Read entries from filename to provided list
 *
 * This method reads the known_hosts file referenced by the path
 * in  filename  argument, and entries matching the  match  argument
 * will be added to the list in  entries  argument.
 * If the  entries  list is NULL, it will allocate a new list. Caller
 * is responsible to free it even if an error occurs.
 *
 * @param match[in]       The host name (with port) to match against
 * @param filename[in]    The known hosts file to parse
 * @param entries[in,out] The list of entries to append matching ones
 * @return                `SSH_OK` on missing file or success parsing,
 *                        `SSH_ERROR` on error
 */
static int ssh_known_hosts_read_entries(const char *match,
                                        const char *filename,
                                        struct ssh_list **entries)
{
    char line[MAX_LINE_SIZE];
    size_t lineno = 0;
    size_t len = 0;
    FILE *fp = NULL;
    int rc;

    fp = ssh_strict_fopen(filename, SSH_MAX_CONFIG_FILE_SIZE);
    if (fp == NULL) {
        SSH_LOG_STRERROR(SSH_LOG_TRACE,
                         errno,
                         "Failed to open the known_hosts file '%s': %s",
                         filename);
        /* The missing file is not an error here */
        return SSH_OK;
    }

    if (*entries == NULL) {
        *entries = ssh_list_new();
        if (*entries == NULL) {
            fclose(fp);
            return SSH_ERROR;
        }
    }

    for (rc = known_hosts_read_line(fp, line, sizeof(line), &len, &lineno);
         rc == 0;
         rc = known_hosts_read_line(fp, line, sizeof(line), &len, &lineno)) {
        struct ssh_knownhosts_internal_entry *ientry = NULL;
        struct ssh_knownhosts_entry *entry = NULL;
        struct ssh_iterator *it = NULL;
        enum ssh_known_hosts_marker_e marker = SSH_KNOWN_HOSTS_MARKER_NONE;
        const char *rest = NULL;
        char *p = NULL;

        if (line[len] != '\n') {
            len = strcspn(line, "\n");
        }
        line[len] = '\0';

        /* Skip leading spaces */
        for (p = line; isspace((int)p[0]); p++);

        /* Skip comments and empty lines */
        if (p[0] == '\0' || p[0] == '#') {
            continue;
        }

        if (p[0] == '@') {
            rest = ssh_known_hosts_parse_marker(p, &marker);
            if (rest == NULL) {
                /* Malformed marker line: do not silently ignore it */
                SSH_LOG(SSH_LOG_WARN,
                        "Malformed marker in known_hosts file '%s' "
                        "line %zu: %s",
                        filename,
                        lineno,
                        p);
                errno = EINVAL;
                goto error;
            }

            if (marker == SSH_KNOWN_HOSTS_MARKER_UNKNOWN) {
                /* Forward compatibility: ignore markers we do not know */
                SSH_LOG(SSH_LOG_TRACE,
                        "Ignoring unknown marker in known_hosts file '%s' "
                        "line %zu",
                        filename,
                        lineno);
                continue;
            }
        } else {
            rest = p;
        }

        rc = ssh_known_hosts_parse_line(match,
                                        rest,
                                        &entry);
        if (rc == SSH_AGAIN) {
            continue;
        } else if (rc != SSH_OK) {
            goto error;
        }

        ientry = calloc(1, sizeof(struct ssh_knownhosts_internal_entry));
        if (ientry == NULL) {
            ssh_knownhosts_entry_free(entry);
            goto error;
        }
        ientry->entry = *entry;
        ientry->marker = marker;
        SAFE_FREE(entry);

        /* Check for duplicates */
        for (it = ssh_list_get_iterator(*entries);
             it != NULL;
             it = it->next) {
            struct ssh_knownhosts_internal_entry *entry2 = NULL;
            int cmp;
            entry2 = ssh_iterator_value(
                struct ssh_knownhosts_internal_entry *, it);
            cmp = ssh_known_hosts_entries_compare(ientry, entry2);
            if (cmp == 0) {
                ssh_knownhosts_internal_entry_free(ientry);
                ientry = NULL;
                break;
            }
        }
        if (ientry != NULL) {
            rc = ssh_list_append(*entries, ientry);
            if (rc != SSH_OK) {
                ssh_knownhosts_internal_entry_free(ientry);
                goto error;
            }
        }
    }

    fclose(fp);
    return SSH_OK;
error:
    fclose(fp);
    return SSH_ERROR;
}

static char *ssh_session_get_host_port(ssh_session session)
{
    char *host_port = NULL;
    char *host = NULL;

    if (session->opts.host == NULL) {
        ssh_set_error(session,
                      SSH_FATAL,
                      "Can't verify server in known hosts if the host we "
                      "should connect to has not been set");

        return NULL;
    }

    host = ssh_lowercase(session->opts.host);
    if (host == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }

    if (session->opts.port == 0 || session->opts.port == 22) {
        host_port = host;
    } else {
        host_port = ssh_hostport(host, session->opts.port);
        SAFE_FREE(host);
        if (host_port == NULL) {
            ssh_set_error_oom(session);
            return NULL;
        }
    }

    return host_port;
}

/**
 * @internal
 *
 * @brief Free known hosts entries list
 *
 * @param[in] entry_list The list of ssh_knownhosts_entry items
 */
static void ssh_knownhosts_entries_free(struct ssh_list *entry_list)
{
    struct ssh_iterator *it = NULL;

    if (entry_list == NULL) {
        return;
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list)) {
        struct ssh_knownhosts_internal_entry *entry = NULL;

        entry = ssh_iterator_value(
            struct ssh_knownhosts_internal_entry *, it);
        ssh_knownhosts_internal_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    ssh_list_free(entry_list);
}

/**
 * @internal
 *
 * @brief Check which host keys should be preferred for the session.
 *
 * This checks the known_hosts file to find out which algorithms should be
 * preferred for the connection we are going to establish.
 *
 * @param[in]  session  The ssh session to use.
 *
 * @return A list of supported key types, NULL on error.
 */
struct ssh_list *ssh_known_hosts_get_algorithms(ssh_session session)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    char *host_port = NULL;
    size_t count;
    struct ssh_list *list = NULL;
    int list_error = 0;
    int rc;

    if (session->opts.knownhosts == NULL ||
        session->opts.global_knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return NULL;
        }
    }

    list = ssh_list_new();
    if (list == NULL) {
        ssh_set_error_oom(session);
        return NULL;
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        goto error;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.knownhosts,
                                      &entry_list);
    if (rc != 0) {
        SAFE_FREE(host_port);
        goto error;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.global_knownhosts,
                                      &entry_list);
    SAFE_FREE(host_port);
    if (rc != 0) {
        goto error;
    }

    if (entry_list == NULL) {
        goto error;
    }

    count = ssh_list_count(entry_list);
    if (count == 0) {
        goto error;
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list)) {
        struct ssh_iterator *it2 = NULL;
        struct ssh_knownhosts_internal_entry *entry = NULL;
        const char *algo = NULL;
        bool present = false;

        entry = ssh_iterator_value(
            struct ssh_knownhosts_internal_entry *, it);

        /* Revoked keys must never be offered as preferred algorithms */
        if (entry->marker == SSH_KNOWN_HOSTS_MARKER_REVOKED) {
            ssh_knownhosts_internal_entry_free(entry);
            ssh_list_remove(entry_list, it);
            continue;
        }

        algo = entry->entry.publickey->type_c;

        /* Check for duplicates */
        for (it2 = ssh_list_get_iterator(list);
             it2 != NULL;
             it2 = it2->next) {
            char *alg2 = ssh_iterator_value(char *, it2);
            int cmp = strcmp(alg2, algo);
            if (cmp == 0) {
                present = true;
                break;
            }
        }

        /* Add to the new list only if it is unique */
        if (!present) {
            rc = ssh_list_append(list, algo);
            if (rc != SSH_OK) {
               list_error = 1;
            }
        }

        ssh_knownhosts_internal_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }
    ssh_list_free(entry_list);
    if (list_error) {
        goto error;
    }

    return list;
error:
    ssh_knownhosts_entries_free(entry_list);
    ssh_list_free(list);
    return NULL;
}

/**
 * @internal
 *
 * @brief   Returns a static string containing a list of the signature types the
 * given key type can generate.
 *
 * @returns A static cstring containing the signature types the key is able to
 * generate separated by commas; NULL in case of error
 */
static const char *ssh_known_host_sigs_from_hostkey_type(enum ssh_keytypes_e type)
{
    switch (type) {
    case SSH_KEYTYPE_RSA:
        return "rsa-sha2-512,rsa-sha2-256,ssh-rsa";
    case SSH_KEYTYPE_ED25519:
        return "ssh-ed25519";
    case SSH_KEYTYPE_SK_ED25519:
        return "sk-ssh-ed25519@openssh.com";
#ifdef HAVE_ECC
    case SSH_KEYTYPE_ECDSA_P256:
        return "ecdsa-sha2-nistp256";
    case SSH_KEYTYPE_ECDSA_P384:
        return "ecdsa-sha2-nistp384";
    case SSH_KEYTYPE_ECDSA_P521:
        return "ecdsa-sha2-nistp521";
    case SSH_KEYTYPE_SK_ECDSA:
        return "sk-ecdsa-sha2-nistp256@openssh.com";
#else
    case SSH_KEYTYPE_ECDSA_P256:
    case SSH_KEYTYPE_ECDSA_P384:
    case SSH_KEYTYPE_ECDSA_P521:
        SSH_LOG(SSH_LOG_WARN, "ECDSA keys are not supported by this build");
        break;
#endif
    case SSH_KEYTYPE_UNKNOWN:
    default:
        SSH_LOG(SSH_LOG_TRACE,
                "The given type %d is not a base private key type "
                "or is unsupported",
                type);
    }

    return NULL;
}

/**
 * @internal
 *
 * @brief Get the host keys algorithms identifiers from the known_hosts files
 *
 * This expands the signatures types that can be generated from the keys types
 * present in the known_hosts files
 *
 * @param[in]  session  The ssh session to use.
 *
 * @return A newly allocated cstring containing a list of signature algorithms
 * that can be generated by the host using the keys listed in the known_hosts
 * files, NULL on error.
 */
char *ssh_known_hosts_get_algorithms_names(ssh_session session)
{
    char methods_buffer[256 + 1] = {0};
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    char *host_port = NULL;
    size_t count;
    bool needcomma = false;
    char *names = NULL;

    int rc;

    if (session->opts.knownhosts == NULL ||
        session->opts.global_knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return NULL;
        }
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return NULL;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.knownhosts,
                                      &entry_list);
    if (rc != 0) {
        SAFE_FREE(host_port);
        ssh_knownhosts_entries_free(entry_list);
        return NULL;
    }

    rc = ssh_known_hosts_read_entries(host_port,
                                      session->opts.global_knownhosts,
                                      &entry_list);
    SAFE_FREE(host_port);
    if (rc != 0) {
        ssh_knownhosts_entries_free(entry_list);
        return NULL;
    }

    if (entry_list == NULL) {
        return NULL;
    }

    count = ssh_list_count(entry_list);
    if (count == 0) {
        ssh_list_free(entry_list);
        return NULL;
    }

    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = ssh_list_get_iterator(entry_list))
    {
        struct ssh_knownhosts_internal_entry *entry = NULL;
        const char *algo = NULL;

        entry = ssh_iterator_value(
            struct ssh_knownhosts_internal_entry *, it);

        /* Revoked keys must never be offered as preferred algorithms */
        if (entry->marker == SSH_KNOWN_HOSTS_MARKER_REVOKED) {
            ssh_knownhosts_internal_entry_free(entry);
            ssh_list_remove(entry_list, it);
            continue;
        }

        algo = ssh_known_host_sigs_from_hostkey_type(
            entry->entry.publickey->type);
        if (algo == NULL) {
            ssh_knownhosts_internal_entry_free(entry);
            ssh_list_remove(entry_list, it);
            continue;
        }

        if (needcomma) {
            strlcat(methods_buffer, ",", sizeof(methods_buffer));
        }

        strlcat(methods_buffer, algo, sizeof(methods_buffer));
        needcomma = true;

        ssh_knownhosts_internal_entry_free(entry);
        ssh_list_remove(entry_list, it);
    }

    ssh_list_free(entry_list);

    names = ssh_remove_duplicates(methods_buffer);

    return names;
}

/**
 * @brief Parse a line from a known_hosts entry into a structure
 *
 * This parses a known_hosts entry into a structure with the key in a libssh
 * consumeable form. You can use the PKI key function to further work with it.
 *
 * @param[in]  hostname     The hostname to match the line to
 *
 * @param[in]  line         The line to compare and parse if we have a hostname
 *                          match.
 *
 * @param[in]  entry        A pointer to store the allocated known_hosts
 *                          entry structure. The user needs to free the memory
 *                          using SSH_KNOWNHOSTS_ENTRY_FREE().
 *
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_known_hosts_parse_line(const char *hostname,
                               const char *line,
                               struct ssh_knownhosts_entry **entry)
{
    struct ssh_knownhosts_entry *e = NULL;
    char *known_host = NULL;
    char *p = NULL;
    const char *cp = NULL;
    char *save_tok = NULL;
    enum ssh_keytypes_e key_type;
    int match = 0;
    int rc = SSH_OK;

    known_host = strdup(line);
    if (known_host == NULL) {
        return SSH_ERROR;
    }

    /* match pattern for hostname or hashed hostname */
    p = strtok_r(known_host, " ", &save_tok);
    if (p == NULL ) {
        free(known_host);
        return SSH_ERROR;
    }

    e = calloc(1, sizeof(struct ssh_knownhosts_entry));
    if (e == NULL) {
        free(known_host);
        return SSH_ERROR;
    }

    if (hostname != NULL) {
        char *host_port = NULL;
        char *q = NULL;

        /* Hashed */
        if (p[0] == '|') {
            match = match_hashed_hostname(hostname, p);
        }

        save_tok = NULL;

        for (q = strtok_r(p, ",", &save_tok);
             q != NULL;
             q = strtok_r(NULL, ",", &save_tok)) {
            int cmp;

            if (q[0] == '[' && hostname[0] != '[') {
                /* Corner case: We have standard port so we do not have
                 * hostname in square braces. But the pattern is enclosed
                 * in braces with, possibly standard or wildcard, port.
                 * We need to test against [host]:port pair here.
                 */
                if (host_port == NULL) {
                    host_port = ssh_hostport(hostname, 22);
                    if (host_port == NULL) {
                        rc = SSH_ERROR;
                        goto out;
                    }
                }

                cmp = match_hostname(host_port, q, strlen(q));
            } else {
                cmp = match_hostname(hostname, q, strlen(q));
            }
            if (cmp == 1) {
                match = 1;
                break;
            }
        }
        free(host_port);

        if (match == 0) {
            rc = SSH_AGAIN;
            goto out;
        }

        e->hostname = strdup(hostname);
        if (e->hostname == NULL) {
            rc = SSH_ERROR;
            goto out;
        }
    }

    /* Restart parsing */
    SAFE_FREE(known_host);
    known_host = strdup(line);
    if (known_host == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    save_tok = NULL;

    p = strtok_r(known_host, " ", &save_tok);
    if (p == NULL ) {
        rc = SSH_ERROR;
        goto out;
    }

    e->unparsed = strdup(p);
    if (e->unparsed == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    /* pubkey type */
    p = strtok_r(NULL, " ", &save_tok);
    if (p == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    key_type = ssh_key_type_from_name(p);
    if (key_type == SSH_KEYTYPE_UNKNOWN) {
        SSH_LOG(SSH_LOG_TRACE, "key type '%s' unknown!", p);
        rc = SSH_ERROR;
        goto out;
    }

    /* public key */
    p = strtok_r(NULL, " ", &save_tok);
    if (p == NULL) {
        rc = SSH_ERROR;
        goto out;
    }

    rc = ssh_pki_import_pubkey_base64(p,
                                      key_type,
                                      &e->publickey);
    if (rc != SSH_OK) {
        SSH_LOG(SSH_LOG_TRACE,
                "Failed to parse %s key for entry: %s!",
                ssh_key_type_to_char(key_type),
                e->unparsed);
        goto out;
    }

    /* comment */
    p = strtok_r(NULL, " ", &save_tok);
    if (p != NULL) {
        cp = strstr(line, p);
        if (cp != NULL) {
            e->comment = strdup(cp);
            if (e->comment == NULL) {
                rc = SSH_ERROR;
                goto out;
            }
        }
    }

    *entry = e;
    SAFE_FREE(known_host);

    return SSH_OK;
out:
    SAFE_FREE(known_host);
    ssh_knownhosts_entry_free(e);
    return rc;
}

/**
 * @brief Check if the set hostname and port match an entry in known_hosts.
 *
 * This check if the set hostname and port have an entry in the known_hosts file.
 * You need to set at least the hostname using ssh_options_set().
 *
 * @param[in]  session  The session with the values set to check.
 *
 * @return A ssh_known_hosts_e return value.
 */
enum ssh_known_hosts_e ssh_session_has_known_hosts_entry(ssh_session session)
{
    struct ssh_list *entry_list = NULL;
    char *host_port = NULL;
    bool global_known_hosts_found = false;
    bool known_hosts_found = false;
    int rc;

    if (session->opts.knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Cannot find a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
        }
    }

    if (session->opts.knownhosts == NULL &&
        session->opts.global_knownhosts == NULL) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "No path set for a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
    }

    if (session->opts.knownhosts != NULL) {
        known_hosts_found = ssh_file_readaccess_ok(session->opts.knownhosts);
        if (!known_hosts_found) {
            SSH_LOG(SSH_LOG_TRACE, "Cannot access file %s",
                    session->opts.knownhosts);
        }
    }

    if (session->opts.global_knownhosts != NULL) {
        global_known_hosts_found =
                ssh_file_readaccess_ok(session->opts.global_knownhosts);
        if (!global_known_hosts_found) {
            SSH_LOG(SSH_LOG_TRACE, "Cannot access file %s",
                    session->opts.global_knownhosts);
        }
    }

    if ((!known_hosts_found) && (!global_known_hosts_found)) {
        ssh_set_error(session,
                      SSH_REQUEST_DENIED,
                      "Cannot find a known_hosts file");

        return SSH_KNOWN_HOSTS_NOT_FOUND;
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return SSH_KNOWN_HOSTS_ERROR;
    }

    if (known_hosts_found) {
        rc = ssh_known_hosts_read_entries(host_port,
                                          session->opts.knownhosts,
                                          &entry_list);
        if (rc != 0) {
            SAFE_FREE(host_port);
            ssh_knownhosts_entries_free(entry_list);
            return SSH_KNOWN_HOSTS_ERROR;
        }
    }

    if (global_known_hosts_found) {
        rc = ssh_known_hosts_read_entries(host_port,
                                          session->opts.global_knownhosts,
                                          &entry_list);
        if (rc != 0) {
            SAFE_FREE(host_port);
            ssh_knownhosts_entries_free(entry_list);
            return SSH_KNOWN_HOSTS_ERROR;
        }
    }

    SAFE_FREE(host_port);

    if (ssh_list_count(entry_list) == 0) {
        ssh_list_free(entry_list);
        return SSH_KNOWN_HOSTS_UNKNOWN;
    }

    ssh_knownhosts_entries_free(entry_list);

    return SSH_KNOWN_HOSTS_OK;
}

/**
 * @brief Export the current session information to a known_hosts string.
 *
 * This exports the current information of a session which is connected so a
 * ssh server into an entry line which can be added to a known_hosts file.
 *
 * @param[in]  session  The session with information to export.
 *
 * @param[in]  pentry_string A pointer to a string to store the allocated
 *                           line of the entry. The user must free it using
 *                           ssh_string_free_char().
 *
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_session_export_known_hosts_entry(ssh_session session,
                                         char **pentry_string)
{
    ssh_key server_pubkey = NULL;
    char *host = NULL;
    char entry_buf[MAX_LINE_SIZE] = {0};
    char *b64_key = NULL;
    int rc;

    if (pentry_string == NULL) {
        ssh_set_error_invalid(session);
        return SSH_ERROR;
    }

    if (session->opts.host == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "Can't create known_hosts entry - hostname unknown");
        return SSH_ERROR;
    }

    host = ssh_session_get_host_port(session);
    if (host == NULL) {
        return SSH_ERROR;
    }

    if (session->current_crypto == NULL) {
        ssh_set_error(session, SSH_FATAL,
                      "No current crypto context, please connect first");
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    server_pubkey = ssh_dh_get_current_server_publickey(session);
    if (server_pubkey == NULL){
        ssh_set_error(session, SSH_FATAL, "No public key present");
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    rc = ssh_pki_export_pubkey_base64(server_pubkey, &b64_key);
    if (rc < 0) {
        SAFE_FREE(host);
        return SSH_ERROR;
    }

    snprintf(entry_buf, sizeof(entry_buf),
                "%s %s %s\n",
                host,
                server_pubkey->type_c,
                b64_key);

    SAFE_FREE(host);
    SAFE_FREE(b64_key);

    *pentry_string = strdup(entry_buf);
    if (*pentry_string == NULL) {
        return SSH_ERROR;
    }

    return SSH_OK;
}

/**
 * @brief Adds the currently connected server to the user known_hosts file.
 *
 * This adds the currently connected server to the known_hosts file by
 * appending a new line at the end. The global known_hosts file is considered
 * read-only so it is not touched by this function.
 *
 * @param[in]  session  The session to use to write the entry.
 *
 * @return SSH_OK on success, SSH_ERROR otherwise.
 */
int ssh_session_update_known_hosts(ssh_session session)
{
    FILE *fp = NULL;
    char *entry = NULL;
    char *dir = NULL;
    size_t nwritten;
    size_t len;
    int rc;
    char err_msg[SSH_ERRNO_MSG_MAX] = {0};

    if (session->opts.knownhosts == NULL) {
        rc = ssh_options_apply(session);
        if (rc != SSH_OK) {
            ssh_set_error(session, SSH_FATAL, "Can't find a known_hosts file");
            return SSH_ERROR;
        }
    }

    errno = 0;
    fp = fopen(session->opts.knownhosts, "a");
    if (fp == NULL) {
        if (errno == ENOENT) {
            dir = ssh_dirname(session->opts.knownhosts);
            if (dir == NULL) {
                ssh_set_error(session, SSH_FATAL, "%s",
                              ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
                return SSH_ERROR;
            }

            rc = ssh_mkdirs(dir, 0700);
            if (rc < 0) {
                ssh_set_error(session, SSH_FATAL,
                              "Cannot create %s directory: %s",
                              dir,
                              ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
                SAFE_FREE(dir);
                return SSH_ERROR;
            }
            SAFE_FREE(dir);

            errno = 0;
            fp = fopen(session->opts.knownhosts, "a");
            if (fp == NULL) {
                ssh_set_error(session, SSH_FATAL,
                              "Couldn't open known_hosts file %s"
                              " for appending: %s",
                              session->opts.knownhosts,
                              ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
                return SSH_ERROR;
            }
        } else {
            ssh_set_error(session,
                          SSH_FATAL,
                          "Couldn't open known_hosts file %s for appending: %s",
                          session->opts.knownhosts,
                          ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
            return SSH_ERROR;
        }
    }

    rc = ssh_session_export_known_hosts_entry(session, &entry);
    if (rc != SSH_OK) {
        fclose(fp);
        return rc;
    }

    len = strlen(entry);
    nwritten = fwrite(entry, sizeof(char), len, fp);
    SAFE_FREE(entry);
    if (nwritten != len || ferror(fp)) {
        ssh_set_error(session, SSH_FATAL,
                      "Couldn't append to known_hosts file %s: %s",
                      session->opts.knownhosts,
                      ssh_strerror(errno, err_msg, SSH_ERRNO_MSG_MAX));
        fclose(fp);
        return SSH_ERROR;
    }

    fclose(fp);
    return SSH_OK;
}

static enum ssh_known_hosts_e
ssh_known_hosts_check_server_key(ssh_session session,
                                 const char *hosts_entry,
                                 const char *filename,
                                 ssh_key server_key,
                                 struct ssh_knownhosts_entry **pentry)
{
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    enum ssh_known_hosts_e found = SSH_KNOWN_HOSTS_UNKNOWN;
    enum ssh_known_hosts_e cert_failure = SSH_KNOWN_HOSTS_UNKNOWN;
    int rc;

    rc = ssh_known_hosts_read_entries(hosts_entry,
                                      filename,
                                      &entry_list);
    if (rc != 0) {
        ssh_knownhosts_entries_free(entry_list);
        return SSH_KNOWN_HOSTS_ERROR;
    }

    it = ssh_list_get_iterator(entry_list);
    if (it == NULL) {
        ssh_knownhosts_entries_free(entry_list);
        return SSH_KNOWN_HOSTS_UNKNOWN;
    }

    /*
     * First pass: revocation. Revoked entries take precedence over every
     * other kind of entry, independent of their order in the file. A revoked
     * plain key matches the presented key directly; a revoked certificate
     * matches an identical presented certificate.
     */
    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = it->next) {
        struct ssh_knownhosts_internal_entry *ientry =
            ssh_iterator_value(struct ssh_knownhosts_internal_entry *, it);
        struct ssh_knownhosts_entry *entry = &ientry->entry;
        bool revoked_match = false;

        if (ientry->marker != SSH_KNOWN_HOSTS_MARKER_REVOKED) {
            continue;
        }

        if (is_cert_type(ssh_key_type(entry->publickey))) {
            if (is_cert_type(ssh_key_type(server_key)) &&
                ssh_key_cmp(server_key,
                            entry->publickey,
                            SSH_KEY_CMP_CERTIFICATE) == 0) {
                revoked_match = true;
            }
        } else if (ssh_key_cmp(server_key,
                               entry->publickey,
                               SSH_KEY_CMP_PUBLIC) == 0) {
            revoked_match = true;
        }

        if (revoked_match) {
            found = SSH_KNOWN_HOSTS_REVOKED;
            goto out;
        }
    }

    /* Second pass: ordinary entries and certificate authorities. */
    for (it = ssh_list_get_iterator(entry_list);
         it != NULL;
         it = it->next) {
        struct ssh_knownhosts_internal_entry *ientry =
            ssh_iterator_value(struct ssh_knownhosts_internal_entry *, it);
        struct ssh_knownhosts_entry *entry = &ientry->entry;
        int cmp;

        if (ientry->marker == SSH_KNOWN_HOSTS_MARKER_REVOKED) {
            continue;
        }

        /* Certificate authority entries only validate certificates. The key
         * stored in the @cert-authority line is the plain CA public key. */
        if (ientry->marker ==
            SSH_KNOWN_HOSTS_MARKER_CERT_AUTHORITY) {
            enum ssh_known_hosts_e cert_rv;

            if (!is_cert_type(ssh_key_type(server_key)) ||
                is_cert_type(ssh_key_type(entry->publickey))) {
                /* No certificate presented, or the CA entry is itself a
                 * certificate which we cannot use as a trust anchor */
                continue;
            }

            cert_rv = ssh_known_hosts_verify_cert(session,
                                                  hosts_entry,
                                                  server_key,
                                                  server_key,
                                                  entry->publickey);
            if (cert_rv == SSH_KNOWN_HOSTS_OK) {
                found = SSH_KNOWN_HOSTS_OK;
                if (pentry != NULL) {
                    struct ssh_knownhosts_entry *detached;
                    /* Remove first so no iterator references the wrapper
                     * while it is being detached. */
                    ssh_list_remove(entry_list, it);
                    detached = ssh_knownhosts_entry_detach(ientry);
                    if (detached != NULL) {
                        *pentry = detached;
                    } else {
                        /* Allocation failure: fall back to in-list cleanup */
                        ssh_knownhosts_internal_entry_free(ientry);
                    }
                }
                goto out;
            }

            /* Expiry beats a generic CA failure: report the most specific
             * reason once all CA entries have been tried. */
            if (cert_failure != SSH_KNOWN_HOSTS_CERT_EXPIRED) {
                cert_failure = cert_rv;
            }
            continue;
        }

        /* Plain entries: the classical key comparison */
        cmp = ssh_key_cmp(server_key,
                          entry->publickey,
                          SSH_KEY_CMP_PUBLIC);
        if (cmp == 0) {
            found = SSH_KNOWN_HOSTS_OK;
            if (pentry != NULL) {
                struct ssh_knownhosts_entry *detached;
                ssh_list_remove(entry_list, it);
                detached = ssh_knownhosts_entry_detach(ientry);
                if (detached != NULL) {
                    *pentry = detached;
                } else {
                    ssh_knownhosts_internal_entry_free(ientry);
                }
            }
            goto out;
        }

        if (ssh_key_type(server_key) ==
            ssh_key_type(entry->publickey)) {
            found = SSH_KNOWN_HOSTS_CHANGED;
            continue;
        }

        if (found != SSH_KNOWN_HOSTS_CHANGED) {
            found = SSH_KNOWN_HOSTS_OTHER;
        }
    }

    if (found != SSH_KNOWN_HOSTS_OK &&
        cert_failure != SSH_KNOWN_HOSTS_UNKNOWN &&
        (found == SSH_KNOWN_HOSTS_UNKNOWN ||
         found == SSH_KNOWN_HOSTS_OTHER)) {
        /* The host was only reachable through certificates: surface the
         * certificate verification failure rather than a plain mismatch. */
        found = cert_failure;
    }

out:
    if (ssh_known_hosts_result_is_fatal(found)) {
        ssh_known_hosts_set_fatal_error(session, found);
    }

    ssh_knownhosts_entries_free(entry_list);

    return found;
}

static bool ssh_known_hosts_should_continue_unsafe(ssh_session session,
                                                   enum ssh_known_hosts_e rv)
{
    return session->opts.StrictHostKeyChecking == SSH_STRICT_HOSTKEY_OFF &&
           (rv == SSH_KNOWN_HOSTS_CHANGED || rv == SSH_KNOWN_HOSTS_OTHER);
}

/**
 * @brief Get the known_hosts entry for the currently connected session.
 *
 * @param[in]  session  The session to validate.
 *
 * @param[in]  pentry   A pointer to store the allocated known hosts entry.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *                                     Note: When GSSAPI key exchange is used,
 *                                     host keys may change frequently and
 *                                     without advance warning per RFC 4462.
 *                                     Clients SHOULD NOT issue strong warnings
 *                                     or abort when this occurs with GSSAPI
 *                                     key exchange.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.
 *                                     This is also returned when GSSAPI key
 *                                     exchange with null hostkey is negotiated,
 *                                     as there is no host key to verify, or when
 *                                     the server does not send the host key despite
 *                                     negotiating a non-null host key algorithm.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an error checking the host.
 *
 * @see ssh_knownhosts_entry_free()
 */
enum ssh_known_hosts_e
ssh_session_get_known_hosts_entry(ssh_session session,
                                  struct ssh_knownhosts_entry **pentry)
{
    enum ssh_known_hosts_e old_rv, rv = SSH_KNOWN_HOSTS_UNKNOWN;
    int rc;

    if (pentry != NULL) {
        *pentry = NULL;
    }

    if (session->opts.knownhosts == NULL) {
        if (ssh_options_apply(session) < 0) {
            ssh_set_error(session,
                          SSH_REQUEST_DENIED,
                          "Can't find a known_hosts file");

            return SSH_KNOWN_HOSTS_NOT_FOUND;
        }
    }

    rv = ssh_session_get_known_hosts_entry_file(session,
                                                session->opts.knownhosts,
                                                pentry);
    if (rv == SSH_KNOWN_HOSTS_OK) {
        /* We already found a match in the first file: return */
        return rv;
    }

    /* Revoked keys and certificate failures are fatal: they must never be
     * overridden by entries in the global known_hosts file or by relaxed
     * strict host key checking. */
    if (ssh_known_hosts_result_is_fatal(rv)) {
        return rv;
    }

    old_rv = rv;
    rv = ssh_session_get_known_hosts_entry_file(session,
                                                session->opts.global_knownhosts,
                                                pentry);

    if (ssh_known_hosts_should_continue_unsafe(session, rv)) {
        ssh_known_hosts_continue_unsafe(session);
        return SSH_KNOWN_HOSTS_OK;
    }

    /* Fatal results from the global file are reported as well */
    if (ssh_known_hosts_result_is_fatal(rv)) {
        return rv;
    }

    /* If the global file did not help, report the result from the user file. */
    if (rv == SSH_KNOWN_HOSTS_UNKNOWN || rv == SSH_KNOWN_HOSTS_NOT_FOUND) {
        if (ssh_known_hosts_should_continue_unsafe(session, old_rv)) {
            ssh_known_hosts_continue_unsafe(session);
            return SSH_KNOWN_HOSTS_OK;
        }

        if ((old_rv == SSH_KNOWN_HOSTS_UNKNOWN ||
             old_rv == SSH_KNOWN_HOSTS_NOT_FOUND) &&
            (session->opts.StrictHostKeyChecking == SSH_STRICT_HOSTKEY_OFF ||
             session->opts.StrictHostKeyChecking ==
                 SSH_STRICT_HOSTKEY_ACCEPT_NEW)) {
            rc = ssh_session_update_known_hosts(session);
            if (rc != SSH_OK) {
                return SSH_KNOWN_HOSTS_ERROR;
            }

            rv =
                ssh_session_get_known_hosts_entry_file(session,
                                                       session->opts.knownhosts,
                                                       pentry);
            if (rv == SSH_KNOWN_HOSTS_UNKNOWN ||
                rv == SSH_KNOWN_HOSTS_NOT_FOUND) {
                return SSH_KNOWN_HOSTS_OK;
            }

            return rv;
        }

        return old_rv;
    }

    /* We found some match: return it */
    return rv;

}

/**
 * @internal
 *
 * @brief Get the known_hosts entry for the current connected session
 *        from the given known_hosts file.
 *
 * @param[in]  session  The session to validate.
 *
 * @param[in]  filename The filename to parse.
 *
 * @param[in]  pentry   A pointer to store the allocated known hosts entry.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an error checking the host.
 *
 * @see ssh_knownhosts_entry_free()
 */
enum ssh_known_hosts_e
ssh_session_get_known_hosts_entry_file(ssh_session session,
                                       const char *filename,
                                       struct ssh_knownhosts_entry **pentry)
{
    ssh_key server_pubkey = NULL;
    char *host_port = NULL;
    enum ssh_known_hosts_e found = SSH_KNOWN_HOSTS_UNKNOWN;

    server_pubkey = ssh_dh_get_current_server_publickey(session);
    if (server_pubkey == NULL) {
#ifdef WITH_GSSAPI
        /* After GSSAPI key exchange, sending the host key is optional
         * because the server is already authenticated via Kerberos.
         * Return SSH_KNOWN_HOSTS_UNKNOWN if there is no host key
         * to let the application decide how to handle this case. */
        if (ssh_session_kex_is_gss(session)) {
            return SSH_KNOWN_HOSTS_UNKNOWN;
        }
#endif
        ssh_set_error(session,
                      SSH_FATAL,
                      "ssh_session_is_known_host called without a "
                      "server_key!");

        return SSH_KNOWN_HOSTS_ERROR;
    }

    host_port = ssh_session_get_host_port(session);
    if (host_port == NULL) {
        return SSH_KNOWN_HOSTS_ERROR;
    }

    found = ssh_known_hosts_check_server_key(session,
                                             host_port,
                                             filename,
                                             server_pubkey,
                                             pentry);
    SAFE_FREE(host_port);

    return found;
}

/**
 * @brief Check if the servers public key for the connected session is known.
 *
 * This checks if we already know the public key of the server we want to
 * connect to. This allows to detect if there is a MITM attach going on
 * of if there have been changes on the server we don't know about.
 *
 * @param[in]  session  The SSH to validate.
 *
 * @returns SSH_KNOWN_HOSTS_OK:        The server is known and has not changed.\n
 *          SSH_KNOWN_HOSTS_CHANGED:   The server key has changed. Either you
 *                                     are under attack or the administrator
 *                                     changed the key. You HAVE to warn the
 *                                     user about a possible attack.\n
 *          SSH_KNOWN_HOSTS_OTHER:     The server gave use a key of a type while
 *                                     we had an other type recorded. It is a
 *                                     possible attack.\n
 *          SSH_KNOWN_HOSTS_UNKNOWN:   The server is unknown. User should
 *                                     confirm the public key hash is correct.\n
 *          SSH_KNOWN_HOSTS_NOT_FOUND: The known host file does not exist. The
 *                                     host is thus unknown. File will be
 *                                     created if host key is accepted.\n
 *          SSH_KNOWN_HOSTS_ERROR:     There had been an error checking the host.
 */
enum ssh_known_hosts_e ssh_session_is_known_server(ssh_session session)
{
    return ssh_session_get_known_hosts_entry(session, NULL);
}

/** @} */
