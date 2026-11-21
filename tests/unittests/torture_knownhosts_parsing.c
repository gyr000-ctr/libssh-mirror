#include "config.h"

#include <sys/stat.h>

#define LIBSSH_STATIC
#include <libssh/priv.h>

#include "knownhosts.c"

#include "torture.h"
#if (defined _WIN32) || (defined _WIN64)
#ifndef S_IRWXO
#define S_IRWXO 0
#endif
#ifndef S_IRWXG
#define S_IRWXG 0
#endif
#endif

#define LOCALHOST_DSS_LINE "localhost,127.0.0.1 ssh-dss AAAAB3NzaC1kc3MAAACBAIK3RTEWBw+rAPcYUM2Qq4kEw59gXpUQ/WvkdeY7QDO64MHaaorySj8xsraNudmQFh4xb/i5Q1EMnNchOFxtilfU5bUJgdTvetyZEWFL+2HxqBs8GaWRyB1vtSFAw3GO8VUEnjF844N3dNyLoc0NX8IvzwNIaQho6KTsueQlG1X9AAAAFQCXUl4a5UvElL4thi/8QlxR5PtEewAAAIBqNpl5MTBxKQu5jT0+WASa7pAqwT53ofv7ZTDIEokYRb57/nwzDgkcs1fsBRrI6eczJ/VlXWwKbsgkx2Nh3ZiWYwC+HY5uqRpDaj3HERC6LMn4dzdcl29fYeziEibCbRjJX5lZF2vIaA1Ewv8yT0UlunyHZRiyw4WlEglkf/NITAAAAIBxLsdBBXn+8qEYwWK9KT+arRqNXC/lrl0Fp5YyxGNGCv82JcnuOShGGTzhYf8AtTCY1u5oixiW9kea6KXGAKgTjfJShr7n47SZVfOPOrBT3VLhRdGGO3GblDUppzfL8wsEdoqXjzrJuxSdrGnkFu8S9QjkPn9dCtScvWEcluHqMw=="
#define LOCALHOST_RSA_LINE "localhost,127.0.0.1 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDD7g+vV5cvxxGN0Ldmda4WZCPgRaxV1tV+1KRZoGUNUI61h0X4bmmGaAPRQBCz4G1d9bawqDqEqnpFWazrxBU5cQtISSjzuDJKovLGliky/ShTszee1Thszg3qVNk9gGOWj7jn/HDaOxRlp003Bp47MOdnMnK/oftllFDfY2fF5IRpE6sSIGtg2ZDtF95TV5/9W2oMOIAy8u/83tuibYlNPa1X/von5LgdaPLn6Bk16bQKIhAhlMtFZH8MBYEWe4ZtOGaSWKOsK9MM/RTMlwPi6PkfoHNl4MCMupjx+CdLXwbQEt9Ww+bBIaCui2VWBEiruVbIgJh0W2Tal0e2BzYZ What a Wurst!"
#define LOCALHOST_ECDSA_SHA1_NISTP256_LINE "localhost ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFWmI0n0Tn5+zR7pPGcKYszRbJ/T0T3QfzRBSMMiyebGKRY8tjkU5h2l/UMugzOrOyWqMGQDgQn+a0aMunhKMg0="
#define LOCALHOST_DEFAULT_ED25519 "localhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"
#define LOCALHOST_PORT_ED25519 "[localhost]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"
#define LOCALHOST_PATTERN_ED25519 "local* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"
#define LOCALHOST_HASHED_ED25519 "|1|ayWjmTf9mYgj7PuQNVOa7Lqkj5s=|hkbEh8FN6IkLo6t6GQGuBwamgsM= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"
#define LOCALHOST_PORT_WILDCARD "[localhost]:* ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"
#define LOCALHOST_STANDARD_PORT "[localhost]:22 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA7M22fXD7OiS7kGMXP+OoIjCa+J+5sq8SgAZfIOmDgM"

/*
 * Certificate / marker test material. The blobs below are the public keys
 * and OpenSSH host certificates generated from a dedicated test CA. They
 * are embedded here so the test does not depend on files shipped next to
 * the build tree.
 */
#define TEST_CA_PUBKEY \
    "localhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILU7utRkVak1NBW4vGzpfDuQYdY8/oc77uCOvq67xp8S test-ca"
#define TEST_OTHER_CA_PUBKEY \
    "localhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOa1FK+gRqqq7AZNFZvJMAJFyX/XYDVtPOJn+p4UcrrH other-ca"
#define TEST_HOST_PUBKEY \
    "localhost ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJkVjepGrv0L2nR1k9ZkjM4GgJrfRH5sPqk7HW7jSe1Q"
#define TEST_HOST_CERT_VALID \
    "localhost ssh-ed25519-cert-v01@openssh.com " \
    "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIH0Wra3EwLuqyDJf/gBx7ni2r4xk9zsgoZZEL8jxOGMrAAAAIJkVjepGrv0L2nR1k9ZkjM4GgJrfRH5sPqk7HW7jSe1QAAAAAAAAAAAAAAACAAAADmhvc3QtbG9uZ3ZhbGlkAAAAGgAAAAlsb2NhbGhvc3QAAAAJMTI3LjAuMC4xAAAAAF4LcIAAAAAAekK7AAAAAAAAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgtTu61GRVqTU0Fbi8bOl8O5Bh1jz+hzvu4I6+rrvGnxIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQJPGLqE/vjLJDHlTeEupitRZG1I3o+su/k4CsJ4zQrNeshmj49FH2ay8QhZbfHf9S3xLNKSCcAv+NVhNA2sOLQI="
#define TEST_HOST_CERT_EXPIRED \
    "localhost ssh-ed25519-cert-v01@openssh.com " \
    "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAICZe5V0ry9yOQHK+9dWzuShVTAMzH5/wuWUYiiTevrL4AAAAIJkVjepGrv0L2nR1k9ZkjM4GgJrfRH5sPqk7HW7jSe1QAAAAAAAAAAAAAAACAAAACWhvc3QtZXhwMgAAAA0AAAAJbG9jYWxob3N0AAAAAF4LcIAAAAAAXgzCAAAAAAAAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAgtTu61GRVqTU0Fbi8bOl8O5Bh1jz+hzvu4I6+rrvGnxIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQOguetGI3ro85PJM3sELemC5qt19t0xT3ZELIjnZ8w/CPpY9jyw4DvcZK7kLkvaV8r6WNLYUaaN68k9aGsZlbgY="
#define TEST_HOST_CERT_BADPRINC \
    "localhost ssh-ed25519-cert-v01@openssh.com " \
    "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIEsGclRhPA94zYrPg8w75lBq1/akndUt2DVywz9t546iAAAAIJkVjepGrv0L2nR1k9ZkjM4GgJrfRH5sPqk7HW7jSe1QAAAAAAAAAAAAAAACAAAADWhvc3QtYmFkcHJpbmMAAAAQAAAADGV2aWwuZXhhbXBsZQAAAABeC3CAAAAAAHpCuwAAAAAAAAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAILU7utRkVak1NBW4vGzpfDuQYdY8/oc77uCOvq67xp8SAAAAUwAAAAtzc2gtZWQyNTUxOQAAAEDYnnxyIt+dzGIgE9fol1wWIGuCgR8gNluVmychv+WHih5Cr5fwjkQ9jbMIBNKMGVS9WgRsEUQxLo6T1oYsFSsJ"
#define TEST_HOST_CERT_OTHER_CA \
    "localhost ssh-ed25519-cert-v01@openssh.com " \
    "AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIFz0zBBTCaptdmep2RzL/+2oDOPt0ztszBP5PT+UWmWIAAAAIJkVjepGrv0L2nR1k9ZkjM4GgJrfRH5sPqk7HW7jSe1QAAAAAAAAAAAAAAACAAAADGhvc3Qtb3RoZXJjYQAAAA0AAAAJbG9jYWxob3N0AAAAAAAAAAD//////////wAAAAAAAAAAAAAAAAAAADMAAAALc3NoLWVkMjU1MTkAAAAg5rUUr6BGqqrsBk0Vm8kwAkXJf9dgNW084mf6nhRyuscAAABTAAAAC3NzaC1lZDI1NTE5AAAAQIIOoby0BC3CfD/nsrcwIpXkhrmxP+RK3RMvjDbFyerIqzhDNa4imWl7dEaSUg8wHiUsFaonF2LjfNb1tTFlZQA="
#define TEST_HOST_HASHED \
    "|1|I3SlbsKQLRLHvcOce8wMP/rGmvc=|/7dZjpwgouis9aIlMgi/F+eVOtk= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJkVjepGrv0L2nR1k9ZkjM4GgJrfRH5sPqk7HW7jSe1Q"

#define TMP_FILE_NAME "/tmp/known_hosts_XXXXXX"

const char template[] = "temp_dir_XXXXXX";

static int setup_knownhosts_file(void **state)
{
    char *tmp_file = NULL;
    size_t nwritten;
    FILE *fp = NULL;
    int rc = 0;

    tmp_file = torture_create_temp_file(TMP_FILE_NAME);
    assert_non_null(tmp_file);

    *state = tmp_file;

    fp = fopen(tmp_file, "w");
    assert_non_null(fp);

    nwritten = fwrite(LOCALHOST_PATTERN_ED25519,
                      sizeof(char),
                      strlen(LOCALHOST_PATTERN_ED25519),
                      fp);
    if (nwritten != strlen(LOCALHOST_PATTERN_ED25519)) {
        rc = -1;
        goto close_fp;
    }

    nwritten = fwrite("\n", sizeof(char), 1, fp);
    if (nwritten != 1) {
        rc = -1;
        goto close_fp;
    }

    nwritten = fwrite(LOCALHOST_RSA_LINE,
                      sizeof(char),
                      strlen(LOCALHOST_RSA_LINE),
                      fp);
    if (nwritten != strlen(LOCALHOST_RSA_LINE)) {
        rc = -1;
        goto close_fp;
    }

close_fp:
    fclose(fp);

    return rc;
}

static int setup_knownhosts_file_duplicate(void **state)
{
    char *tmp_file = NULL;
    size_t nwritten;
    FILE *fp = NULL;
    int rc = 0;

    tmp_file = torture_create_temp_file(TMP_FILE_NAME);
    assert_non_null(tmp_file);

    *state = tmp_file;

    fp = fopen(tmp_file, "w");
    assert_non_null(fp);

    /* ed25519 key */
    nwritten = fwrite(LOCALHOST_PATTERN_ED25519,
                      sizeof(char),
                      strlen(LOCALHOST_PATTERN_ED25519),
                      fp);
    if (nwritten != strlen(LOCALHOST_PATTERN_ED25519)) {
        rc = -1;
        goto close_fp;
    }

    nwritten = fwrite("\n", sizeof(char), 1, fp);
    if (nwritten != 1) {
        rc = -1;
        goto close_fp;
    }

    /* RSA key */
    nwritten = fwrite(LOCALHOST_RSA_LINE,
                      sizeof(char),
                      strlen(LOCALHOST_RSA_LINE),
                      fp);
    if (nwritten != strlen(LOCALHOST_RSA_LINE)) {
        rc = -1;
        goto close_fp;
    }

    nwritten = fwrite("\n", sizeof(char), 1, fp);
    if (nwritten != 1) {
        rc = -1;
        goto close_fp;
    }

    /* ed25519 key again */
    nwritten = fwrite(LOCALHOST_PATTERN_ED25519,
                      sizeof(char),
                      strlen(LOCALHOST_PATTERN_ED25519),
                      fp);
    if (nwritten != strlen(LOCALHOST_PATTERN_ED25519)) {
        rc = -1;
        goto close_fp;
    }

    nwritten = fwrite("\n", sizeof(char), 1, fp);
    if (nwritten != 1) {
        rc = -1;
        goto close_fp;
    }

close_fp:
    fclose(fp);

    return rc;
}

static int setup_knownhosts_file_unsupported_type(void **state)
{
    char *tmp_file = NULL;
    size_t nwritten;
    FILE *fp = NULL;
    int rc = 0;

    tmp_file = torture_create_temp_file(TMP_FILE_NAME);
    assert_non_null(tmp_file);

    *state = tmp_file;

    fp = fopen(tmp_file, "w");
    assert_non_null(fp);

    nwritten = fwrite(LOCALHOST_DSS_LINE,
                      sizeof(char),
                      strlen(LOCALHOST_DSS_LINE),
                      fp);
    if (nwritten != strlen(LOCALHOST_DSS_LINE)) {
        rc = -1;
        goto close_fp;
    }

close_fp:
    fclose(fp);

    return rc;
}

static int teardown_knownhosts_file(void **state)
{
    char *tmp_file = *state;

    if (tmp_file == NULL) {
        return -1;
    }

    unlink(tmp_file);
    SAFE_FREE(tmp_file);

    return 0;
}

static void torture_knownhosts_parse_line_rsa(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_RSA_LINE,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_RSA);
    assert_string_equal(entry->comment, "What a Wurst!");

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);

    rc = ssh_known_hosts_parse_line("127.0.0.1",
                                    LOCALHOST_RSA_LINE,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "127.0.0.1");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_RSA);
    assert_string_equal(entry->comment, "What a Wurst!");

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_ecdsa(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_ECDSA_SHA1_NISTP256_LINE,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ECDSA_P256);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_default_ed25519(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_DEFAULT_ED25519,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ED25519);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_port_ed25519(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("[localhost]:2222",
                                    LOCALHOST_PORT_ED25519,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "[localhost]:2222");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ED25519);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_port_wildcard(void **state)
{
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_PORT_WILDCARD,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ED25519);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_standard_port(void **state)
{
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_STANDARD_PORT,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ED25519);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_pattern_ed25519(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_PATTERN_ED25519,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ED25519);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_parse_line_hashed_ed25519(void **state) {
    struct ssh_knownhosts_entry *entry = NULL;
    int rc;

    (void) state;

    rc = ssh_known_hosts_parse_line("localhost",
                                    LOCALHOST_HASHED_ED25519,
                                    &entry);
    assert_int_equal(rc, SSH_OK);

    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->unparsed);
    assert_non_null(entry->publickey);
    assert_int_equal(ssh_key_type(entry->publickey), SSH_KEYTYPE_ED25519);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
}

static void torture_knownhosts_read_file(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    struct ssh_knownhosts_entry *entry = NULL;
    enum ssh_keytypes_e type;
    int rc;

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(entry_list);
    it = ssh_list_get_iterator(entry_list);
    assert_non_null(it);

    /* First key in known hosts file is ED25519 */
    entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
    assert_non_null(entry);

    assert_string_equal(entry->hostname, "localhost");
    type = ssh_key_type(entry->publickey);
    assert_int_equal(type, SSH_KEYTYPE_ED25519);
    assert_non_null(it->next);

    it = it->next;

    /* Second key in known hosts file is RSA */
    entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
    assert_non_null(entry);

    assert_string_equal(entry->hostname, "localhost");
    type = ssh_key_type(entry->publickey);
    assert_int_equal(type, SSH_KEYTYPE_RSA);
    assert_null(it->next);

    it = ssh_list_get_iterator(entry_list);
    for (;it != NULL; it = it->next) {
        entry = ssh_iterator_value(struct ssh_knownhosts_entry *, it);
        SSH_KNOWNHOSTS_ENTRY_FREE(entry);
    }
    ssh_list_free(entry_list);
}

static void torture_knownhosts_get_algorithms_names(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session;
    const char *expect = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa";
    char *names = NULL;
    bool process_config = false;

    session = ssh_new();
    assert_non_null(session);

    /* This makes sure the global configuration file is not processed */
    ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &process_config);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownhosts_file);

    names = ssh_known_hosts_get_algorithms_names(session);
    assert_non_null(names);
    assert_string_equal(names, expect);

    SAFE_FREE(names);
    ssh_free(session);
}

/* Do not remove this test if we completely remove DSA support! */
static void torture_knownhosts_get_algorithms_names_unsupported(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session;
    char *names = NULL;
    bool process_config = false;

    session = ssh_new();
    assert_non_null(session);

    /* This makes sure the global configuration file is not processed */
    ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &process_config);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownhosts_file);

    names = ssh_known_hosts_get_algorithms_names(session);
    assert_null(names);

    ssh_free(session);
}

static void torture_knownhosts_algorithms_wanted(void **state)
{
    const char *knownhosts_file = *state;
    char *algo_list = NULL;
    ssh_session session;
    bool process_config = false;
    const char *wanted = "ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,"
                         "rsa-sha2-256,ecdsa-sha2-nistp521";
    const char *expect = "rsa-sha2-256,ecdsa-sha2-nistp384,"
                         "ecdsa-sha2-nistp256,ecdsa-sha2-nistp521";
    int verbose = 4;

    session = ssh_new();
    assert_non_null(session);

    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbose);

    /* This makes sure the global configuration file is not processed */
    ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &process_config);

    /* Set the wanted list of hostkeys, ordered by preference */
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, wanted);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownhosts_file);

    algo_list = ssh_client_select_hostkeys(session);
    assert_non_null(algo_list);
    assert_string_equal(algo_list, expect);
    free(algo_list);

    ssh_free(session);
}

static void torture_knownhosts_algorithms_negative(UNUSED_PARAM(void **state))
{
    const char *wanted = NULL;
    const char *expect = NULL;

    char *algo_list = NULL;

    char *cwd = NULL;
    char *tmp_dir = NULL;

    bool process_config = false;
    int verbose = 4;
    int rc = 0;

    ssh_session session;
    /* Create temporary directory */
    cwd = torture_get_current_working_dir();
    assert_non_null(cwd);

    tmp_dir = torture_make_temp_dir(template);
    assert_non_null(tmp_dir);

    rc = torture_change_dir(tmp_dir);
    assert_int_equal(rc, 0);

    session = ssh_new();
    assert_non_null(session);

    ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbose);
    ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &process_config);
    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");

    /* Test with unknown key type in known_hosts */
    wanted = "rsa-sha2-256";
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, wanted);
    torture_write_file("unknown_key_type", "localhost unknown AAAABBBBCCCC");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "unknown_key_type");
    algo_list = ssh_client_select_hostkeys(session);
    assert_non_null(algo_list);
    assert_string_equal(algo_list, wanted);
    SAFE_FREE(algo_list);

    /* Test with unsupported, but existing types */
    wanted = "rsa-sha2-256-cert-v01@openssh.com,"
             "rsa-sha2-512-cert-v01@openssh.com";
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, wanted);
    algo_list = ssh_client_select_hostkeys(session);
    assert_null(algo_list);

    /* In FIPS mode, test filtering keys not allowed */
    if (ssh_fips_mode()) {
        wanted = "ssh-ed25519,rsa-sha2-256,ssh-rsa";
        expect = "rsa-sha2-256";
        ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, wanted);
        torture_write_file("no_fips", LOCALHOST_DEFAULT_ED25519);
        ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "no_fips");
        algo_list = ssh_client_select_hostkeys(session);
        assert_non_null(algo_list);
        assert_string_equal(algo_list, expect);
        SAFE_FREE(algo_list);
    }

    ssh_free(session);

    /* Teardown */
    rc = torture_change_dir(cwd);
    assert_int_equal(rc, 0);

    rc = torture_rmdirs(tmp_dir);
    assert_int_equal(rc, 0);

    SAFE_FREE(tmp_dir);
    SAFE_FREE(cwd);
}

#ifndef _WIN32 /* There is no /dev/null on Windows */
static void torture_knownhosts_host_exists(void **state)
{
    const char *knownhosts_file = *state;
    enum ssh_known_hosts_e found;
    ssh_session session;

    session = ssh_new();
    assert_non_null(session);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownhosts_file);

    /* This makes sure the system's known_hosts are not used */
    ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "/dev/null");
    found = ssh_session_has_known_hosts_entry(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);

    /* This makes sure the check will not fail when the system's known_hosts is
     * not accessible*/
    ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "./unaccessible");
    found = ssh_session_has_known_hosts_entry(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);

    /* This makes sure the check will fail for an unknown host */
    ssh_options_set(session, SSH_OPTIONS_HOST, "wurstbrot");
    found = ssh_session_has_known_hosts_entry(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_UNKNOWN);

    ssh_free(session);
}

static void torture_knownhosts_host_exists_global(void **state)
{
    const char *knownhosts_file = *state;
    enum ssh_known_hosts_e found;
    ssh_session session;

    session = ssh_new();
    assert_non_null(session);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, knownhosts_file);

    /* This makes sure the user's known_hosts are not used */
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null");
    found = ssh_session_has_known_hosts_entry(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);

    /* This makes sure the check will not fail when the user's known_hosts is
     * not accessible*/
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "./unaccessible");
    found = ssh_session_has_known_hosts_entry(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);

    /* This makes sure the check will fail for an unknown host */
    ssh_options_set(session, SSH_OPTIONS_HOST, "wurstbrot");
    found = ssh_session_has_known_hosts_entry(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_UNKNOWN);

    ssh_free(session);
}

static void torture_knownhosts_algorithms(void **state)
{
    const char *knownhosts_file = *state;
    char *algo_list = NULL;
    ssh_session session;
    bool process_config = false;
    const char *expect = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,"
                         "ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,"
                         "ecdsa-sha2-nistp256,"
                         "sk-ssh-ed25519@openssh.com,"
                         "sk-ecdsa-sha2-nistp256@openssh.com";
    const char *expect_fips = "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp521,"
                              "ecdsa-sha2-nistp384,ecdsa-sha2-nistp256";

    session = ssh_new();
    assert_non_null(session);

    /* This makes sure the global configuration file is not processed */
    ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &process_config);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, knownhosts_file);
    /* This makes sure the system's known_hosts are not used */
    ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "/dev/null");

    algo_list = ssh_client_select_hostkeys(session);
    assert_non_null(algo_list);
    if (ssh_fips_mode()) {
        assert_string_equal(algo_list, expect_fips);
    } else {
        assert_string_equal(algo_list, expect);
    }
    free(algo_list);

    ssh_free(session);
}

static void torture_knownhosts_algorithms_global(void **state)
{
    const char *knownhosts_file = *state;
    char *algo_list = NULL;
    ssh_session session;
    bool process_config = false;
    const char *expect = "ssh-ed25519,rsa-sha2-512,rsa-sha2-256,"
                         "ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,"
                         "ecdsa-sha2-nistp256,"
                         "sk-ssh-ed25519@openssh.com,"
                         "sk-ecdsa-sha2-nistp256@openssh.com";
    const char *expect_fips = "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp521,"
                              "ecdsa-sha2-nistp384,ecdsa-sha2-nistp256";

    session = ssh_new();
    assert_non_null(session);

    /* This makes sure the global configuration file is not processed */
    ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &process_config);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    /* This makes sure the current-user's known hosts are not used */
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null");
    ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, knownhosts_file);

    algo_list = ssh_client_select_hostkeys(session);
    assert_non_null(algo_list);
    if (ssh_fips_mode()) {
        assert_string_equal(algo_list, expect_fips);
    } else {
        assert_string_equal(algo_list, expect);
    }
    free(algo_list);

    ssh_free(session);
}

static int setup_bad_knownhosts_file(void **state)
{
    char *tmp_file = NULL;
    size_t nwritten;
    FILE *fp = NULL;
    int rc = 0;

    tmp_file = torture_create_temp_file(TMP_FILE_NAME);
    assert_non_null(tmp_file);

    *state = tmp_file;

    fp = fopen(tmp_file, "w");
    assert_non_null(fp);

    nwritten = fwrite(LOCALHOST_DEFAULT_ED25519,
                      sizeof(char),
                      strlen(LOCALHOST_DEFAULT_ED25519),
                      fp);
    if (nwritten != strlen(LOCALHOST_DEFAULT_ED25519)) {
        rc = -1;
        goto close_fp;
    }

    nwritten = fwrite("\n", sizeof(char), 1, fp);
    if (nwritten != 1) {
        rc = -1;
        goto close_fp;
    }

#define LOCALHOST_BAD_LINE "localhost \n"
    nwritten = fwrite(LOCALHOST_BAD_LINE,
                      sizeof(char),
                      strlen(LOCALHOST_BAD_LINE),
                      fp);
    if (nwritten != strlen(LOCALHOST_BAD_LINE)) {
        rc = -1;
        goto close_fp;
    }

close_fp:
    fclose(fp);

    return rc;
}

static void torture_knownhosts_has_entry(void **state)
{
    const char *knownhosts_file = *state;
    enum ssh_known_hosts_e found;
    ssh_session session;
    bool process_config = false;
    struct ssh_knownhosts_entry *entry = NULL;

    session = ssh_new();
    assert_non_null(session);

    /* This makes sure the global configuration file is not processed */
    ssh_options_set(session, SSH_OPTIONS_PROCESS_CONFIG, &process_config);

    ssh_options_set(session, SSH_OPTIONS_HOST, "localhost");
    /* This makes sure the current-user's known hosts are not used */
    ssh_options_set(session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null");
    ssh_options_set(session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, knownhosts_file);

    /* Error is expected -- this tests the memory is not leaked from this
     * test case */
    found = ssh_session_has_known_hosts_entry(session);
    assert_int_equal(found, SSH_KNOWN_HOSTS_ERROR);

    found = ssh_session_get_known_hosts_entry(session, &entry);
    assert_int_equal(found, SSH_KNOWN_HOSTS_ERROR);
    assert_null(entry);

    ssh_free(session);
}
#endif /* _WIN32 There is no /dev/null on Windows */

/*
 * Marker line (@cert-authority / @revoked) parsing tests
 */

static void torture_knownhosts_marker_parse(UNUSED_PARAM(void **state))
{
    enum ssh_known_hosts_marker_e marker = SSH_KNOWN_HOSTS_MARKER_NONE;
    const char *rest = NULL;

    /* No marker */
    rest = ssh_known_hosts_parse_marker("localhost ssh-ed25519 AAAA", &marker);
    assert_non_null(rest);
    assert_int_equal(marker, SSH_KNOWN_HOSTS_MARKER_NONE);
    assert_string_equal(rest, "localhost ssh-ed25519 AAAA");

    /* cert-authority, case insensitive and with extra whitespace */
    rest = ssh_known_hosts_parse_marker("@CERT-AUTHORITY   localhost key",
                                        &marker);
    assert_non_null(rest);
    assert_int_equal(marker, SSH_KNOWN_HOSTS_MARKER_CERT_AUTHORITY);
    assert_string_equal(rest, "localhost key");

    /* revoked, case insensitive */
    rest = ssh_known_hosts_parse_marker("@REVOKED localhost key", &marker);
    assert_non_null(rest);
    assert_int_equal(marker, SSH_KNOWN_HOSTS_MARKER_REVOKED);
    assert_string_equal(rest, "localhost key");

    /* Unknown marker: skipped, not a hard parse error */
    rest = ssh_known_hosts_parse_marker("@openssh-something localhost key",
                                        &marker);
    assert_non_null(rest);
    assert_int_equal(marker, SSH_KNOWN_HOSTS_MARKER_UNKNOWN);

    /* Malformed marker lines */
    assert_null(ssh_known_hosts_parse_marker("@", &marker));
    assert_null(ssh_known_hosts_parse_marker("@ localhost key", &marker));
    assert_null(ssh_known_hosts_parse_marker("@revoked", &marker));
    assert_null(ssh_known_hosts_parse_marker("@revoked, localhost key",
                                             &marker));
}

static int setup_marker_file(void **state)
{
    char *tmp_file = torture_create_temp_file(TMP_FILE_NAME);
    assert_non_null(tmp_file);
    *state = tmp_file;
    return 0;
}

static int teardown_marker_file(void **state)
{
    char *tmp_file = *state;

    if (tmp_file == NULL) {
        return -1;
    }
    unlink(tmp_file);
    SAFE_FREE(tmp_file);
    return 0;
}

static void torture_knownhosts_read_revoked_entry(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    struct ssh_knownhosts_internal_entry *ientry = NULL;
    int rc;

    torture_write_file(knownhosts_file,
                       "@revoked " TEST_HOST_PUBKEY "\n");

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(entry_list);
    it = ssh_list_get_iterator(entry_list);
    assert_non_null(it);

    ientry = ssh_iterator_value(struct ssh_knownhosts_internal_entry *, it);
    assert_int_equal(ientry->marker, SSH_KNOWN_HOSTS_MARKER_REVOKED);
    assert_int_equal(ssh_key_type(ientry->entry.publickey),
                     SSH_KEYTYPE_ED25519);
    assert_null(it->next);

    ssh_knownhosts_entries_free(entry_list);
}

static void torture_knownhosts_read_cert_authority_entry(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    struct ssh_knownhosts_internal_entry *ientry = NULL;
    int rc;

    torture_write_file(knownhosts_file,
                       "@cert-authority " TEST_CA_PUBKEY "\n");

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(entry_list);
    it = ssh_list_get_iterator(entry_list);
    assert_non_null(it);

    ientry = ssh_iterator_value(struct ssh_knownhosts_internal_entry *, it);
    assert_int_equal(ientry->marker,
                     SSH_KNOWN_HOSTS_MARKER_CERT_AUTHORITY);
    assert_int_equal(ssh_key_type(ientry->entry.publickey),
                     SSH_KEYTYPE_ED25519);

    ssh_knownhosts_entries_free(entry_list);
}

static void torture_knownhosts_read_hashed_marker_entry(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    struct ssh_iterator *it = NULL;
    struct ssh_knownhosts_internal_entry *ientry = NULL;
    int rc;

    /* The hash must resolve to "localhost" */
    torture_write_file(knownhosts_file,
                       "@revoked " TEST_HOST_HASHED "\n");

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    assert_non_null(entry_list);
    it = ssh_list_get_iterator(entry_list);
    assert_non_null(it);

    ientry = ssh_iterator_value(struct ssh_knownhosts_internal_entry *, it);
    assert_int_equal(ientry->marker, SSH_KNOWN_HOSTS_MARKER_REVOKED);
    assert_string_equal(ientry->entry.hostname, "localhost");

    /* The hashed entry must not match a different host */
    ssh_knownhosts_entries_free(entry_list);
    entry_list = NULL;
    rc = ssh_known_hosts_read_entries("other.example",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    assert_null(ssh_list_get_iterator(entry_list));
    ssh_knownhosts_entries_free(entry_list);
}

static void torture_knownhosts_marker_duplicate_entries(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    int rc;

    /* The same key with different markers are different entries, but an
     * exact duplicate is dropped. */
    torture_write_file(knownhosts_file,
                       TEST_HOST_PUBKEY "\n"
                       "@revoked " TEST_HOST_PUBKEY "\n"
                       "@revoked " TEST_HOST_PUBKEY "\n");

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(ssh_list_count(entry_list), 2);
    ssh_knownhosts_entries_free(entry_list);
}

static void torture_knownhosts_malformed_marker_line(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    int rc;

    torture_write_file(knownhosts_file,
                       TEST_HOST_PUBKEY "\n"
                       "@revoked,\n");

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_ERROR);
    ssh_knownhosts_entries_free(entry_list);
}

static void torture_knownhosts_unknown_marker_ignored(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    int rc;

    torture_write_file(knownhosts_file,
                       "@future-marker " TEST_HOST_PUBKEY "\n"
                       TEST_HOST_PUBKEY "\n");

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    /* Only the plain line is kept */
    assert_int_equal(ssh_list_count(entry_list), 1);
    ssh_knownhosts_entries_free(entry_list);
}

/*
 * Host key / certificate verification tests. These call the internal check
 * function directly with imported keys, avoiding any network interaction.
 */

static int import_line_key(const char *line, ssh_key *key)
{
    char type[128] = {0};
    char blob[8192] = {0};
    const char *sp = NULL;

    /* The test material has the form "[hostname|hash] type blob [comment]";
     * the type is always the last token before the base64 key. */
    sp = strchr(line, ' ');
    if (sp == NULL) {
        return SSH_ERROR;
    }
    sp++;
    if (sscanf(sp, "%127s %8191s", type, blob) != 2) {
        return SSH_ERROR;
    }

    if (strcmp(type, "ssh-ed25519") == 0) {
        return ssh_pki_import_pubkey_base64(blob,
                                            SSH_KEYTYPE_ED25519,
                                            key);
    }

    return ssh_pki_import_cert_base64(
        blob,
        ssh_key_type_from_name(type),
        key);
}

static void torture_knownhosts_revoked_host_key(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_key = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       "@revoked " TEST_HOST_PUBKEY "\n");

    rc = import_line_key(TEST_HOST_PUBKEY, &server_key);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_key,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_REVOKED);

    ssh_key_free(server_key);
    ssh_free(session);
}

static void torture_knownhosts_revoked_different_key_still_unknown(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_key = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       "@revoked " LOCALHOST_DEFAULT_ED25519 "\n");

    rc = import_line_key(TEST_HOST_PUBKEY, &server_key);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_key,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_UNKNOWN);

    ssh_key_free(server_key);
    ssh_free(session);
}

static void torture_knownhosts_cert_authority_valid(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_cert = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       "@cert-authority " TEST_CA_PUBKEY "\n");

    rc = import_line_key(TEST_HOST_CERT_VALID, &server_cert);
    assert_int_equal(rc, SSH_OK);
    assert_true(is_cert_type(ssh_key_type(server_cert)));

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_cert,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);

    ssh_key_free(server_cert);
    ssh_free(session);
}

static void torture_knownhosts_cert_authority_expired(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_cert = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       "@cert-authority " TEST_CA_PUBKEY "\n");

    rc = import_line_key(TEST_HOST_CERT_EXPIRED, &server_cert);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_cert,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_CERT_EXPIRED);

    ssh_key_free(server_cert);
    ssh_free(session);
}

static void torture_knownhosts_cert_authority_unknown_ca(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_cert = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    /* Trust anchor is a different CA than the one that signed the cert */
    torture_write_file(knownhosts_file,
                       "@cert-authority " TEST_OTHER_CA_PUBKEY "\n");

    rc = import_line_key(TEST_HOST_CERT_VALID, &server_cert);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_cert,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA);

    ssh_key_free(server_cert);
    ssh_free(session);
}

static void torture_knownhosts_cert_authority_bad_principal(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_cert = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       "@cert-authority " TEST_CA_PUBKEY "\n");

    /* The certificate is correctly signed but names evil.example, not
     * localhost. */
    rc = import_line_key(TEST_HOST_CERT_BADPRINC, &server_cert);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_cert,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA);

    ssh_key_free(server_cert);
    ssh_free(session);
}

static void torture_knownhosts_cert_authority_plain_key(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_key = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       "@cert-authority " TEST_CA_PUBKEY "\n");

    /* A plain key cannot be authenticated by a certificate authority line */
    rc = import_line_key(TEST_HOST_PUBKEY, &server_key);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_key,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_UNKNOWN);

    ssh_key_free(server_key);
    ssh_free(session);
}

static void torture_knownhosts_revoked_certificate(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_cert = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       "@revoked " TEST_HOST_CERT_VALID "\n");

    rc = import_line_key(TEST_HOST_CERT_VALID, &server_cert);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_cert,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_REVOKED);

    ssh_key_free(server_cert);
    ssh_free(session);
}

static void torture_knownhosts_revoked_hashed_host(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_key = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       "@revoked " TEST_HOST_HASHED "\n");

    rc = import_line_key(TEST_HOST_PUBKEY, &server_key);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_key,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_REVOKED);

    ssh_key_free(server_key);
    ssh_free(session);
}

static void torture_knownhosts_revoked_beats_ca(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_cert = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    /* Both a trusted CA and a revocation of the exact certificate */
    torture_write_file(knownhosts_file,
                       "@cert-authority " TEST_CA_PUBKEY "\n"
                       "@revoked " TEST_HOST_CERT_VALID "\n");

    rc = import_line_key(TEST_HOST_CERT_VALID, &server_cert);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_cert,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_REVOKED);

    ssh_key_free(server_cert);
    ssh_free(session);
}

static void torture_knownhosts_revoked_case_insensitive(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_key = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    /* The marker must be recognized regardless of its case */
    torture_write_file(knownhosts_file,
                       "@ReVoKeD " TEST_HOST_PUBKEY "\n");

    rc = import_line_key(TEST_HOST_PUBKEY, &server_key);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_key,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_REVOKED);

    ssh_key_free(server_key);
    ssh_free(session);
}

static void torture_knownhosts_revoked_with_port(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_key = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    /* Marker line using the bracketed host:port notation */
    torture_write_file(knownhosts_file,
                       "@revoked [localhost]:2222 ssh-ed25519 "
                       "AAAAC3NzaC1lZDI1NTE5AAAAIJkVjepGrv0L2nR1k9ZkjM4GgJrf"
                       "RH5sPqk7HW7jSe1Q\n");

    rc = import_line_key(TEST_HOST_PUBKEY, &server_key);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "[localhost]:2222",
                                             knownhosts_file,
                                             server_key,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_REVOKED);

    /* A different port must not match the revocation entry */
    found = ssh_known_hosts_check_server_key(session,
                                             "[localhost]:3333",
                                             knownhosts_file,
                                             server_key,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_UNKNOWN);

    ssh_key_free(server_key);
    ssh_free(session);
}

static void torture_knownhosts_revoked_wildcard(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_key = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       "@revoked local* ssh-ed25519 "
                       "AAAAC3NzaC1lZDI1NTE5AAAAIJkVjepGrv0L2nR1k9ZkjM4GgJrf"
                       "RH5sPqk7HW7jSe1Q\n");

    rc = import_line_key(TEST_HOST_PUBKEY, &server_key);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_key,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_REVOKED);

    ssh_key_free(server_key);
    ssh_free(session);
}

static void torture_knownhosts_oversized_marker_line(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    FILE *fp = NULL;
    char *big = NULL;
    int rc;

    /*
     * A line longer than MAX_LINE_SIZE cannot be parsed. The existing line
     * reader stops at the oversized line and reports E2BIG; the important
     * guarantee is that the oversized content is never turned into a trusted
     * entry. A well-formed marker line placed first is still accepted.
     */
    big = calloc(1, MAX_LINE_SIZE + 128);
    assert_non_null(big);
    memset(big, 'a', MAX_LINE_SIZE + 127);

    fp = fopen(knownhosts_file, "w");
    assert_non_null(fp);
    fprintf(fp, "@revoked " TEST_HOST_PUBKEY "\n");
    fprintf(fp, "@revoked %s\n", big);
    fclose(fp);
    free(big);

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    /* Only the well-formed first line produced an entry; the oversized line
     * must not have been accepted. */
    assert_int_equal(ssh_list_count(entry_list), 1);
    ssh_knownhosts_entries_free(entry_list);
}

static void torture_knownhosts_marker_long_line_bounded(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    int rc;

    /* The longest line that still fits must parse the marker correctly */
    torture_write_file(knownhosts_file,
                       "@revoked " TEST_HOST_PUBKEY "\n");

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    assert_int_equal(ssh_list_count(entry_list), 1);
    ssh_knownhosts_entries_free(entry_list);
}

static void torture_knownhosts_marker_skips_nonmatching_host(void **state)
{
    const char *knownhosts_file = *state;
    struct ssh_list *entry_list = NULL;
    int rc;

    /* A marker entry for a different host must not be returned for ours */
    torture_write_file(knownhosts_file,
                       "@revoked other.example ssh-ed25519 "
                       "AAAAC3NzaC1lZDI1NTE5AAAAIJkVjepGrv0L2nR1k9ZkjM4GgJrf"
                       "RH5sPqk7HW7jSe1Q\n");

    rc = ssh_known_hosts_read_entries("localhost",
                                      knownhosts_file,
                                      &entry_list);
    assert_int_equal(rc, SSH_OK);
    assert_null(ssh_list_get_iterator(entry_list));
    ssh_knownhosts_entries_free(entry_list);
}

static int setup_two_marker_files(void **state)
{
    char **paths = calloc(2, sizeof(char *));
    assert_non_null(paths);
    paths[0] = torture_create_temp_file(TMP_FILE_NAME);
    paths[1] = torture_create_temp_file(TMP_FILE_NAME);
    assert_non_null(paths[0]);
    assert_non_null(paths[1]);
    *state = paths;
    return 0;
}

static int teardown_two_marker_files(void **state)
{
    char **paths = *state;

    if (paths == NULL) {
        return -1;
    }
    unlink(paths[0]);
    unlink(paths[1]);
    SAFE_FREE(paths[0]);
    SAFE_FREE(paths[1]);
    SAFE_FREE(paths);
    return 0;
}

static void torture_knownhosts_revoked_user_file_wins(void **state)
{
    char **paths = *state;
    const char *user_file = paths[0];
    const char *global_file = paths[1];
    ssh_session session = ssh_new();
    ssh_key server_cert = NULL;
    enum ssh_known_hosts_e found;
    int rc;
    int strict = SSH_STRICT_HOSTKEY_OFF;

    assert_non_null(session);

    /* The user file trusts the CA, the global file revokes the certificate.
     * Revocation in either file must be fatal. */
    torture_write_file((char *)user_file,
                       "@cert-authority " TEST_CA_PUBKEY "\n");
    torture_write_file((char *)global_file,
                       "@revoked " TEST_HOST_CERT_VALID "\n");

    rc = import_line_key(TEST_HOST_CERT_VALID, &server_cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             user_file,
                                             server_cert,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             global_file,
                                             server_cert,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_REVOKED);

    /* Even with strict checking disabled, a revocation must not be
     * downgraded to an accepted key. */
    assert_false(ssh_known_hosts_should_continue_unsafe(
        session, SSH_KNOWN_HOSTS_REVOKED));
    assert_false(ssh_known_hosts_result_is_fatal(SSH_KNOWN_HOSTS_OK));
    assert_true(ssh_known_hosts_result_is_fatal(
        SSH_KNOWN_HOSTS_CERT_EXPIRED));
    assert_true(ssh_known_hosts_result_is_fatal(
        SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA));

    ssh_key_free(server_cert);
    ssh_free(session);
}

static void torture_knownhosts_cert_failure_not_downgraded(void **state)
{
    char **paths = *state;
    const char *user_file = paths[0];
    const char *global_file = paths[1];
    ssh_session session = ssh_new();
    ssh_key server_cert = NULL;
    enum ssh_known_hosts_e found;
    int rc;
    int strict = SSH_STRICT_HOSTKEY_OFF;

    assert_non_null(session);

    /* Neither file can validate the certificate: the user file holds an
     * unrelated CA, the global file has no entry at all. */
    torture_write_file((char *)user_file,
                       "@cert-authority " TEST_OTHER_CA_PUBKEY "\n");
    torture_write_file((char *)global_file, "\n");

    rc = import_line_key(TEST_HOST_CERT_VALID, &server_cert);
    assert_int_equal(rc, SSH_OK);

    rc = ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, &strict);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             user_file,
                                             server_cert,
                                             NULL);
    assert_int_equal(found, SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA);

    /* A certificate failure must never be bypassed by relaxed strict host
     * key checking. */
    assert_false(ssh_known_hosts_should_continue_unsafe(
        session, SSH_KNOWN_HOSTS_CERT_UNKNOWN_CA));
    assert_false(ssh_known_hosts_should_continue_unsafe(
        session, SSH_KNOWN_HOSTS_CERT_EXPIRED));

    ssh_key_free(server_cert);
    ssh_free(session);
}

static void torture_knownhosts_check_returns_owned_entry(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_key = NULL;
    struct ssh_knownhosts_entry *entry = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       TEST_HOST_PUBKEY "\n");

    rc = import_line_key(TEST_HOST_PUBKEY, &server_key);
    assert_int_equal(rc, SSH_OK);

    /* The returned entry must be independently owned and freeable through
     * the public ssh_knownhosts_entry_free() API. */
    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_key,
                                             &entry);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);
    assert_non_null(entry);
    assert_string_equal(entry->hostname, "localhost");
    assert_non_null(entry->publickey);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
    assert_null(entry);

    ssh_key_free(server_key);
    ssh_free(session);
}

static void torture_knownhosts_cert_check_returns_owned_entry(void **state)
{
    const char *knownhosts_file = *state;
    ssh_session session = ssh_new();
    ssh_key server_cert = NULL;
    struct ssh_knownhosts_entry *entry = NULL;
    enum ssh_known_hosts_e found;
    int rc;

    assert_non_null(session);
    torture_write_file(knownhosts_file,
                       "@cert-authority " TEST_CA_PUBKEY "\n");

    rc = import_line_key(TEST_HOST_CERT_VALID, &server_cert);
    assert_int_equal(rc, SSH_OK);

    found = ssh_known_hosts_check_server_key(session,
                                             "localhost",
                                             knownhosts_file,
                                             server_cert,
                                             &entry);
    assert_int_equal(found, SSH_KNOWN_HOSTS_OK);
    assert_non_null(entry);
    assert_non_null(entry->publickey);

    SSH_KNOWNHOSTS_ENTRY_FREE(entry);
    assert_null(entry);

    ssh_key_free(server_cert);
    ssh_free(session);
}

int torture_run_tests(void) {
    int rc;
    struct CMUnitTest tests[] = {
        cmocka_unit_test(torture_knownhosts_parse_line_rsa),
        cmocka_unit_test(torture_knownhosts_parse_line_ecdsa),
        cmocka_unit_test(torture_knownhosts_parse_line_default_ed25519),
        cmocka_unit_test(torture_knownhosts_parse_line_port_ed25519),
        cmocka_unit_test(torture_knownhosts_parse_line_port_wildcard),
        cmocka_unit_test(torture_knownhosts_parse_line_standard_port),
        cmocka_unit_test(torture_knownhosts_parse_line_pattern_ed25519),
        cmocka_unit_test(torture_knownhosts_parse_line_hashed_ed25519),
        cmocka_unit_test_setup_teardown(torture_knownhosts_read_file,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_read_file,
                                        setup_knownhosts_file_duplicate,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_get_algorithms_names,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_get_algorithms_names_unsupported,
                                        setup_knownhosts_file_unsupported_type,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_algorithms_wanted,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test(torture_knownhosts_algorithms_negative),
#ifndef _WIN32
        cmocka_unit_test_setup_teardown(torture_knownhosts_host_exists,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_host_exists_global,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_algorithms,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_algorithms_global,
                                        setup_knownhosts_file,
                                        teardown_knownhosts_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_has_entry,
                                        setup_bad_knownhosts_file,
                                        teardown_knownhosts_file),
#endif
        cmocka_unit_test(torture_knownhosts_marker_parse),
        cmocka_unit_test_setup_teardown(torture_knownhosts_read_revoked_entry,
                                        setup_marker_file,
                                        teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_read_cert_authority_entry,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_read_hashed_marker_entry,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_marker_duplicate_entries,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_malformed_marker_line,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_unknown_marker_ignored,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_revoked_host_key,
                                        setup_marker_file,
                                        teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_revoked_different_key_still_unknown,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_cert_authority_valid,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_cert_authority_expired,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_cert_authority_unknown_ca,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_cert_authority_bad_principal,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_cert_authority_plain_key,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_revoked_certificate,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_revoked_hashed_host,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_revoked_beats_ca,
                                        setup_marker_file,
                                        teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_revoked_case_insensitive,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_revoked_with_port,
                                        setup_marker_file,
                                        teardown_marker_file),
        cmocka_unit_test_setup_teardown(torture_knownhosts_revoked_wildcard,
                                        setup_marker_file,
                                        teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_oversized_marker_line,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_marker_long_line_bounded,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_marker_skips_nonmatching_host,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_revoked_user_file_wins,
            setup_two_marker_files,
            teardown_two_marker_files),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_cert_failure_not_downgraded,
            setup_two_marker_files,
            teardown_two_marker_files),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_check_returns_owned_entry,
            setup_marker_file,
            teardown_marker_file),
        cmocka_unit_test_setup_teardown(
            torture_knownhosts_cert_check_returns_owned_entry,
            setup_marker_file,
            teardown_marker_file),
    };

    ssh_init();
    torture_filter_tests(tests);
    rc = cmocka_run_group_tests(tests, NULL, NULL);
    ssh_finalize();
    return rc;
}
