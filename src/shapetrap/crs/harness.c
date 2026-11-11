/* shapetrap CRS harness: feeds one HTTP request per input line to
 * libmodsecurity (v3) loaded with the OWASP Core Rule Set and prints the
 * verdict.  Nothing is sent over the network and nothing is executed; the
 * request only exists as arguments to the library.
 *
 * Input, one request per line, tab separated:
 *     METHOD <TAB> hex(URI) <TAB> content-type or "-" <TAB> hex(body) or "-"
 * Output, one line per request:
 *     status <TAB> comma-separated ids of the rules that logged a match
 * where status is the HTTP status of the disruptive action (403) or 0.
 *
 * Build:  cc -O2 -o crs-harness harness.c -lmodsecurity
 * Usage:  crs-harness <modsecurity.conf>  < requests.tsv  > verdicts.tsv
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>

#define MAX_IDS 4096

struct match_log {
    char ids[MAX_IDS];
    size_t used;
};

static void on_log(void *data, const void *message) {
    struct match_log *log = (struct match_log *)data;
    const char *msg = (const char *)message;
    if (log == NULL || msg == NULL) return;
    const char *p = msg;
    while ((p = strstr(p, "[id \"")) != NULL) {
        p += 5;
        const char *end = strchr(p, '"');
        if (end == NULL) break;
        size_t n = (size_t)(end - p);
        if (n > 0 && n < 16 && log->used + n + 2 < MAX_IDS) {
            if (log->used > 0) log->ids[log->used++] = ',';
            memcpy(log->ids + log->used, p, n);
            log->used += n;
            log->ids[log->used] = '\0';
        }
        p = end;
    }
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decodes hex in place; returns the decoded length, or -1 on bad input. */
static long unhex(char *s) {
    size_t n = strlen(s);
    if (n % 2) return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hexval((unsigned char)s[2 * i]), lo = hexval((unsigned char)s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        s[i] = (char)(hi * 16 + lo);
    }
    s[n / 2] = '\0';
    return (long)(n / 2);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <modsecurity.conf>\n", argv[0]);
        return 2;
    }
    ModSecurity *modsec = msc_init();
    msc_set_connector_info(modsec, "shapetrap-crs-harness");
    msc_set_log_cb(modsec, on_log);
    RulesSet *rules = msc_create_rules_set();
    const char *error = NULL;
    if (msc_rules_add_file(rules, argv[1], &error) < 0) {
        fprintf(stderr, "cannot load rules: %s\n", error ? error : "unknown error");
        return 1;
    }

    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, stdin)) != -1) {
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = '\0';
        char *method = line;
        char *uri = strchr(method, '\t');
        char *ctype = uri ? strchr(uri + 1, '\t') : NULL;
        char *body = ctype ? strchr(ctype + 1, '\t') : NULL;
        if (!uri || !ctype || !body) { puts("-1\tbad-line"); continue; }
        *uri++ = '\0'; *ctype++ = '\0'; *body++ = '\0';
        long body_len = 0;
        if (unhex(uri) < 0) { puts("-1\tbad-hex"); continue; }
        if (strcmp(body, "-") != 0 && (body_len = unhex(body)) < 0) { puts("-1\tbad-hex"); continue; }

        struct match_log log = { {0}, 0 };
        Transaction *t = msc_new_transaction(modsec, rules, &log);
        msc_process_connection(t, "198.51.100.7", 40000, "192.0.2.1", 80);
        msc_process_uri(t, uri, method, "1.1");
        msc_add_request_header(t, (const unsigned char *)"Host", (const unsigned char *)"localhost");
        msc_add_request_header(t, (const unsigned char *)"User-Agent",
                               (const unsigned char *)"Mozilla/5.0 (X11; Linux x86_64) shapetrap");
        msc_add_request_header(t, (const unsigned char *)"Accept", (const unsigned char *)"*/*");
        if (strcmp(ctype, "-") != 0) {
            char clen[32];
            snprintf(clen, sizeof clen, "%ld", body_len);
            msc_add_request_header(t, (const unsigned char *)"Content-Type", (const unsigned char *)ctype);
            msc_add_request_header(t, (const unsigned char *)"Content-Length", (const unsigned char *)clen);
        }
        msc_process_request_headers(t);
        if (body_len > 0) msc_append_request_body(t, (const unsigned char *)body, (size_t)body_len);
        msc_process_request_body(t);

        ModSecurityIntervention it;
        memset(&it, 0, sizeof it);
        it.status = 200;
        int disruptive = msc_intervention(t, &it) && it.disruptive;
        printf("%d\t%s\n", disruptive ? it.status : 0, log.ids);
        free(it.log);
        free(it.url);
        msc_transaction_cleanup(t);
    }
    free(line);
    msc_rules_cleanup(rules);
    msc_cleanup(modsec);
    return 0;
}
