#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../mongoose.h"

static void print_response(const struct http_message * hm)
{
    char * copy = malloc(hm->body.len + 1);
    memcpy(copy, hm->body.p, hm->body.len);
    copy[hm->body.len] = 0;
    printf("*************************************************\n");
    printf("*  HTTP message\n");
    printf("*************************************************\n");
    printf("%s\n", copy);
}


int main(void)
{
    const char * host_url = "https://httpbin.org";

    struct mg_mgr mgr;
    struct mg_connect_opts opts;
    const char * err_str;

    const struct http_message * hm;

    memset(&opts, 0, sizeof(opts));
    opts.ssl_ca_cert = "cacert_httpbin.pem";
    opts.error_string = &err_str;

    struct mg_http_connection * conn = mg_http_connect(host_url, &opts, 5);

    if (!conn)
    {
        fprintf(stderr,"Cannot open connection");
        exit(1);
    }

    hm = mg_http_request(conn, "/get?request=first", "Which: First\r\n", 0);

    print_response(hm);

    hm = mg_http_request(conn, "/get?request=second", "Which: Second\r\n", 0);

    print_response(hm);

    hm = mg_http_request(conn, "/delay/10?request=third", "Which: Third\r\n", 0);

    if (hm == 0)
        printf("Connection timeout out\n");

    hm = mg_http_request(conn, "/get?request=fourth", "Which: Fourth\r\n", 0);
    print_response(hm);

    mg_http_close(conn);

    return 0;
}

