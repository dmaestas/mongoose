#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../mongoose.h"

int response_1 = 0;
int response_2 = 0;

static void http_client_future_1(struct http_message * hm, int ev, void * p)
{
    char * copy = malloc(hm->body.len + 1);
    memcpy(copy, hm->body.p, hm->body.len);
    copy[hm->body.len] = 0;
    printf("*************************************************\n");
    printf("*  First HTTP message - %s\n", (char *)p);
    printf("*************************************************\n");
    printf("%s\n", copy);
    response_1 = 1;
}

static void http_client_future_2(struct http_message * hm, int ev, void * p)
{
    char * copy = malloc(hm->body.len + 1);
    memcpy(copy, hm->body.p, hm->body.len);
    copy[hm->body.len] = 0;
    printf("*************************************************\n");
    printf("*  Second HTTP message - %s\n", (char *)p);
    printf("*************************************************\n");
    printf("%s\n", copy);
    response_2 = 1;
}



int main(void)
{
    const char * host_url = "https://httpbin.org";

    struct mg_mgr mgr;
    struct mg_connect_opts opts;
    const char * err_str;

    memset(&opts, 0, sizeof(opts));
//    if (ca_cert_file)
    opts.ssl_ca_cert = "cacert_httpbin.pem";
    opts.error_string = &err_str;
//    opts.ssl_server_name = "httpbin.org";

    mg_mgr_init(&mgr, NULL);

    struct mg_http_aio_connection * conn = mg_http_aio_connect(&mgr, opts, host_url);

    if (!conn)
    {
        fprintf(stderr,"Cannot open connection");
        exit(1);
    }

    mg_http_aio_request(conn, http_client_future_1, "Uno", "/get?request=first", "Future: First\r\n", 0);

    while (!response_1)
        mg_mgr_poll(&mgr, 1000);

    mg_http_aio_request(conn, http_client_future_2, "Dos", "/get?request=second", "Future: Second\r\n", 0);

    while (!response_2)
        mg_mgr_poll(&mgr, 1000);

    mg_http_aio_close(conn);

    mg_mgr_free(&mgr);

    return 0;
}

