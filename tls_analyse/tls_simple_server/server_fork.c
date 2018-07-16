/* Source: https://wiki.openssl.org/index.php/Simple_TLS_Server 
 * Small changes to have more connections possible at once and
 * analyse the memory fingerprint of connections.
 * Create cert and key with:
 * openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout key.pem -out cert.pem
 * To compile use:
 * $ gcc server_fork.c -o server_fork -lssl -lcrypto
 * To connect use:
 * $ ./server_fork &
 * $ ncat --ssl-ciphers ECDHE-RSA-AES256-GCM-SHA384 --ssl localhost 4433
 * Or:
 * $ ./server_fork &
 * $ openssl s_client -connect localhost:4433
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
	perror("Unable to create socket");
	exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	perror("Unable to bind");
	exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
	perror("Unable to listen");
	exit(EXIT_FAILURE);
    }

    return s;
}

void init_openssl()
{ 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);
    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        // printf("A SSL obj is: %zu bytes\n", sizeof(SSL));
        const char reply[] = "test\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if(!fork())
        {
          if (SSL_accept(ssl) <= 0) {
              ERR_print_errors_fp(stderr);
          }
          else {
            int run = 1;
            while(run)
            {
              if(SSL_write(ssl, reply, strlen(reply)) < 0)
                run = 0;
              sleep(1);
            }
          }
          SSL_free(ssl);
          close(client);
          exit(0);
        }
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}


