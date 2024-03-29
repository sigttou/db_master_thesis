/* Source: https://wiki.openssl.org/index.php/Simple_TLS_Server 
 * Small changes to have more connections possible at once and
 * analyse the memory fingerprint of connections.
 * Create cert and key with:
 * openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout key.pem -out cert.pem
 * To compile use:
 * $ gcc server_threads.c -o server_threads -lssl -lcrypto -lpthread
 * To connect use:
 * $ ./server_threads &
 * $ ncat --ssl-ciphers ECDHE-RSA-AES256-GCM-SHA384 --ssl localhost 4433
 * Or:
 * $ ./server_threads &
 * $ openssl s_client -connect localhost:4433
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <signal.h>

typedef struct{
  SSL_CTX* ctx_;
  int client_;
} t_arg;

SSL* SSLTOFLIP;
SSL_CTX* CTXTOFLIP;
EVP_CIPHER_CTX* CCTXTOFLIP;

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

void* connection_thread(void *arg)
{
  SSL_CTX* ctx = ((t_arg*)arg)->ctx_;
  SSL* ssl = SSL_new(ctx);
  int client = ((t_arg*)arg)->client_;
  SSL_set_fd(ssl, client);

  const char reply[] = "test\n";

  if (SSL_accept(ssl) <= 0)
    ERR_print_errors_fp(stderr);
  else
  {
    int run = 1;
    SSLTOFLIP = ssl;
    CTXTOFLIP = ssl->session_ctx;
    CCTXTOFLIP = ssl->enc_write_ctx;
    while(run)
    {
      if(SSL_write(ssl, reply, strlen(reply)) < 0)
        run = 0;
      sleep(1);
    }
  }
  SSL_free(ssl);
  close(client);
  pthread_exit(NULL);
}

void toggle_bit(void* memory, size_t byte_pos, size_t bit)
{
  if(!memory)
    return;
  char* byte = (char*)(memory + byte_pos);
  *byte ^= 1UL << bit;
}

void* flipping_thread(void __attribute__((__unused__)) *arg)
{
  while(1)
  {
    getchar();
    /*
    size_t byte_pos = rand() % sizeof(SSL);
    size_t bit = rand() % 8;
    printf("Flipping %zd bit in %zd byte in %p\n", bit, byte_pos, SSLTOFLIP);
    toggle_bit(SSLTOFLIP, byte_pos, bit);
    */
    /*
    size_t byte_pos = rand() % sizeof(SSL_CTX);
    size_t bit = rand() % 8;
    printf("Flipping %zd bit in %zd byte in %p\n", bit, byte_pos, CTXTOFLIP);
    toggle_bit(CTXTOFLIP, byte_pos, bit);
    */
    size_t byte_pos = rand() % sizeof(EVP_MAX_IV_LENGTH);
    size_t bit = rand() % 8;
    printf("Flipping %zd bit in %zd byte in %p\n", bit, byte_pos, CCTXTOFLIP->iv);
    toggle_bit(CCTXTOFLIP->iv, byte_pos, bit);
  }
}


int main(int argc, char **argv)
{
    srand(time(NULL));
    sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL);
    int sock;
    SSL_CTX *ctx;
    printf("SSL %lu bytes\n", sizeof(SSL));
    printf("SSL_CTX %lu bytes\n", sizeof(SSL_CTX));
    printf("EVP_CIPHER_CTX %lu bytes\n", sizeof(EVP_CIPHER_CTX));

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    pthread_t t;
    pthread_create(&t, NULL, &flipping_thread, NULL);
    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        pthread_t t;
        t_arg arg;
        arg.ctx_ = ctx;
        arg.client_ = client;
        pthread_create(&t, NULL, &connection_thread, &arg);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}


