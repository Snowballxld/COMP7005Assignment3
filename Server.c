#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>

#define BUF_SIZE 1024
#define BACKLOG 10
#define MAX_CLIENTS 100

int sockfd = -1;

// vigenere Cipher
void vigenere_cipher(char *text, const char *key, int encrypt)
{
    int key_len = strlen(key);
    for (int i = 0, j = 0; text[i]; i++)
    {
        char c = text[i];
        if (isalpha(c))
        {
            char key_char = tolower(key[j % key_len]);
            int shift = key_char - 'a';

            if (!encrypt)
                shift = -shift;

            if (isupper(c))
                text[i] = 'A' + ((c - 'A' + shift + 26) % 26);
            else
                text[i] = 'a' + ((c - 'a' + shift + 26) % 26);

            j++;
        }
    }
}

// graceful shutdown
void cleanup(int sig)
{
    printf("\nShutting down server...\n");
    if (sockfd >= 0)
        close(sockfd);
    exit(0);
}

// parse arguments
void parse_args(int argc, char *argv[], char **ip, int *port)
{

    if (argc == 2 && (strcmp(argv[1], "h") == 0 || strcmp(argv[1], "-h") == 0))
    {
        fprintf(stderr, "Usage: %s <IPv4/IPv6 address> <port>\n", argv[0]);
        exit(0);
    }

    if (argc != 3)
    {
        fprintf(stderr, "Incorrect number of parameters\nUsage: %s <IPv4/IPv6 address> <port>\n", argv[0]);
        exit(1);
    }
    *ip = argv[1];

    char *endptr;
    long p = strtol(argv[2], &endptr, 10);

    if (*endptr != '\0')
    {
        fprintf(stderr, "Error: port must be a number\n");
        exit(1);
    }

    if (p < 0 || p > 65535)
    {
        fprintf(stderr, "Error: port must be between 0 and 65535\n");
        exit(1);
    }

    *port = (int)p;
}

// create server socket
int create_server_socket(const char *ip, int port, struct sockaddr_storage *addr, socklen_t *addr_len)
{
    int is_ipv6 = strchr(ip, ':') != NULL;
    int sock;

    if (is_ipv6)
    {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        memset(addr6, 0, sizeof(*addr6));
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);

        if (inet_pton(AF_INET6, ip, &addr6->sin6_addr) <= 0)
        {
            fprintf(stderr, "Invalid IPv6 address\n");
            exit(1);
        }

        if (IN6_IS_ADDR_LINKLOCAL(&addr6->sin6_addr))
        {
            for (unsigned int if_index = 1; if_index < 256; if_index++)
            {
                char ifname[IF_NAMESIZE];
                if (if_indextoname(if_index, ifname) && strcmp(ifname, "lo") != 0)
                {
                    addr6->sin6_scope_id = if_index;
                    break;
                }
            }
            if (addr6->sin6_scope_id == 0)
            {
                fprintf(stderr, "Could not find non-loopback interface for link-local IPv6\n");
                exit(1);
            }
        }

        *addr_len = sizeof(*addr6);
        sock = socket(AF_INET6, SOCK_STREAM, 0);
    }
    else
    {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        memset(addr4, 0, sizeof(*addr4));
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(port);

        if (inet_pton(AF_INET, ip, &addr4->sin_addr) <= 0)
        {
            fprintf(stderr, "Invalid IPv4 address\n");
            exit(1);
        }

        *addr_len = sizeof(*addr4);
        sock = socket(AF_INET, SOCK_STREAM, 0);
    }

    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(sock, (struct sockaddr *)addr, *addr_len) < 0)
    {
        perror("bind");
        exit(1);
    }

    if (listen(sock, BACKLOG) < 0)
    {
        perror("listen");
        exit(1);
    }

    return sock;
}

// handle clients
void handle_client(int sockfd)
{
    struct pollfd fds[MAX_CLIENTS];
    memset(fds, 0, sizeof(fds));

    fds[0].fd = sockfd;
    fds[0].events = POLLIN;
    int nfds = 1;

    srand(time(NULL));

    while (1)
    {
        int ready = poll(fds, nfds, -1);
        if (ready < 0)
        {
            perror("poll");
            break;
        }

        // new connections
        if (fds[0].revents & POLLIN)
        {
            int client_fd = accept(sockfd, NULL, NULL);
            if (client_fd >= 0)
            {
                int flags = fcntl(client_fd, F_GETFL, 0);
                if (flags == -1)
                    flags = 0;

                fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);

                if (nfds < MAX_CLIENTS)
                {
                    fds[nfds].fd = client_fd;
                    fds[nfds].events = POLLIN;
                    nfds++;
                    printf("New client connected (fd=%d)\n", client_fd);
                }
                else
                {
                    printf("Too many clients, rejecting.\n");
                    close(client_fd);
                }
            }
        }

        // existing clients
        for (int i = 1; i < nfds; i++)
        {
            if (fds[i].revents & POLLIN)
            {
                char buffer[BUF_SIZE];
                int n = read(fds[i].fd, buffer, sizeof(buffer) - 1);
                if (n <= 0)
                {
                    printf("Client disconnected (fd=%d)\n", fds[i].fd);
                    close(fds[i].fd);
                    fds[i] = fds[nfds - 1];
                    nfds--;
                    i--;
                    continue;
                }

                buffer[n] = '\0';
                char *newline = strchr(buffer, '\n');
                if (!newline)
                    continue;

                *newline = '\0';

                char *key = buffer;
                char *message = newline + 1;
                char *end = strchr(message, '\n');

                if (end)
                    *end = '\0';

                printf("Received message: '%s' (key='%s')\n", message, key);

                vigenere_cipher(message, key, 1);

                int delay = 1 + rand() % 3;
                sleep(delay);

                write(fds[i].fd, message, strlen(message));
                printf("Sent encrypted message, '%s', to fd=%d\n", message, fds[i].fd);
            }
        }
    }
}

// main
int main(int argc, char *argv[])
{
    signal(SIGINT, cleanup);

    char *ip;
    int port;

    parse_args(argc, argv, &ip, &port);

    struct sockaddr_storage addr;
    socklen_t addr_len;

    sockfd = create_server_socket(ip, port, &addr, &addr_len);

    printf("Server listening on %s:%d\n", ip, port);

    handle_client(sockfd);

    cleanup(0);
    return 0;
}
