#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#define BUF_SIZE 1024

// Vigenère Cipher
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

// Parse command-line arguments
void parse_args(int argc, char *argv[], char **message, char **key, char **ip, int *port)
{
    if (argc != 5)
    {
        fprintf(stderr, "Usage: %s <message> <key> <server IP> <port>\n", argv[0]);
        exit(1);
    }

    *message = argv[1];
    *key = argv[2];
    *ip = argv[3];
    *port = atoi(argv[4]);

    for (int i = 0; (*key)[i]; i++)
    {
        if (!isalpha((*key)[i]))
        {
            fprintf(stderr, "Error: key contains non-alphabetic character '%c'\n", (*key)[i]);
            exit(1);
        }
    }
}

// Create client socket
int create_client_socket(const char *ip, int port, struct sockaddr_storage *addr, socklen_t *addr_len)
{
    int sock;
    if (strchr(ip, ':')) // IPv6
    {
        sock = socket(AF_INET6, SOCK_STREAM, 0);
        if (sock < 0)
        {
            perror("socket");
            exit(1);
        }

        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        memset(addr6, 0, sizeof(*addr6));
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(port);

        if (inet_pton(AF_INET6, ip, &addr6->sin6_addr) <= 0)
        {
            fprintf(stderr, "Invalid IPv6 address\n");
            exit(1);
        }

        // Handle link-local automatically
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
    }
    else // IPv4
    {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
        {
            perror("socket");
            exit(1);
        }

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
    }

    return sock;
}

// Send key and message
void send_message(int sock, const char *key, const char *message)
{
    write(sock, key, strlen(key));
    write(sock, "\n", 1);
    write(sock, message, strlen(message));
    write(sock, "\n", 1);
}

// Receive encrypted message and decrypt
void receive_and_decrypt(int sock, const char *key)
{
    char buffer[BUF_SIZE];
    int n = read(sock, buffer, BUF_SIZE - 1);
    if (n > 0)
    {
        buffer[n] = '\0';
        printf("Encrypted: %s\n", buffer);

        vigenere_cipher(buffer, key, 0);
        printf("Decrypted: %s\n", buffer);
    }
}

// Main
int main(int argc, char *argv[])
{
    char *message, *key, *ip;
    int port;

    parse_args(argc, argv, &message, &key, &ip, &port);

    struct sockaddr_storage server_addr;
    socklen_t addr_len;
    int sock = create_client_socket(ip, port, &server_addr, &addr_len);

    if (connect(sock, (struct sockaddr *)&server_addr, addr_len) < 0)
    {
        perror("connect");
        exit(1);
    }

    send_message(sock, key, message);
    receive_and_decrypt(sock, key);

    close(sock);
    return 0;
}
