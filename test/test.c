#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define MAXBUFSIZE 65536

int main (int argc, char **argv)
{
    int sock, ret;
    char buffer[MAXBUFSIZE+1];
    struct sockaddr_in saddr;

    memset(&saddr, 0, sizeof(struct sockaddr_in));

    sock = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket failed!");
        return 1;
    }

    int optval = 1;
    setsockopt(sock, SOL_UDP, 200, &optval, sizeof(optval));

    saddr.sin_family = PF_INET;
    saddr.sin_port = htons(10000);
    saddr.sin_addr.s_addr = inet_addr("0.0.0.0");
    ret = bind(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
    if (ret < 0) {
        perror("bind failed!");
        return 1;
    }

    saddr.sin_family = PF_INET;
    saddr.sin_port = htons(9999);
    saddr.sin_addr.s_addr = inet_addr("200.200.200.200");
    ret = connect(sock, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
    if (ret < 0) {
        perror("connect failed!");
        return 1;
    }

    ret = read(sock, buffer, MAXBUFSIZE);
    if (ret < 0) {
        perror("read error");
        return 1;
    }

    buffer[ret] = 0;
    printf("buffer=%s\n", buffer);
}
