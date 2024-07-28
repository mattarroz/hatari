
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "gdbstub_backend.h"

static int connfd, sockfd;
static const int port = 2000;

void z_gdb_putchar(unsigned char ch) {
  if (!write(connfd, &ch, 1))
    fprintf(stderr, "gdbstub_backend_tcpip: write failed.\n");
}

unsigned char z_gdb_getchar(void) {
  unsigned char ch;
//  read(connfd, &ch, 1);
  if (!read(connfd, &ch, 1))
    fprintf(stderr, "gdbstub_backend_tcpip: read failed.\n");
  return  ch;
}


int z_gdb_backend_init(void) {
  socklen_t len;
  struct sockaddr_in servaddr, cli;

  // socket create and verification
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    printf("gdbstub_backend_tcpip: socket creation failed...\n");
    exit(0);
  }
  else
    printf("gdbstub_backend_tcpip: socket successfully created..\n");
  bzero(&servaddr, sizeof(servaddr));

  // assign IP, PORT
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);

  // Binding newly created socket to given IP and verification
  if ((bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr))) != 0) {
    fprintf(stderr, "gdbstub_backend_tcpip: socket bind failed (%s)\n", strerror(errno));
    return 0;
  }
  else
    printf("gdbstub_backend_tcpip: Socket successfully bound..\n");

  // Now server is ready to listen and verification
  if ((listen(sockfd, 5)) != 0) {
    printf("gdbstub_backend_tcpip: Listen failed...\n");
    return 0;
  }
  else
    printf("gdbstub_backend_tcpip: Server listening..\n");
  len = sizeof(cli);

  connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
  if (connfd < 0) {
    printf("gdbstub_backend_tcpip: accept failed...\n");
    return 0;
  }
  else
    printf("gdbstub_backend_tcpip: Server accepted the client...\n");

  return 1;
}

void z_gdb_backend_destroy(void) {
  close(connfd);
  close(sockfd);
}
