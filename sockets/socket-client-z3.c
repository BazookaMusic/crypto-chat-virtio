/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <sys/select.h>

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "cryptodev.h"
#include <sys/ioctl.h>
#include <fcntl.h>

#include "socket-common.h"

#define DATA_SIZE       256
#define BLOCK_SIZE      16
#define KEY_SIZE	16  /* AES128 */
#define BUFFER_SIZE 256

unsigned char CRYPTO_KEY[16] = {'3', 'o', '#', '^', 'b', '7', 'h', '6', '.', 'g', 'c', '&', '$', 'r', 't', 'l'};
unsigned char CRYPTO_IV[16] = {'$', '0', ',', '8', '9', 'p', 'c', 'q', 't', 's', 'e', 'r', '5', ',', '5', 'u'};

struct fd_struct
{
	int sd;
	int crypto_fd;
};

size_t getline_limited(char *buffer, size_t n)
{
	// Read up to \n
	// Split into different lines, if more than n chars
	char c;
	size_t offset;

	for (offset = 0; (c = getchar()) != '\n' && c != EOF && (n - 1); offset++)
	{
		buffer[offset] = c;
		n--;
	}
	buffer[offset++] = '\n';

	return offset;
}

/* Insist until all of the data has been read */
ssize_t insist_read(int fd, void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = read(fd, buf, cnt);
                if (ret < 0)
                        return ret;
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;

	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

void read_chat(void *fd_data)
{
	ssize_t n;
	unsigned char buf[DATA_SIZE];

    	int sd = ((struct fd_struct*)fd_data)->sd;
    	int cfd = ((struct fd_struct*)fd_data)->crypto_fd;

	struct session_op sess;
	struct crypt_op cryp;
	struct {
		unsigned char
				encrypted[DATA_SIZE],
				decrypted[DATA_SIZE],
				*iv,
				*key;
	} data;

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

	data.key = CRYPTO_KEY;
	data.iv = CRYPTO_IV;

	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = data.key;

	if (ioctl(cfd, CIOCGSESSION, &sess))
	{
		perror("ioctl(CIOCGSESSION)");
		exit(1);
	}

	n = insist_read(sd, buf, DATA_SIZE);
	memcpy(data.encrypted, buf, DATA_SIZE);
	if (n < 0)
	{
		perror("read");
		exit(1);
	}

	if (n == 0)	goto shutdown_read;

	cryp.ses = sess.ses;
	cryp.len = DATA_SIZE;
	cryp.src = data.encrypted;
	cryp.dst = data.decrypted;
	cryp.iv = data.iv;
	cryp.op = COP_DECRYPT;
	if (ioctl(cfd, CIOCCRYPT, &cryp))
	{
		perror("ioctl(CIOCCRYPT)");
		exit(1);
	}

	fprintf(stdout, "\n Remote said:\n    ");
	fflush(stdout);
	printf("%s", data.decrypted);

shutdown_read:
	if (ioctl(cfd, CIOCFSESSION, &sess.ses))
	{
		perror("ioctl(CIOCFSESSION)");
		exit(1);
	}
}

void write_chat(void *fd_data)
{
	size_t n;
	size_t buffer_size = DATA_SIZE - 1;
	unsigned char buf[DATA_SIZE];

	int sd = ((struct fd_struct*)fd_data)->sd;
	int cfd = ((struct fd_struct*)fd_data)->crypto_fd;

	struct session_op sess;
	struct crypt_op cryp;
	struct {
		unsigned char
				in[DATA_SIZE],
				encrypted[DATA_SIZE],
				*iv,
				*key;
	} data;

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

	data.key = CRYPTO_KEY;
	data.iv = CRYPTO_IV;

	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = data.key;

	if (ioctl(cfd, CIOCGSESSION, &sess))
	{
		perror("ioctl(CIOCGSESSION)");
		exit(1);
	}

	memset(buf, 0, DATA_SIZE);
	n = getline_limited(buf, buffer_size);
	buf[n] = '\0';
	memcpy(data.in, buf, DATA_SIZE);
	if (n < 0)
	{
		perror("read");
		exit(1);
	}

	if (n == 0) goto shutdown_write;

	cryp.ses = sess.ses;
	cryp.len = DATA_SIZE;
	cryp.src = data.in;
	cryp.dst = data.encrypted;
	cryp.iv = data.iv;
	cryp.op = COP_ENCRYPT;

	if (ioctl(cfd, CIOCCRYPT, &cryp))
	{
		perror("ioctl(CIOCCRYPT)");
		exit(1);
	}

	fprintf(stdout, "\n I said:\n    ");
	fflush(stdout);
	if (insist_write(0, buf, n) != n)
	{
		perror("write");
		exit(1);
	}

	if (insist_write(sd, data.encrypted, DATA_SIZE) != DATA_SIZE)
	{
		perror("write");
		exit(1);
	}

shutdown_write:
	if (ioctl(cfd, CIOCFSESSION, &sess.ses))
	{
		perror("ioctl(CIOCFSESSION)");
		exit(1);
	}
}

int build_fd_sets(int sd, fd_set *read_fds, fd_set *write_fds, fd_set *except_fds)
{
	FD_ZERO(read_fds);
	FD_SET(STDIN_FILENO, read_fds);
	FD_SET(sd, read_fds);

	FD_ZERO(write_fds);

	FD_ZERO(except_fds);
	FD_SET(STDIN_FILENO, except_fds);
	FD_SET(sd, except_fds);

	return 0;
}

int main(int argc, char *argv[])
{
	int sd, port;
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;

	struct fd_struct fd_data;

	fd_set read_fds, write_fds, except_fds;

	if (argc != 3)
	{
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	int crypto_fd;

	crypto_fd = open("/dev/cryptodev0", O_RDWR);
	if (crypto_fd < 0)
	{
		perror("open(/dev/cryptodev0)");
		return 1;
	}

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... ");
	fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
	{
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	fd_data.sd = sd;
	fd_data.crypto_fd = crypto_fd;

	while(1)
	{
		build_fd_sets(sd, &read_fds, &write_fds, &except_fds);

		int activity = select(sd + 1, &read_fds, &write_fds, &except_fds, NULL);

		switch(activity)
		{
			case -1:
				perror("select()");
				exit(1);
			case 0:
			  printf("select() returns 0.\n");
				exit(1);
			default:
			  if (FD_ISSET(STDIN_FILENO, &read_fds))
				{
					write_chat(&fd_data);
				}
				if (FD_ISSET(STDIN_FILENO, &except_fds))
				{
 			    printf("except_fds for stdin.\n");
			    exit(1);
				}
				if (FD_ISSET(sd, &read_fds))
				{
					read_chat(&fd_data);
				}
				if (FD_ISSET(sd, &except_fds))
				{
					exit(1);
				}
		}
	}

	fprintf(stderr, "\nDone.\n");

	if (close(crypto_fd) < 0)
	{
		perror("close(crypto_fd)");
		return 1;
	}

	return 0;
}
