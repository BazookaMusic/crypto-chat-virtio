/*
 * socket-server.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

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

#include <arpa/inet.h>
#include <netinet/in.h>

#include <sys/ioctl.h>
#include <fcntl.h>

#include "socket-common.h"

#define DATA_SIZE 256
#define BUFFER_SIZE 256

/* Insist until all of the data has been read */
ssize_t insist_read(int fd, void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;

	while (cnt > 0)
	{
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

ssize_t getline_limited(char *buffer, size_t n)
{
	// Read up to \n
	// Split into different lines, if more than n chars
	char c;
	size_t offset;

	for (offset = 0; (c = getchar()) != '\n' && c != EOF && (n - 1); offset++)
	{
		if(c < 0) return -1;
		buffer[offset] = c;
		n--;
	}
	buffer[offset++] = '\n';

	return offset;
}

void read_chat(int sd)
{
	ssize_t n;
	unsigned char buf[DATA_SIZE];

	//get entire buffer from client
	n = insist_read(sd, buf, DATA_SIZE);

	//error
	if (n < 0)
	{
		perror("read");
		exit(1);
	}

	//print received message
	fprintf(stdout, "\n Remote said:\n    ");
	fflush(stdout);
	printf("%s", buf);
}

void write_chat(int sd)
{
	ssize_t n;
	size_t buffer_size = DATA_SIZE - 1;
	unsigned char buf[DATA_SIZE];

	//reset buffer
	memset(buf, 0, DATA_SIZE);
	//read lines from stdin
	n = getline_limited(buf, buffer_size);
	//add delimiter to end of data
	buf[n] = '\0';

	//error
	if (n < 0)
	{
		perror("read");
		exit(1);
	}

	fprintf(stdout, "\n I said:\n    ");
	fflush(stdout);
	//output written message to stdout
	if (insist_write(0, buf, n) != n)
	{
		perror("write");
		exit(1);
	}

	//send the entire buffer to client
	//client uses '\0' to identify the end of message
	if (insist_write(sd, buf, DATA_SIZE) != DATA_SIZE)
	{
		perror("write");
		exit(1);
	}
}

int build_fd_sets(int sd, fd_set *read_fds, fd_set *write_fds, fd_set *except_fds)
{
	//initialize read file descriptor set
	FD_ZERO(read_fds);
	//add STDIN
	FD_SET(STDIN_FILENO, read_fds);
	//add the given socket descriptor
	FD_SET(sd, read_fds);

	//write set not used
	FD_ZERO(write_fds);

	//initialize exception file descriptor set
	FD_ZERO(except_fds);
	//add STDIN
	FD_SET(STDIN_FILENO, except_fds);
	//add the given socket descriptor
	FD_SET(sd, except_fds);

	return 0;
}

int main(void)
{
	char addrstr[INET_ADDRSTRLEN];
	int sd, newsd;
	socklen_t len;
	struct sockaddr_in sa;

	//sets for select
	fd_set read_fds, write_fds, except_fds;

	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	//ipv4 & tcp
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	/* Bind to a well-known port */
	//struct for binding
	memset(&sa, 0, sizeof(sa));
	//set as ipv4
	sa.sin_family = AF_INET;
	//set port & convert to Server Endian convention
	sa.sin_port = htons(TCP_PORT);
	// bind to all interfaces
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
	{
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	//tcp backlog is how many clients can be in the connection queue
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}

	/* Loop forever, accept()ing connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		//a new socket descriptor is created for every accepted connection
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		//convert ip address to printable format
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n",
			addrstr, ntohs(sa.sin_port));

		while(1)
		{
			//see the implementation above
			build_fd_sets(newsd, &read_fds, &write_fds, &except_fds);

			//newsd is the largest file descriptor
			int activity = select(newsd + 1, &read_fds, &write_fds, &except_fds, NULL);

			switch(activity)
			{
				case -1:
				//error case
					perror("select()");
					exit(1);
				case 0:
				//error case
				  	printf("select() returns 0.\n");
					exit(1);
				default:
					//data available from stdin
				  	if (FD_ISSET(STDIN_FILENO, &read_fds))
					{
						//send data
						write_chat(newsd);
					}

					//exception from stdin
					if (FD_ISSET(STDIN_FILENO, &except_fds))
					{
	 			    	printf("except_fds for stdin.\n");
				    	exit(1);
					}

					//data available from socket
					if (FD_ISSET(newsd, &read_fds))
					{
						//get data from socket
						read_chat(newsd);
					}

					//socket exception
					if (FD_ISSET(newsd, &except_fds))
					{
						exit(1);
					}
			}
		}

		/* Make sure we don't leak open files */
		if (close(newsd) < 0)
			perror("close");
	}

	/* This will never happen */
	return 1;
}
