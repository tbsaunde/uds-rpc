#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>

#include "proto.h"

static void fry(void *addr, uint64_t size)
{
	uint64_t *buf = (uint64_t *)addr;
	for (uint64_t i = 0; i < size / 8; i++) {
		buf[i] = buf[i] ^ 0x4242424242424242;
	}
}

static void handle_req(int sock)
{
	char cbuf[4096] = {0};
	char iobuf[100] = {0};
	struct iovec iov = { &iobuf, sizeof(iobuf) };
	struct msghdr mhdr = {0};
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = cbuf;
	mhdr.msg_controllen = sizeof(cbuf);
	int ret = recvmsg(sock, &mhdr, 0);
	if (ret < 0) {
		perror("recvmsg");
		return;
	}

	if (ret < sizeof(req)) {
		printf("too small msg size %d\n", ret);
		return;
	}

	int fd = -1;
	for (struct cmsghdr *chdr = CMSG_FIRSTHDR(&mhdr); chdr != NULL; chdr = CMSG_NXTHDR(&mhdr, chdr)) {
		if (chdr->cmsg_level == SOL_SOCKET && chdr->cmsg_type == SCM_RIGHTS) {
			fd = *(int *) CMSG_DATA(chdr);
		}
	}

	if (fd < 0) {
		printf("client didn't send a fd\n");
		return;
	}

	struct req *request = (struct req *) iov.iov_base;
	uint64_t size = request->buf_size;
	void *addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		return;
	}

	if (request->opcode == OP_FRY) {
		fry(addr, size);
	} else if (request->opcode == OP_ECHO) {
		// nothing to do.
	} else {
		printf("bad opcode");
	}

	munmap(addr, size);

	union {
		cmsghdr align;
		char buf[CMSG_SPACE(sizeof(int))];
	} u = {0};
	struct msghdr rmsg = {0};
	rmsg.msg_iov = &iov;
	rmsg.msg_iovlen = 1;
	rmsg.msg_control = u.buf;
	rmsg.msg_controllen = sizeof(u.buf);
	struct cmsghdr *rchdr = CMSG_FIRSTHDR(&rmsg);
	rchdr->cmsg_level = SOL_SOCKET;
	rchdr->cmsg_type = SCM_RIGHTS;
	rchdr->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(rchdr), &fd, sizeof(int));
	ret = sendmsg(sock, &rmsg, 0);
	if (ret == -1) {
		perror("sendmsg");
	}

	close(fd);
}

int main()
{
	unlink(SOCK_PATH);

	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket");
		return 1;
	}

	struct sockaddr_un addr = {0};
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SOCK_PATH);
	int ret = bind(sock, (const struct sockaddr *) &addr, sizeof(addr));
	if (ret < 0) {
		perror("bind");
		return 2;
	}

	ret = listen(sock, 20);
	if (ret < 0) {
		perror("listen");
		return 3;
	}

	while (true) {
		int fd = accept(sock, NULL, NULL);
		if (fd < 0) {
			perror("accept");
			continue;
		}

		handle_req(fd);
		close(fd);
	}

	return 0;
}

