#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include "proto.h"

#define X10(a) a a a a a a a a a a
#define X100(a) X10(a) X10(a) X10(a) X10(a) X10(a) X10(a) X10(a) X10(a) X10(a) X10(a)
#define X1000(a) X100(a) X100(a) X100(a) X100(a) X100(a) X100(a) X100(a) X100(a) X100(a) X100(a)
#define X10000(a) X1000(a) X1000(a) X1000(a) X1000(a) X1000(a) X1000(a) X1000(a) X1000(a) X1000(a) X1000(a)

static const char BUF_CONTENTS[] = X10000("hello world");
static const size_t BUF_SIZE = sizeof(BUF_CONTENTS);

static void do_request()
{
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		perror("socket");
		return;
	}

	struct sockaddr_un addr = {0};
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, SOCK_PATH);
	int ret = connect(sock, (const struct sockaddr *) &addr, sizeof(addr));
	if (ret != 0) {
		perror("connect");
		close(sock);
		return;
	}

	int fd = open("temp.img", O_RDWR | O_CREAT);
	if (fd == -1) {
		perror("open /dev/zero");
		close(sock);
		return;
	}

	unlink("temp.img");
	ret = ftruncate(fd, BUF_SIZE);
	if (ret != 0) {
		perror("ftruncate");
		close(fd);
		close(sock);
		return;
	}

	void *buf_addr = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (buf_addr == MAP_FAILED) {
		perror("mmap");
		close(fd);
		close(sock);
		return;
	}

	memcpy(buf_addr, BUF_CONTENTS, BUF_SIZE);
	munmap(buf_addr, BUF_SIZE);

	char iobuf[50] = {0};
	struct req *request = (struct req *) iobuf;
	request->buf_size = BUF_SIZE;
	request->opcode = OP_FRY;
	struct iovec iov = { iobuf, sizeof(iobuf) };
	char cbuf[CMSG_SPACE(sizeof(int))] = {0};
	struct msghdr mhdr = {0};
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = cbuf;
	mhdr.msg_controllen = sizeof(cbuf);
	struct cmsghdr *chdr = CMSG_FIRSTHDR(&mhdr);
	chdr->cmsg_level = SOL_SOCKET;
	chdr->cmsg_type = SCM_RIGHTS;
	chdr->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(chdr), &fd, sizeof(fd));
	ret = sendmsg(sock, &mhdr, 0);
	if (ret < 0) {
		perror("sendmsg");
		close(sock);
		close(fd);
		return;
	}

	close(fd);

	char riobuf[50] = {0};
	struct iovec riovec = { riobuf, sizeof(riobuf) };
	char rcbuf[CMSG_SPACE(sizeof(int))] = {0};
	struct msghdr rmhdr = {0};
	rmhdr.msg_iov = &riovec;
	rmhdr.msg_iovlen = 1;
	rmhdr.msg_control = rcbuf;
	rmhdr.msg_controllen = sizeof(rcbuf);
	ret = recvmsg(sock, &rmhdr, 0);
	if (ret == -1) {
		perror("recvmsg");
		close(sock);
		return;
	}

	close(sock);
	fd = -1;
	for (struct cmsghdr *rchdr = CMSG_FIRSTHDR(&rmhdr); rchdr != NULL; rchdr = CMSG_NXTHDR(&rmhdr, rchdr)) {
		if (rchdr->cmsg_level == SOL_SOCKET && rchdr->cmsg_type == SCM_RIGHTS) {
			fd = *(int *) CMSG_DATA(rchdr);
		}
	}

	if (fd == -1) {
		printf("no fd returned\n");
		return;
	}

	void *rbuf = mmap(NULL, BUF_SIZE, PROT_READ, MAP_SHARED, fd, 0);
	if (rbuf == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return;
	}

	close(fd);

	bool same = true;
	for (size_t i = 0; i < BUF_SIZE; i++) {
		if (BUF_CONTENTS[i] ^ 0x42 != ((uint8_t *) rbuf)[i]) {
			same = false;
			break;
		}
	}

	if (same != 0) {
		printf("unexpected return buf\n");
	}

	munmap(rbuf, BUF_SIZE);
}

int main()
{
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (int i = 0; i < 1000 * 1000; i++)
	do_request();
	clock_gettime(CLOCK_MONOTONIC, &end);
	long diff_ns = end.tv_nsec - start.tv_nsec;
	long diff_s = end.tv_sec - start.tv_sec;
	int64_t diff = diff_ns + (1000 * 1000 * 1000 * diff_s);
	printf("finished in %ld\n", diff);
	return 0;
}
