#ifndef __proto_h_
#define __proto_h_

static const char SOCK_PATH[] = "server.sock";

enum opcodes {
	OP_ECHO,
	OP_FRY
};

struct req {
	uint32_t opcode;
	char comment[8];
	uint64_t buf_size;
};

#endif
