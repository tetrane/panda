#pragma once

#include <stdint.h>

typedef enum x86_register_group_t {
	GP,
	PC,
	SEG,
	CTRL,
	MSR,
} vmi_x86_register_group_t;

typedef enum x86_register_t {
	// general purpose
	RAX = 0,
	RCX,
	RDX,
	RBX,
	RSP,
	RBP,
	RSI,
	RDI,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,

	// segment
	ES = 0,
	CS,
	SS,
	DS,
	FS,
	GS,

	// control
	CR0 = 0,
	CR1, // unused
	CR2,
	CR3,
	CR4,

	// MSR
	X86_MSR_LSTAR = 0xc0000082,
	X86_MSR_GSBASE = 0xc0000101,
	X86_MSR_KERNELGSBASE = 0xc0000102,
} vmi_x86_register_t;

typedef enum request_type_t {
	// break/watch points (set/remove)
	BP = 0x10,
	WP_READ = 0x01,
	WP_WRITE = 0x02,
	WP_ACCESS = WP_READ | WP_WRITE,

	// memory/registers (read only)
	MEM_READ,
	REG_READ,

	// continue, pause, step
	EXEC,
} vmi_request_type_t;

typedef enum request_action_t {
	SET,
	REM,
	REM_ALL,

	PAUSE,
	STEP,
	CONTINUE,
	CONTINUE_ASYNC,
} vmi_request_action_t;

typedef struct __attribute__((__packed__)) request_t {
	struct __attribute__((__packed__)) {
		uint32_t request_type;
		uint32_t request_action;
	};
	struct __attribute__((__packed__)) {
		union {
			uint64_t virtual_address;
			struct __attribute__((__packed__)) {
				uint32_t register_group;
				uint32_t register_id;
			};
		};
		uint32_t memory_size;
	} request_data;
} vmi_request_t;

int vmiserver_start(const char *device);
