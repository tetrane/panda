#include "panda/plugin.h"

// return: 0 if ok, otherwise < 0
static __attribute__((nonnull(3))) int read_virtual_memory(uint64_t va, uint32_t len, uint8_t * buffer)
{
	return panda_virtual_memory_read(first_cpu, va, buffer, len);
}

// return: register size if ok, otherwise < 0
static __attribute__((nonnull(3))) int read_register(int32_t reg_group, int32_t reg_id, uint64_t * reg_val)
{
	X86CPU * cpu = X86_CPU(first_cpu);
	CPUX86State * env = &cpu->env;

	switch (reg_group) {
	case GP:
		if (RAX <= reg_id && reg_id <= R15) {
			*reg_val = env->regs[reg_id];
			return sizeof(env->regs[reg_id]);
		} else {
			return -1;
		}

	case PC:
		*reg_val = env->eip;
		return sizeof(env->eip);

	case SEG:
		if (ES <= reg_id && reg_id <= GS) {
			*reg_val = env->segs[reg_id].selector;
			return sizeof(env->segs[reg_id].selector);
		} else {
			return -1;
		}

	case CTRL:
		if (CR0 <= reg_id && reg_id <= CR4 && reg_id != CR1) {
			*reg_val = env->cr[reg_id];
			return sizeof(env->cr[reg_id]);
		} else {
			return -1;
		}

	case MSR:
		switch (reg_id)
		{
		case X86_MSR_LSTAR:
			*reg_val = env->lstar;
			return sizeof(env->lstar);

		case X86_MSR_GSBASE:
			*reg_val = env->segs[R_GS].base;
			return sizeof(env->segs[R_GS].base);

		case X86_MSR_KERNELGSBASE:
			*reg_val = env->kernelgsbase;
			return sizeof(env->kernelgsbase);

		default:
			return -1;
		}

	default:
		return -1;
	}
}

// return: always 0
static int set_breakpoint(uint64_t va)
{
	return cpu_breakpoint_insert(first_cpu, va, BP_GDB, NULL);
}

// return: 0 if ok, otherwise < 0
static int remove_breakpoint(uint64_t va)
{
	return cpu_breakpoint_remove(first_cpu, va, BP_GDB);
}

static int remove_all_breakpoints(void)
{
	cpu_breakpoint_remove_all(first_cpu, BP_GDB);
	return 0; // always success
}

static int set_watchpoint(uint64_t va, uint32_t len, int wp)
{
	switch (wp) {
		case WP_READ:
		case WP_WRITE:
		case WP_ACCESS:
			return cpu_watchpoint_insert(first_cpu, va, len, wp, NULL);

		default:
			return -1;
	}
}

static int remove_watchpoint(uint64_t va, uint32_t len)
{
	return cpu_watchpoint_remove(first_cpu, va, len, BP_GDB);
}

static int remove_all_watchpoints(void)
{
	cpu_watchpoint_remove_all(first_cpu, BP_GDB);
	return 0; // always success
}

static int pause_vm(void)
{
	if (runstate_is_running()) {
		return vm_stop(RUN_STATE_PAUSED);
	}
	return 0;
}

static int step_vm(void)
{
	cpu_single_step(first_cpu, SSTEP_ENABLE | SSTEP_NOIRQ | SSTEP_NOTIMER);
	if (!runstate_needs_reset()) {
		vm_start();
	}
	return 0; // always success
}

static int continue_async_vm(void)
{
	if (!runstate_needs_reset()) {
		cpu_single_step(first_cpu, 0); // disable single step (if the VM is in)
		vm_start();
	}
	return 0; // always success
}
