#include "qemu/osdep.h"

#include "qemu/cutils.h"
#include "qmp-commands.h"
#include "qapi/error.h"
#include "sysemu/sysemu.h"
#include "sysemu/char.h"
#include "monitor/monitor.h"

#include "exec/reven-vmi.h"
#include "reven-vmi-handlers.c"

static const char TYPE_CHARDEV_VMI[] = "chardev-vmi";
static const char ID_CHARDEV_VMI[] = "vmi";
static CharBackend chr_backend;
static VMChangeStateEntry *sync_wait_handler = NULL;

void __attribute__((nonnull(1, 2))) qmp_open_vmi(const char *socket_path, Error **errp)
{
	char device[128] = { 0 };
	snprintf(device, sizeof(device), "unix:%s", socket_path);
	if (vmiserver_start(device) != 0) {
		int errsv = errno;
		if (errsv != 0) {
			error_setg(errp, "VMI initialization failed: %s", strerror(errsv));
		} else {
			error_setg(errp, "VMI initialization failed unexpectedly");
		}
	} else {
		error_setg(errp, "VMI socket successfully opened");
	}
	return;
}

void qmp_close_vmi(Error **errp)
{
	qemu_chr_fe_deinit(&chr_backend);
	qmp_chardev_remove(ID_CHARDEV_VMI, errp);
	return;
}

static void vmi_monitor_open(Chardev *chr, ChardevBackend *backend, bool *be_openned, Error **errp)
{
	*be_openned = false;
}

static int vmi_monitor_write(Chardev *chr, const uint8_t *buf, int len)
{
	return qemu_chr_fe_write_all(&chr_backend, buf, len);
}

static void char_vmi_class_init(ObjectClass *oc, void *data)
{
	ChardevClass *cc = CHARDEV_CLASS(oc);

	cc->internal = true;
	cc->open = vmi_monitor_open;
	cc->chr_write = vmi_monitor_write;
}

static void register_types(void)
{
	static const TypeInfo char_vmi_type_info = {
		.name = TYPE_CHARDEV_VMI,
		.parent = TYPE_CHARDEV,
		.class_init = char_vmi_class_init,
	};

	type_register_static(&char_vmi_type_info);
}

static int vmi_chr_can_receive(void *opaque)
{
	return sizeof(vmi_request_t);
}

// response: [data length: 4 bytes] + [data buffer: data length]
static void put_response(const uint8_t *buf, uint32_t size)
{
	if (size > 0) {
		// size of header is included in the response length
		uint32_t resp_len = size + sizeof(uint32_t);
		uint8_t *resp_buf = g_malloc(resp_len);

		memcpy(resp_buf, &size, sizeof(uint32_t));
		memcpy(resp_buf + sizeof(uint32_t), buf, size);

		qemu_chr_fe_write_all(&chr_backend, resp_buf, resp_len);
		g_free(resp_buf);
	} else {
		qemu_chr_fe_write_all(&chr_backend, (const uint8_t*)&size, sizeof(uint32_t));
	}
}

static inline void put_empty_response(void)
{
	put_response(NULL, 0);
}

#define put_typed_response(resp) put_response((const uint8_t*)resp, sizeof(*(resp)))

static void sync_wait_callback(void *opaque, int running, RunState state)
{
	if (running) {
		return;
	}

	switch (state) {
	case RUN_STATE_DEBUG: {
		int bp_err = 0; // always success
		put_typed_response(&bp_err);
		if (sync_wait_handler) {
			qemu_del_vm_change_state_handler(sync_wait_handler);
			sync_wait_handler = NULL;
		}
		return;
	}

	default:
		break;
	}
}

static void handle_request(const vmi_request_t *req)
{
	if (sync_wait_handler) {
		qemu_del_vm_change_state_handler(sync_wait_handler);
		sync_wait_handler = NULL;
	}

	switch (req->request_type)
	{
	case MEM_READ: {
		uint32_t mem_size = req->request_data.memory_size;
		if (mem_size == 0) {
			put_empty_response();
		} else {
			uint8_t *buf = g_malloc(mem_size);
			if (read_virtual_memory(req->request_data.virtual_address, mem_size, buf) >= 0) {
				put_response(buf, mem_size);
			} else {
				put_empty_response();
			}
			g_free(buf);
		}
		return;
	}

	case REG_READ: {
		union {
			uint64_t reg_val_64;
			uint32_t reg_val_32;
		} reg_val;
		int reg_size = read_register(req->request_data.register_group, req->request_data.register_id, &reg_val.reg_val_64);
		switch (reg_size)
		{
		case 8:
			put_typed_response(&reg_val.reg_val_64);
			break;

		case 4:
			put_typed_response(&reg_val.reg_val_32);
			break;

		default:
			put_empty_response();
			break;
		}
		return;
	}

	case BP: {
		int bp_err;
		switch (req->request_action)
		{
		case SET:
			bp_err = set_breakpoint(req->request_data.virtual_address);
			break;

		case REM:
			bp_err = remove_breakpoint(req->request_data.virtual_address);
			break;

		case REM_ALL:
			bp_err = remove_all_breakpoints();
			break;

		default:
			return put_empty_response();
		}

		return put_typed_response(&bp_err);
	}

	case WP_READ:
	case WP_WRITE: {
		int wp_err;
		switch (req->request_action)
		{
		case SET:
			wp_err = set_watchpoint(req->request_data.virtual_address, req->request_data.memory_size, req->request_type);
			break;

		case REM:
			wp_err = remove_watchpoint(req->request_data.virtual_address, req->request_data.memory_size);
			break;

		case REM_ALL:
			wp_err = remove_all_watchpoints();
			break;

		default:
			return put_empty_response();
		}

		return put_typed_response(&wp_err);
	}

	case EXEC: {
		int ex_err;
		switch (req->request_action)
		{
		case PAUSE:
			ex_err = pause_vm();
			break;

		case STEP:
			sync_wait_handler = qemu_add_vm_change_state_handler(sync_wait_callback, NULL);
			ex_err = step_vm();
			return; // no immediate response

		case CONTINUE:
			sync_wait_handler = qemu_add_vm_change_state_handler(sync_wait_callback, NULL);
			ex_err = continue_async_vm();
			return; // no immediate response

		case CONTINUE_ASYNC:
			ex_err = continue_async_vm();
			break; // response immediately

		default:
			return put_empty_response();
		}

		return put_typed_response(&ex_err);
	}

	default:
		return put_empty_response();
	}
}

static void vmi_chr_receive(void *opaque, const uint8_t *buf, int size)
{
	vmi_request_t req;

	if (size != sizeof(vmi_request_t)) {
		put_empty_response();
	} else {
		// type punning
		memcpy(&req, buf, size);
		handle_request(&req);
	}
}

static void vmi_chr_event(void *opaque, int event)
{
	return;
}

int vmiserver_start(const char *device)
{
	char vmi_device_name[128] = {0};
	Chardev *chr_dev;
	Chardev *mon_chr_dev;

	if (!device) {
		return -1;
	}

	if (strstart(device, "unix:", NULL)) {
		snprintf(vmi_device_name, sizeof(vmi_device_name),
		         "%s,nowait,nodelay,server", device);
	}

	chr_dev = qemu_chr_new_noreplay(ID_CHARDEV_VMI, vmi_device_name);
	if (!chr_dev) {
		return -1;
	}

	mon_chr_dev = qemu_chardev_new(ID_CHARDEV_VMI, TYPE_CHARDEV_VMI, NULL, &error_abort);
	monitor_init(mon_chr_dev, 0);

	if (!qemu_chr_fe_init(&chr_backend, chr_dev, &error_abort)) {
		return -1;
	}

	qemu_chr_fe_set_handlers(&chr_backend, vmi_chr_can_receive, vmi_chr_receive,
	                         vmi_chr_event, NULL, NULL, true);

	return 0;

}

type_init(register_types);
