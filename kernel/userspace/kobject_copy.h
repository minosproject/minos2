#ifndef __MINOS_KOBJECT_COPY_H__
#define __MINOS_KOBJECT_COPY_H__

ssize_t kobject_copy_ipc_data(struct task *tdst,
		struct task *tsrc, int check_size);

ssize_t kobject_copy_extra_data(struct task *tdst,
		struct task *tsrc, int check_size);

ssize_t kobject_copy_ipc_payload(struct task *dtsk, struct task *ttsk,
		size_t *actual_data, size_t *actual_extra,
		int check_data, int check_extra);

#endif
