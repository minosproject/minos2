/*
 * Copyright (C) 2021 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <minos/minos.h>
#include <minos/kobject.h>
#include <minos/uaccess.h>
#include <minos/mm.h>
#include <minos/sched.h>
#include <minos/irq.h>
#include <minos/poll.h>

struct irq_event {
	struct kobject kobj;
	struct irq_desc *idesc;
	struct event event;
	struct poll_event_kernel poll_event;
};

#define kobj_to_irq_event(kobj) (struct irq_event *)kobj->data

#define IRQ_RIGHT	KOBJ_RIGHT_RW
#define IRQ_RIGHT_MASK	(0)

static int do_handle_userspace_irq(uint32_t irq, void *data)
{
	struct irq_event *ievent = (struct irq_event *)data;
	struct kobject *kobj = &ievent->kobj;
	struct irq_desc *idesc = ievent->idesc;
	struct poll_struct *ps = kobj->poll_struct;

	ASSERT(idesc != NULL);
	irq_mask(irq);

	/*
	 * Whether this irq has been listened. If this irq is polled
	 * by one process, just send an event to the task.
	 */
	if (event_is_polled(ps, EV_IN)) {
		poll_event_send_static(ps->pevents[EV_IN], &ievent->poll_event);
		return 0;
	} else {
		set_bit(IRQ_FLAGS_PENDING_BIT, &idesc->flags);
		smp_wmb();

		return wake(&ievent->event, 0);
	}
}

static inline int request_user_irq(uint32_t irq, unsigned long flags, void *pdata)
{
	return request_irq(irq, do_handle_userspace_irq, flags | IRQ_FLAGS_USER,
			current->name, pdata);
}

static int irq_kobj_open(struct kobject *kobj, handle_t handle, right_t rigt)
{
	struct irq_event *ievent = kobj_to_irq_event(kobj);
	struct irq_desc *idesc = ievent->idesc;

	return request_user_irq(idesc->hno, idesc->flags, ievent);
}

static long irq_kobj_read(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct irq_event *ievent = kobj_to_irq_event(kobj);
	struct irq_desc *idesc = ievent->idesc;
	long ret = 0;

	if (event_is_polled(kobj->poll_struct, EV_IN))
		return -EPERM;

	ret = wait_event(&ievent->event,
			test_and_clear_bit(IRQ_FLAGS_PENDING_BIT, &idesc->flags),
			timeout);
	if (ret == 0)
		clear_bit(IRQ_FLAGS_PENDING_BIT, &idesc->flags);

	return ret;
}

static long irq_kobj_write(struct kobject *kobj, void __user *data,
		size_t data_size, void __user *extra,
		size_t extra_size, uint32_t timeout)
{
	struct irq_event *ievent = kobj_to_irq_event(kobj);

	irq_unmask(ievent->idesc->hno);

	return 0;
}

static int irq_kobj_close(struct kobject *kobj, right_t right, struct process *proc)
{
	return 0;
}

static struct kobject_ops irq_kobj_ops = {
	.open	= irq_kobj_open,
	.recv	= irq_kobj_read,
	.send	= irq_kobj_write,
	.close	= irq_kobj_close,
};

int irq_kobject_create(struct kobject **rkobj, right_t *right, unsigned long data)
{
	/*
	 * data[0-15] : the irq number.
	 * data[16-31] : the irq flags
	 */
	uint32_t irqnum = data & 0xffff;
	unsigned long flags = (data >> 16) & 0xffff;
	struct irq_event *ievent;
	struct irq_desc *idesc;

	/*
	 * only root service can create an irq kobject.
	 */
	if (!proc_can_hwctl(current_proc))
		return -EPERM;

	if ((irqnum < SPI_IRQ_BASE) || (irqnum > BAD_IRQ))
		return -EINVAL;

	idesc = get_irq_desc(irqnum);
	if (!idesc)
		return -ENOENT;

	ievent = zalloc(sizeof(struct irq_event));
	if (!ievent)
		return -ENOMEM;

	event_init(&ievent->event, OS_EVENT_TYPE_IRQ, ievent);
	ievent->poll_event.event.events = POLLIN;
	ievent->poll_event.event.data.type = 0;

	ievent->idesc = idesc;
	idesc->flags = flags;
	idesc->hno = irqnum;

	kobject_init(&ievent->kobj, KOBJ_TYPE_IRQ,
			IRQ_RIGHT_MASK, (unsigned long)ievent);
	ievent->kobj.ops = &irq_kobj_ops;
	*rkobj = &ievent->kobj;
	*right = IRQ_RIGHT;

	return 0;
}
DEFINE_KOBJECT(irq, KOBJ_TYPE_IRQ, irq_kobject_create);
