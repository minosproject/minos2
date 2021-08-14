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

#define kobj_to_irqdesc(kobj)	\
	(struct irq_desc *)kobj->data

#define IRQ_KOBJ_RIGHT	\
	(KOBJ_RIGHT_RW | KOBJ_RIGHT_GRANT)

static int irq_kobj_open(struct kobject *kobj, handle_t handle, right_t rigt)
{
	struct irq_desc *idesc = kobj_to_irqdesc(kobj);

	return request_user_irq(idesc->hno, idesc->flags, kobj);
}

static long irq_kobj_read(struct kobject *kobj, void __user *data,
		size_t data_size, size_t *actual_data, void __user *extra,
		size_t extra_size, size_t *actual_extra, uint32_t timeout)
{
	struct irq_desc *idesc = kobj_to_irqdesc(kobj);
	unsigned long flags;
	int wait = 0, ret = 0;

	if (event_is_polled(&kobj->poll_struct, POLLIN))
		return -EBUSY;

	/*
	 * return as soon as fast if the irq is already pending.
	 */
	if (test_and_clear_bit(IRQ_FLAGS_PENDING_BIT, &idesc->flags))
		return 0;

	spin_lock_irqsave(&idesc->lock, flags);

	if (test_and_clear_bit(IRQ_FLAGS_PENDING_BIT, &idesc->flags))
		goto out;

	/*
	 * somebody already poll on this irq
	 */
	if (idesc->owner || timeout == 0) {
		ret = -EAGAIN;
		goto out;
	}

	idesc->owner = current_tid;
	__event_task_wait((unsigned long)idesc, TASK_EVENT_IRQ, timeout);
	wait = 1;
out:
	spin_unlock_irqrestore(&idesc->lock, flags);

	if (wait)
		ret = wait_event();

	if (ret == -EABORT) {
		spin_lock_irqsave(&idesc->lock, flags);
		idesc->owner = 0;
		spin_unlock_irqrestore(&idesc->lock, flags);
	} else if (ret == 0) {
		clear_bit(IRQ_FLAGS_PENDING_BIT, &idesc->flags);
	}

	return ret;
}

static long irq_kobj_write(struct kobject *kobj, void __user *data,
		size_t data_size, void __user *extra,
		size_t extra_size, uint32_t timeout)
{
	struct irq_desc *idesc = kobj_to_irqdesc(kobj);

	if (test_bit(IRQ_FLAGS_PENDING_BIT, &idesc->flags))
		pr_warn("irq %d state not correct\n", idesc->hno);

	irq_unmask(idesc->hno);

	return 0;
}

static int irq_kobj_close(struct kobject *kobj, right_t right)
{
	return 0;
}

static struct kobject_ops irq_kobj_ops = {
	.open	= irq_kobj_open,
	.recv	= irq_kobj_read,
	.send	= irq_kobj_write,
	.close	= irq_kobj_close,
};

static struct kobject *irq_kobject_create(right_t right,
		right_t right_req, unsigned long data)
{
	/*
	 * data[0-15] : the irq number.
	 * data[16-31] : the irq flags
	 */
	uint32_t irqnum = data & 0xffff;
	unsigned long flags = (data >> 16) & 0xffff;
	struct irq_desc *idesc;
	struct kobject *kobj;

	/*
	 * only root service can create an irq kobject.
	 */
	if (current_proc->kobj.right != KOBJ_RIGHT_ROOT)
		return ERROR_PTR(EPERM);

	if ((right & IRQ_KOBJ_RIGHT) != right)
		pr_warn("request unsupport right for irq 0x%x\n", right);

	if ((irqnum < SPI_IRQ_BASE) || (irqnum > BAD_IRQ))
		return ERROR_PTR(EINVAL);

	idesc = get_irq_desc(irqnum);
	if (!idesc)
		return ERROR_PTR(ENOENT);

	if (idesc->kobj)
		return ERROR_PTR(EBUSY);

	kobj = zalloc(sizeof(struct kobject));
	if (!kobj)
		return ERROR_PTR(ENOMEM);

	idesc->poll_event = (struct poll_event_kernel *)alloc_poll_event();
	if (!idesc->poll_event) {
		free(kobj);
		return ERROR_PTR(ENOMEM);
	}

	idesc->kobj = kobj;
	idesc->poll_event->release = 0;
	idesc->poll_event->event.events = POLLIN;
	idesc->poll_event->event.data.type = POLLIN_IRQ;
	idesc->flags = flags;
	idesc->hno = irqnum;
	kobject_init(kobj, KOBJ_TYPE_IRQ, right, (unsigned long)idesc);
	kobj->ops = &irq_kobj_ops;

	return kobj;
}
DEFINE_KOBJECT(irq, KOBJ_TYPE_IRQ, irq_kobject_create);
