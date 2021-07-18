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

static struct kobject root_ns;
static DEFINE_SPIN_LOCK(namespace_lock);

static inline void add_namespace(struct kobject *root, struct kobject *n)
{
	/*
	 * all namespace will link to the root namespace or
	 * device namespace. the three list member will used
	 * as below purpose:
	 * list - link to the request handlder if a normal kobject.
	 *        if this is a namespace, it will link to the root
	 *        namespace.
	 * child - only used for namespace kobject to link all his
	 *        children.
	 * parent - used for other kobject except namespace.
	 */
	spin_lock(&namespace_lock);
	list_add_tail(&root->child, &n->list);
	spin_unlock(&namespace_lock);
}

static inline void delete_namespace(struct kobject *n)
{
	spin_lock(&namespace_lock);
	list_del(&n->list);
	spin_unlock(&namespace_lock);
}

static struct kobject *__find_process_kobject(struct kobject *root, char *name)
{
	struct kobject *srv;

	spin_lock(&namespace_lock);
	list_for_each_entry(srv, &root->child, list) {
		if ((!srv->name) || (srv->right == KOBJ_RIGHT_NONE))
			continue;

		if (strcmp(srv->name, name) == 0) {
			spin_unlock(&namespace_lock);
			return srv;
		}
	}
	spin_unlock(&namespace_lock);

	return NULL;
}

int get_kobject_from_namespace(char *name, struct kobject **kobj, char **path)
{
	char *str, *ns_name, *srv_name, *extra_name;
	struct kobject *root = &root_ns;
	char *tmp = name;
	struct kobject *ns, *srv;

	*kobj = NULL;
	*path = NULL;

	if (!name || (*name == '/'))
		return -EINVAL;

	str = strchr(tmp, '/');
	if (str == NULL)
		return -EINVAL;
	*str = 0;

	ns_name = tmp;
	srv_name = str + 1;

	/*
	 * get the extra_name, the extra string will pass to the
	 * process as a parameter.
	 */
	str = strchr(srv_name, '/');
	if (str == NULL)
		extra_name = NULL;
	else
		extra_name = str + 1;
	*str = 0;

	ns = __find_process_kobject(root, ns_name);
	if (!ns)
		return -ENOENT;

	srv = get_kobject_by_name(ns, srv_name);
	if (!srv)
		return -ENOENT;

	*kobj = srv;
	*path = extra_name;

	return 0;
}

void register_namespace(struct process *proc)
{
	add_namespace(&root_ns, &proc->kobj);
}

static int __init_text root_namespace_init(void)
{
	static char *root_ns_name = "/";

	kobject_init(&root_ns, 0, 0, 0, 0, 0);
	root_ns.name = root_ns_name;

	return 0;
}
subsys_initcall(root_namespace_init);
