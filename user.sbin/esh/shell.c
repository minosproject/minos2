/*
 * Copyright (C) 2020 Min Le (lemin9538@gmail.com)
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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <minos/kobject.h>

#include "shell_command.h"
#include "esh.h"
#include "esh_internal.h"

static struct esh *pesh;

int excute_shell_command(int argc, char **argv)
{
#if 0
        struct shell_command *cmd;
        extern unsigned long __shell_command_start;
        extern unsigned long __shell_command_end;

        if ((argc == 0) || (argv[0] == NULL))
                return -EINVAL;

        section_for_each_item(__shell_command_start,
                                __shell_command_end, cmd) {
                if (strcmp(argv[0], cmd->name) == 0) {
                        if (cmd->hdl == NULL)
                                return -ENOENT;

                        return cmd->hdl(argc, argv);
                }   
        }
#endif
        return -ENOENT;
}

static void __esh_putc(struct esh *esh, char c, void *arg)
{
	char buf[8];

	buf[0] = c;
	kobject_write(2, buf, 1, NULL, 0, 0);
}

static void esh_excute_command(struct esh *esh,
		int argc, char **argv, void *arg)
{
	int ret;

	ret = excute_shell_command(argc, argv);
	if (ret == -ENOENT)
		printf("Command %s not found\n", argv[0]);
}

int main(int argc, char **argv)
{
	char buf[32];
	int ret, i;
	char ch;

	pesh = esh_init();
	esh_register_command(pesh, esh_excute_command);
	esh_register_print(pesh, __esh_putc);

	printf("\n");
	printf(" _   _   _   _   _   _\n");
	printf("/ \\ / \\ / \\ / \\ / \\ / \\\n");
	printf("(M | i | n | o | s | 2 )\n");
	printf("\\_/ \\_/ \\_/ \\_/ \\_/ \\_/\n");
	printf("\n  Welcome to Minos2 \n");
	printf("\n");

	esh_rx(pesh, '\n');

	for (; ;) {
		ret = fread(buf, 1, 32, stdin);
		if (ret < 0)
			break;

		for (i = 0; i < ret; i++) {
			ch = buf[i];
			if (ch == '\r')
				ch = '\n';
			esh_rx(pesh, ch);
		}
	}

	return 0;
}
