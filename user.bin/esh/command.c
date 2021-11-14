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
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#include <minos/kobject.h>

#include "shell_command.h"
#include "esh.h"
#include "esh_internal.h"
#include "shell.h"

static char __pwd[FILENAME_MAX];

int cd_main(int argc, char **argv)
{
	return 0;
}

int pwd_main(int argc, char **argv)
{
	printf("%s\n", __pwd);
	return 0;
}

int clear_main(int argc, char **argv)
{
	static char *clearmsg = "\x1b[2J\x1b[H";

	kobject_write(2, clearmsg, strlen(clearmsg), NULL, 0, -1);
	return 0;
}

int help_main(int argc, char **argv)
{
	char *cmd = (argc == 2) ? argv[1] : NULL;
	struct shell_cmd *command;
	int idx = 0;

	for (;;) {
		command = shell_cmds[idx++];
		if (command == NULL)
			break;

		if (cmd == NULL) {
			printf("%s : %s\n", command->cmd, command->helpmsg);
		} else {
			if (strcmp(cmd, command->cmd) == 0) {
				printf("%s : %s\n", command->cmd, command->helpmsg);
				return 0;
			}
		}
	}

	if (cmd)
		printf("help : no such command \"%s\"\n", cmd);

	return 0;
}

int ls_main(int argc, char **argv)
{
	return 0;
}

int exec_main(int argc, char **argv)
{
	return 0;
}

void esh_command_init(void)
{
	strcpy(__pwd, "/");
}
