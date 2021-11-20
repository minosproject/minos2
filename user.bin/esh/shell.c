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

static struct esh *pesh;

DEFINE_SHELL_CMD(cd, "change directory");
DEFINE_SHELL_CMD(pwd, "current directory");
DEFINE_SHELL_CMD(clear, "clear the screen");
DEFINE_SHELL_CMD(help, "get help");
DEFINE_SHELL_CMD(ls, "list directory");
DEFINE_SHELL_CMD(exec, "run a application on the filesystem");

struct shell_cmd *shell_cmds[] = {
	&shell_cmd_cd,
	&shell_cmd_pwd,
	&shell_cmd_clear,
	&shell_cmd_ls,
	&shell_cmd_help,
	&shell_cmd_exec,
	NULL,
};

static void __esh_putc(struct esh *esh, char c, void *arg)
{
	char buf[8];

	buf[0] = c;
	kobject_write(2, buf, 1, NULL, 0, 0);
}

static int esh_excute_fs_command(int argc, char **argv, void *arg)
{
	char buf[FILENAME_MAX];
	int len;
	pid_t pid;

	/*
	 * the application must put under /c/bin folder, otherwise
	 * need use exec command to exec the application.
	 */
	if ((strlen(argv[0]) + strlen("/c/bin/") + 1) > FILENAME_MAX)
		return -ENAMETOOLONG;

	len = sprintf(buf, "%s", "/c/bin/");
	strcpy(&buf[len], argv[0]);

	if (access(buf, X_OK) != 0) {
		printf("no such application %s\n", buf);
		return -EACCES;
	}

	pid = execv(buf, &argv[1]);
	if (pid <= 0) {
		printf("exec %s failed %d\n", buf, pid);
		return pid;
	}

	/*
	 * run in background ?
	 */
	if (strcmp(argv[argc - 1], "&") == 0)
		return 0;
	else
		return waitpid(pid, NULL, 0);
}

static void esh_excute_command(struct esh *esh, int argc, char **argv, void *arg)
{
	struct shell_cmd *command;
	int idx = 0;

	for (;;) {
		command = shell_cmds[idx++];
		if (command == NULL)
			break;

		if (strcmp(argv[0], command->cmd) == 0) {
			command->func(argc, argv);
			return;
		}
	}

	if (esh_excute_fs_command(argc, argv, arg) == -ENOENT)
		printf("Command \"%s\" not found\n", argv[0]);
}

int main(int argc, char **argv)
{
	char buf[32];
	int ret, i;
	char ch;

	pesh = esh_init();
	esh_command_init();
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

