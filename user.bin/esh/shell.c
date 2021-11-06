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

#include <minos/kobject.h>

#include "shell_command.h"
#include "esh.h"
#include "esh_internal.h"

static char __pwd[FILENAME_MAX];

static struct esh *pesh;
static char *clearmsg = "\x1b[2J\x1b[H";

#if 0
static int cd_main(int argc, char **argv)
{
	char __pwd_buf[FILENAME_MAX];
	char *arg;
	char ch;

	if (argc == 0 || grgc > 2) {
		printf("invalid argument\n");
		return -EINVAL;
	}

	if (argc == 1)
		return 0;

	memset(__pwd_buf, 0, FILENAME_MAX);
	if (strcmp(arg, '.') == 0)
		return 0;

	ch = *arg;
	if (ch == '/')
		__pwd_buf[0] = '/';
	else
		strcpy(__pwd_buf, __pwd);

	arg = argv[1];
	while (*arg == '/')
		arg++;
}

#define DEFINE_SHELL_CMD(name)				\
	extern int name##_main(int argc, char **argv);	\
	static struct shell_cmd shell_cmd_##name = {	\
		.func = name##_main,			\
		.cmd = #name,				\
	}

DEFINE_SHELL_CMD(cd);
DEFINE_SHELL_CMD(pwd);

static struct shell_cmd *shell_cmds[] = {
	&shell_cmd_ps,
	&shell_cmd_ls,
	&shell_cmd_cd,
	NULL,
};
#endif

int excute_shell_command(int argc, char **argv)
{
	return execv("/c/bin/ps.app", NULL);
}

static void __esh_putc(struct esh *esh, char c, void *arg)
{
	char buf[8];

	buf[0] = c;
	kobject_write(2, buf, 1, NULL, 0, 0);
}

static int handle_internal_cmd(int argc, char **argv, void *arg)
{
	if (strcmp(argv[0], "clear") == 0) {
		kobject_write(2, clearmsg, strlen(clearmsg), NULL, 0, -1);
		return 1;
	}

	return 0;
}

static void esh_excute_command(struct esh *esh,
		int argc, char **argv, void *arg)
{
	int ret;

	ret = handle_internal_cmd(argc, argv, arg);
	if (ret)
		return;

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
