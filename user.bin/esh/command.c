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
#include <dirent.h>
#include <limits.h>

#include <minos/kobject.h>

#include "shell_command.h"
#include "esh.h"
#include "esh_internal.h"
#include "shell.h"

int exit_main(int argc, char **argv)
{
	exit(0);
}

int cd_main(int argc, char **argv)
{
	char cwd[PATH_MAX];
	char *dir;

	dir = (argc == 2) ? argv[1] : NULL;
	if (dir == NULL) {
		printf("cd : please select a directory\n");
		return -EINVAL;
	}

	if (strcmp(dir, ".") == 0)
		return 0;
	while (*dir == ' ') /*skip all space*/
		dir++;
	if (dir[0] == 0) {
		chdir("/");
		return 0;
	}

	getcwd(cwd, PATH_MAX);

	if (strcmp(dir, "..") == 0) {
		if (strcmp(cwd, "/") == 0)
			return 0;

		int len = strlen(cwd)  - 1;
		for (int i=len; i>=0; i--) {
			if (cwd[i] == '/') {
				cwd[i] = 0;
				break;
			}
		}
		if (cwd[0] == 0) {
			chdir("/");
			return 0;
		}
	} else if (dir[0] == '/') {
		strcpy(cwd, dir);
	} else {
		int len = strlen(cwd);
		if (cwd[len-1] != '/') {
			cwd[len] = '/';
			len++;
		}
		strcpy(cwd+len, dir);
	}

	if (chdir(cwd))
		printf("cd: no such directory %s !\n", cwd);

	return 0;
}

int pwd_main(int argc, char **argv)
{
	char buf[PATH_MAX];
	printf("%s\n", getcwd(buf, PATH_MAX));
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

static void do_ls(DIR *dir)
{
	struct dirent *de;
	int cnt = 0;
	char isdir;

	while ((de = readdir(dir)) != NULL) {
		if ((de->d_type == DT_DIR) || (de->d_type == DT_SRV))
			isdir = 'd';
		else
			isdir = '-';
		printf("%c%c%c%c    %s%c\n", isdir, 'r', 'w', '-',
				de->d_name, isdir == 'd' ? '/':' ');
		cnt++;
	}

	printf("total   %d\n", cnt);
}

int ls_main(int argc, char **argv)
{
	DIR *dir;

	if (argc > 2) {
		printf("ls: wrong argument\n");
		return -EINVAL;
	}

	dir = (argc == 2) ? opendir(argv[1]) : getcdir();
	if (dir == NULL) {
		printf("ls: no such directory\n");
		return -EINVAL;
	}

	do_ls(dir);

	if (argc == 2)
		closedir(dir);
	else
		rewinddir(dir);

	return 0;
}

int exec_main(int argc, char **argv)
{
	pid_t pid;

	if (argc < 2) {
		printf("exec : wrong argument !\n");
		return -EINVAL;
	}

	if (access(argv[1], X_OK) != 0) {
		printf("%s can not be executed !\n", argv[1]);
		return -EACCES;
	}

	pid = execv(argv[1], &argv[2]);
	if (pid <= 0) {
		printf("exec %s failed %d\n", argv[1], pid);
		return pid;
	}

	return waitpid(pid, NULL, 0);
}

void esh_command_init(void)
{

}
