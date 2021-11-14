#ifndef __ESH_SHELL_H__
#define __ESH_SHELL_H__

#define SHELL_CMD_NAME_SIZE	32

struct shell_cmd {
	int (*func)(int argc, char **argv);
	char *cmd;
	char *helpmsg;
};

#define DEFINE_SHELL_CMD(name, __helpmsg__)		\
	extern int name##_main(int argc, char **argv);	\
	static struct shell_cmd shell_cmd_##name = {	\
		.func = name##_main,			\
		.cmd = #name,				\
		.helpmsg = #__helpmsg__,		\
	}

extern struct shell_cmd *shell_cmds[];
void esh_command_init(void);

#endif
