#ifndef __MINOS_CHANNEL_H__
#define __MINOS_CHANNEL_H__

/*
 * object 代表内核资源，资源是全局的 每个资源就是一个object,
 * 每个但是资源会属于某个id  然后可以在各个进程中传递资源，
 * 每个资源会有唯一的id，资源从属于某一个进程，当资源授予某一个
 * 进程的时候，返回一个hanlde， 这个handle属于进程描述符表中。
 * 资源传递通过channel来传递.
 *
 * 每个server会有默认channel()  ----> channel 0, register sever的时候会
 * 注册channel的功能
 *
 * 名字叫做port. 每个server使用port对外提供服务，每个port的功能可以不一样
 * 比如一个典型的文件系统服务只有一个port
 *
 * 另外对于一个带有双工的网卡，可以有两个thread, 一个tx thread一个rx thread
 * 或者irq thread，则至少会有两个port
 *
 *  /dev/marvel/port_tx	// 文件类型 普通 port
 *  /dev/marver/port_rx	// 文件类型
 *  /proc/port0
 *
 */

struct object {
	uint8_t type;
};

struct vma_handle {
	struct object object;
};

struct pmo {
	struct object object;
};

// 客户端和服务端通信需要协议。

struct channel {
	int 
	mutex_t mutex;
};

收到了vmo，调用vmo_map()map到自己的内存区域，然后可以进行读写。


fd = open("/dev/procsrv");

write(fd, &msg, sizeof(msg));   // create_process

ipc_recv(&msg, sizeof(msg), NULL);
if () {

}

switch (request) {
case CREATE_PROCESS:
	break;
}

open("/dev/data/bin.elf");

vmo_handle= create_vmo(proc, xxx);

ret = ipc_send(fd, &msg, sizeof(msg));


/*
 * 解析xxx
 */

ipc_send(fd, &msg, );	//read segment data

ipc_send(fd, &msg);	// read segment data

close(vmo_handle); //可以不需要close

ipc_send(fd, void *addr, size_t size, int flags);


#endif
