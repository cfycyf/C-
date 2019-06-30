/*
 * socketpair基本用法： 
 * 1. 这对套接字可以用于全双工通信，每一个套接字既可以读也可以写。
 * 例如，可以往sv[0]中写，从sv[1]中读；或者从sv[1]中写，从sv[0]中读； 
 * 2. 如果往一个套接字(如sv[0])中写入后，再从该套接字读时会阻塞，只能在另一个套接字中(sv[1])上读成功； 
 * 3. 读、写操作可以位于同一个进程，也可以分别位于不同的进程，
 * 如父子进程。如果是父子进程时，一般会功能分离，一个进程用来读，一个用来写。
 * 因为文件描述副sv[0]和sv[1]是进程共享的，所以读的进程要关闭写描述符, 反之，写的进程关闭读描述符。
 */

#include <stdio.h> 
#include <string.h> 
#include <unistd.h> 
#include <sys/types.h> 
#include <error.h> 
#include <errno.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <signal.h> 

int pip_fd[2];

void sig_hander(int sig)
{
	if(write(pip_fd[1], &sig, sizeof(sig)) < 0)
	  printf("write socket fail\n");
}

int main(){
	int sig;
	
	socketpair(AF_UNIX, SOCK_STREAM, 0, pip_fd);
	signal(SIGUSR1, sig_hander);
	
	for(;;){
		if(read(pip_fd[0], &sig, sizeof(sig)) <0){
			printf("read socket fail\n");
			sleep(1);
			continue;
		}
		switch(sig){
			case SIGUSR1:
				printf("=== SIGUSR1 \n");
				break;
		}
	}
	return 0;

}
