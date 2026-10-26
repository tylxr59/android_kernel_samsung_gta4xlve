// SPDX-License-Identifier: GPL-2.0-only
/* Owned temporary fixtures only; no sysctl changes or external paths. */
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static const char *base="/data/local/tmp/los24-fs-protection-test";
static int make_file(const char *name,int mode) {
 int fd=open(name,O_CREAT|O_EXCL|O_WRONLY,mode);if(fd<0)return -1;return close(fd);
}
static int child_test(int which) {
 if(setgroups(0,NULL)||setgid(65534)||setuid(65534))return 3;
 int fd,rc,denied;
 /* Direct reads/ordinary writes prove directory/file DAC permits the control. */
 fd=open("regular",O_RDONLY);if(fd<0)return 4;close(fd);
 fd=open("regular",O_WRONLY);if(fd<0)return 4;close(fd);
 errno=0;
 switch(which){
 case 0:fd=open("link",O_RDONLY);rc=fd;if(fd>=0)close(fd);break;
 case 1:rc=link("readonly","newhardlink");if(!rc)unlink("newhardlink");break;
 case 2:fd=open("fifo",O_CREAT|O_RDONLY|O_NONBLOCK,0600);rc=fd;if(fd>=0)close(fd);break;
 case 3:fd=open("regular",O_CREAT|O_RDONLY,0600);rc=fd;if(fd>=0)close(fd);break;
 case 4:fd=open("group/fifo",O_CREAT|O_RDONLY|O_NONBLOCK,0600);rc=fd;if(fd>=0)close(fd);break;
 case 5:fd=open("group/regular",O_CREAT|O_RDONLY,0600);rc=fd;if(fd>=0)close(fd);break;
 default:return 5;
 }
 denied=rc<0&&(errno==EACCES||errno==EPERM);return denied?0:1;
}
int main(void){
 if(getuid()!=0){fputs("Requires authorized rooted diagnostics\n",stderr);return 2;}
 umask(0);if(mkdir(base,01777)){perror("fixture mkdir (will not reuse existing path)");return 2;}
 if(chdir(base)){rmdir(base);return 2;}
 int rc=2;
 if(make_file("regular",0666)||make_file("readonly",0644)||mkfifo("fifo",0666)||symlink("readonly","link")||mkdir("group",01770))goto done;
 if(chown("regular",2000,2000)||chown("readonly",2000,2000)||chown("fifo",2000,2000)||lchown("link",2000,2000)||chown("group",0,65534))goto done;
 if(make_file("group/regular",0666)||mkfifo("group/fifo",0666)||chown("group/regular",2000,2000)||chown("group/fifo",2000,2000))goto done;
 rc=0;
 for(int which=0;which<6;which++){
  pid_t p=fork();if(p<0){rc=2;break;}if(!p)_Exit(child_test(which));int status;
  if(waitpid(p,&status,0)!=p||!WIFEXITED(status)||WEXITSTATUS(status)){fprintf(stderr,"FAIL: protection case %d status=%d\n",which,status);rc=1;break;}
 }
 if(!rc)puts("PASS: link, FIFO and regular-file protections; world/group-sticky cases and DAC controls");
 done:
 unlink("link");unlink("fifo");unlink("regular");unlink("readonly");unlink("newhardlink");unlink("group/fifo");unlink("group/regular");rmdir("group");chdir("/");rmdir(base);return rc;
}
