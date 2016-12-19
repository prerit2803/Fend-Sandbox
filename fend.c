  #include <sys/ptrace.h>
  #include <sys/user.h>
  #include <fnmatch.h>
  #include <stdlib.h>
  #include <stdio.h>
  #include <err.h>
  #include <string.h>
  #include <sys/reg.h>
  #include <sys/syscall.h>
  #include <signal.h>
  #include <ctype.h>
  #include <errno.h>
  #include <fcntl.h>
  #include <limits.h>
  #include <libgen.h>
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/wait.h>

  const int long_size = sizeof(long);

  //sandbox declaration
  struct sandbox{
  	pid_t child;
  	const char *name;
  };

  void patternMatch(char*, char*, int*);

  //sandbox initialiazation (from toosh: https://github.com/t00sh/p-sandbox/blob/master/p-sandbox.c)
  void sandbox_init(struct sandbox *sb, char **argv, char *config)
  {
  	pid_t pid;
    int split[3];

    pid = fork();//initializing child

    if(pid == -1) //failure to create child
      err(EXIT_FAILURE, "[SANDBOX] Error on fork:");

    if(pid == 0) { //child process
      if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        err(EXIT_FAILURE, "[SANDBOX] Failed to PTRACE_TRACEME:");
          //check for execute permission
        /*patternMatch(config, argv[0], split);
        if (split[2]!=1)
        {
          printf("Terminating fend: unauthorized access of %s\n", argv[0]);
          exit(EXIT_FAILURE);
        }*/
        if(execv(argv[0], argv) < 0)
          err(EXIT_FAILURE, "[SANDBOX] Failed to execv:");
        } else {//parent process
            sb->child = pid;
            sb->name = argv[0];
  	     }
}

//fetch values stored at addresses pointed by registers (linuxjournal: http://www.linuxjournal.com/article/6100)
void fetchAddr(pid_t child, long reg, char *file) {
  char *laddr;
  int i, j, len=1000;
  long temp;
  i = 0;
  laddr = file;
  while(i < (len / long_size)) {
    temp = ptrace(PTRACE_PEEKDATA, child, reg + i * 8, NULL);
    memcpy(laddr, &temp, long_size);
    ++i;
    laddr += long_size;
  }
  file[len] = '\0';
}

//fetch values from registers (linuxjournal: http://www.linuxjournal.com/article/6100)
void fetchVal(pid_t child, char **rdiVal, char **rsiVal, long *rsi_reg)
{
  long rdi_reg;
  rdi_reg = ptrace(PTRACE_PEEKUSER, child, 8 * RDI, NULL); //fetch address stored in RDI register
  *rsi_reg = ptrace(PTRACE_PEEKUSER, child, 8 * RSI, NULL); //fetch address stored in RSI register
  *rdiVal = (char *)calloc((1000), sizeof(char));
  *rsiVal = (char *)calloc((1000), sizeof(char));
  fetchAddr(child, rdi_reg, *rdiVal); //fetch values pointed by address stored in RDI register
  fetchAddr(child, *rsi_reg, *rsiVal); //fetch values pointed by address stored in RSI register
}

//Matching filename against config file
void patternMatch(char *config, char *str, int *split)
{
  FILE *fptr;
  int i, access, curr;
  char buff[255], loc[255];
  fptr=fopen(config,"r"); //open configuration file
  if(fptr==NULL){
    exit(EXIT_FAILURE); 
    exit(1);             
  }
  while(1)
  {
    fscanf(fptr, "%s", buff); //fetch permissions
    if (feof(fptr)){
      break;
    }
    access=atoi(buff); //convert to integer
    curr=access;
    fscanf(fptr, "%s", buff); //fetch glob pattern
    if(fnmatch(buff,str,FNM_NOESCAPE)==0){
      strcpy(loc,buff);
      curr=access;
    }
  }
  fclose(fptr); //close pointer
  for (i = 2; i >= 0; i--) { //splitting into array
    split[i]=curr%10;
    curr/=10;
  }
}

//Sandbox processing
void sandbox_run(struct sandbox *sb, char *config)
{
  long syscall_no, rsi_reg;
  char *rdiVal, *rsiVal, *ts1, *dir, buf[PATH_MAX + 1], *res, cwd[1024];
  int i, split[3], dirPerm[3], status, flag=0, RWflag=0, WRflag=0, RDflag=0, CRflag=0, APflag=0, TRflag=0, count=0, toggle[12]={0};
  while(1) {
           wait(&status);
           if(WIFEXITED(status))
               exit(EXIT_SUCCESS);
           syscall_no = ptrace(PTRACE_PEEKUSER, sb->child, 8 * ORIG_RAX, NULL); 
           rdiVal=NULL;
           res=NULL;
           rsiVal=NULL;
           ts1=NULL;
           dir=NULL;
           res=NULL;
           rsi_reg=0;
           for (i = 0; i < 3; ++i)
           {
           	split[i]=0;
           	dirPerm[i]=0;
           }
           if (syscall_no == SYS_open && toggle[0]==0)
           {
           	toggle[0]=1;
           	fetchVal(sb->child, &rdiVal, &rsiVal, &rsi_reg);
           	patternMatch(config, rdiVal, split);
           	flag=0;
  			     RWflag=0;
              WRflag=0;
              RDflag=0;
              CRflag=0;
              APflag=0;
              TRflag=0;
              count=0;
                  if ((rsi_reg & O_CREAT) == O_CREAT)
                  {
  					CRflag=1;
  					count++;
  					if(realpath(rdiVal, buf))
  					{
  						getcwd(cwd, sizeof(cwd));
  						patternMatch(config, cwd, dirPerm);
  					}
                  }
                  if ((rsi_reg & O_TRUNC) == O_TRUNC)
                  {
                    TRflag=1;
                    count++;
                  }
                  if ((rsi_reg & O_APPEND) == O_APPEND)
                  {
                    APflag=1;
                    count++;
                  }
                  if ((rsi_reg & O_WRONLY) == O_WRONLY)
                 {
                   WRflag=1;
                   count++;
                 }
                 else
                  {
                    if ((rsi_reg & O_RDWR) == O_RDWR)
                    {
                      RWflag=1;
                      count++;
                    }
                    else
                    {
                      RDflag=1;
                      count++;
                    }
                  }
                  if(CRflag==1 && dirPerm[1]==1 && dirPerm[2]==1)
                  {
                  	count--;
                  }
  				        if(TRflag==1 && split[0]==1 && split[1]==1)
                  {
                    count--;
                  }
                  if(APflag==1 && split[0]==1 && split[1]==1)
                  {
                    count--;
                  }                

                  if(RWflag==1 && split[0]==1 && split[1]==1 && flag==0)
                  {
                    flag= 1;
                    count--;
                  }
                  if (WRflag==1 && split[1]==1 && flag==0)
                  {
                    flag=1;
                    count--;
                  }
                  if (RDflag==1 && split[0]==1 && flag==0)
                  {
                    flag=1;
                    count--;
                  }
                  if(count!=0)
                    {
                      printf("Terminating fend: unauthorized access of %s\n", rdiVal);
                      exit(EXIT_FAILURE);
                  }
           }
           else
           	toggle[0]=0;

           if (syscall_no==SYS_openat && toggle[1]==0)
           {
           	toggle[1]=1;
            fetchVal(sb->child, &rdiVal, &rsiVal, &rsi_reg);
            res=realpath(rsiVal,buf);
            ts1 = strdup(res);
            dir = dirname(ts1);
            patternMatch(config, dir, split);
            flag=0;
             RWflag=0;
              WRflag=0;
              RDflag=0;
              CRflag=0;
              APflag=0;
              TRflag=0;
              count=0;
                  if ((rsi_reg & O_CREAT) == O_CREAT)
                  {
            CRflag=1;
            count++;
            if(!realpath(rdiVal, buf))
            {
              getcwd(cwd, sizeof(cwd));
              patternMatch(config, cwd, dirPerm);
            }
                  }
                  if ((rsi_reg & O_TRUNC) == O_TRUNC)
                  {
                    TRflag=1;
                    count++;
                  }
                  if ((rsi_reg & O_APPEND) == O_APPEND)
                  {
                    APflag=1;
                    count++;
                  }
                  if ((rsi_reg & O_WRONLY) == O_WRONLY)
                 {
                   WRflag=1;
                   count++;
                 }
                 else
                  {
                    if ((rsi_reg & O_RDWR) == O_RDWR)
                    {
                      RWflag=1;
                      count++;
                    }
                    else
                    {
                      RDflag=1;
                      count++;
                    }
                  }
                  if(CRflag==1 && dirPerm[1]==1 && dirPerm[2]==1)
                  {
                    count--;
                  }
                  if(TRflag==1 && split[0]==1 && split[1]==1)
                  {
                    count--;
                  }
                  if(APflag==1 && split[0]==1 && split[1]==1)
                  {
                    count--;
                  }                

              if(RWflag==1 && split[0]==1 && split[1]==1 && flag==0)
                  {
                    flag= 1; 
                    count--;
                  }
                  if (WRflag==1 && split[1]==1 && flag==0)
                  {
                    flag=1;
                    count--;
                  }
                  if (RDflag==1 && split[0]==1 && flag==0)
                  {
                    flag=1;
                    count--;
                  }
                  if(count!=0)
                    {
                      printf("Terminating fend: unauthorized access of %s\n", rsiVal);
                      exit(EXIT_FAILURE);
                  }
           }
           else{
           	toggle[1]=0;
           }
           if (syscall_no==SYS_access && toggle[2]==0)
           {
           	toggle[2]=1;
           }
           else{
           	toggle[2]=0;
           }
           if (syscall_no==SYS_link && toggle[3]==0)
           {
           	toggle[3]=1;
            fetchVal(sb->child, &rdiVal, &rsiVal, &rsi_reg);
            res=realpath(rdiVal,buf);
            ts1 = strdup(res);
            dir = dirname(ts1);
            patternMatch(config, dir, split);
            if (split[1]!=1)
            {
              printf("Terminating fend: unauthorized access of %s\n", rdiVal);
              exit(EXIT_FAILURE);
            }
            res=NULL;
            ts1=NULL;
            dir=NULL;
            res=realpath(rsiVal,buf);
            ts1 = strdup(res);
            dir = dirname(ts1);
            patternMatch(config, dir, split);
            if (split[1]!=1)
            {
              printf("Terminating fend: unauthorized access of %s\n", rsiVal);
              exit(EXIT_FAILURE);
            }
           }
           else{
           	toggle[3]=0;
           }
           if (syscall_no==SYS_linkat && toggle[4]==0)
           {
           	toggle[4]=1;
            fetchVal(sb->child, &rdiVal, &rsiVal, &rsi_reg);
            res=realpath(rdiVal,buf);
            ts1 = strdup(res);
            dir = dirname(ts1);
            patternMatch(config, dir, split);
            if (split[1]!=1)
            {
              printf("Terminating fend: unauthorized access of %s\n", rdiVal);
              exit(EXIT_FAILURE);
            }
            res=NULL;
            ts1=NULL;
            dir=NULL;
            res=realpath(rsiVal,buf);
            ts1 = strdup(res);
            dir = dirname(ts1);
            patternMatch(config, dir, split);
            if (split[1]!=1)
            {
              printf("Terminating fend: unauthorized access of %s\n", rsiVal);
              exit(EXIT_FAILURE);
            }
           }
           else{
           	toggle[4]=0;
           }
           if (syscall_no==SYS_unlink && toggle[5]==0)
           {
           	toggle[5]=1;
            fetchVal(sb->child, &rdiVal, &rsiVal, &rsi_reg);
            res=realpath(rdiVal,buf);
            ts1 = strdup(res);
            dir = dirname(ts1);
            patternMatch(config, dir, split);
            if (split[1]!=1)
            {
              printf("Terminating fend: unauthorized access of %s\n", rdiVal);
              exit(EXIT_FAILURE);
            }
           }
           else{
           	toggle[5]=0;
           }
           if (syscall_no==SYS_rmdir && toggle[6]==0)
           {
           	toggle[6]=1;
            fetchVal(sb->child, &rdiVal, &rsiVal, &rsi_reg);
            if(realpath(rdiVal, buf))
            {
              getcwd(cwd, sizeof(cwd));
            }
            else{
              ts1 = strdup(rdiVal);
              dir = dirname(ts1);
              strcpy(cwd,dir);
            }
            patternMatch(config, cwd, split);
            if (split[1]!=1)
            {
              printf("Terminating fend: unauthorized access of %s\n", rsiVal);
              exit(EXIT_FAILURE);
            }
           }
           else{
           	toggle[6]=0;
           }
           if (syscall_no==SYS_mkdir && toggle[7]==0)
           {
           	toggle[7]=1;
           	fetchVal(sb->child, &rdiVal, &rsiVal, &rsi_reg);
           	if(realpath(rdiVal, buf))
            {
              getcwd(cwd, sizeof(cwd));
            }
           	else{
           		ts1 = strdup(rdiVal);
  				    dir = dirname(ts1);
           		strcpy(cwd,dir);
           	}
           	patternMatch(config, cwd, split);
           	if (split[1]==1 && split[2]==1)
            {
              continue;
            }
            else
            {
              printf("Terminating fend: unauthorized access of %s\n", rsiVal);
              exit(EXIT_FAILURE);
            }
           }
           else{
           	toggle[7]=0;
           }
           if (syscall_no==SYS_chmod && toggle[8]==0)
           {
           	toggle[8]=1;
           }
           else{
           	toggle[8]=0;
           }
           if (syscall_no==SYS_rename && toggle[9]==0)
           {
           	toggle[9]=1;
           	fetchVal(sb->child, &rdiVal, &rsiVal, &rsi_reg);
            res=realpath(rdiVal,buf);
            ts1 = strdup(res);
            dir = dirname(ts1);
           	patternMatch(config, dir, split);
           	if (split[1]==1 && split[2]==1)
            {
              res=NULL;
              ts1=NULL;
              dir=NULL;
              res=realpath(rsiVal,buf);
              ts1 = strdup(res);
              dir = dirname(ts1);
              patternMatch(config, dir, split);
              if (split[1]==1 && split[2]==1)
              {
                continue;
              }
              else
              {
                printf("Terminating fend: unauthorized access of %s\n", rsiVal);
                exit(EXIT_FAILURE);
              }
            }
            else
            {
              printf("Terminating fend: unauthorized access of %s\n", rsiVal);
              exit(EXIT_FAILURE);
            }
           }
           else{
           	toggle[9]=0;
           }
           if (syscall_no==SYS_renameat && toggle[10]==0)
           {
           	toggle[10]=1;
            fetchVal(sb->child, &rdiVal, &rsiVal, &rsi_reg);
            res=realpath(rdiVal,buf);
            ts1 = strdup(res);
            dir = dirname(ts1);
            patternMatch(config, dir, split);
            if (split[1]==1 && split[2]==1)
            {
              res=NULL;
              ts1=NULL;
              dir=NULL;
              res=realpath(rsiVal,buf);
              ts1 = strdup(res);
              dir = dirname(ts1);
              patternMatch(config, dir, split);
              if (split[1]==1 && split[2]==1)
              {
                continue;
              }
              else
              {
                printf("Terminating fend: unauthorized access of %s\n", rsiVal);
                exit(EXIT_FAILURE);
              }
           }
         }
           else{
           	toggle[10]=0;
           }
           if (syscall_no==SYS_mkdirat && toggle[11]==0)
           {
           	toggle[11]=1;
            fetchVal(sb->child, &rdiVal, &rsiVal, &rsi_reg);
            if(realpath(rdiVal, buf))
            {
              getcwd(cwd, sizeof(cwd));
            }
            else{
              ts1 = strdup(rdiVal);
              dir = dirname(ts1);
              strcpy(cwd,dir);
            }
            patternMatch(config, cwd, split);
            if (split[1]==1 && split[2]==1)
            {
              continue;
            }
            else
            {
              printf("Terminating fend: unauthorized access of %s\n", rsiVal);
              exit(EXIT_FAILURE);
            }
           }
           else{
           	toggle[11]=0;
           }
           ptrace(PTRACE_SYSCALL, sb->child, NULL, NULL);
       }
  }

  int main(int args, char **argv){
  	char *config, *file;
  	struct sandbox sb;
  	if(args<2)
  	{
  		errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]); //No command is given
  	}
  	if(strcmp(argv[1],"-c")!=0) // no configuration file is given
  	{
  		FILE* fp;
  		fp = fopen("./.fendrc", "r"); // for current directory
  		if (fp != NULL)
  		{
  			config="./.fendrc";
  			sandbox_init(&sb, argv+1, config);
      	}
  		else
  		{
        file=getenv("HOME");
        strcat(file,"/.fendrc");
  			fp = fopen(file, "r"); // for home directory
  			if (fp != NULL)
  			{
  				strcpy(config,file);
  				sandbox_init(&sb, argv+1, config);
  			}
  			else
  			{
  				errx(EXIT_FAILURE,"Must provide a config file.");
  			}
  		}
  	}
  	else // config file is given
  	{
  		if(args<4) // no command is given
  		{
  			errx(EXIT_FAILURE, "[SANDBOX] Usage : %s <elf> [<arg1...>]", argv[0]);
  		}
  		else
  		{
  			config=argv[2];
  			sandbox_init(&sb, argv+3, config);
  		}

  	}
  	for(;;) {
      sandbox_run(&sb,config);
    	}

  	return EXIT_SUCCESS;
  }