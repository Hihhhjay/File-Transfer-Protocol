#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h> 
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>
#include <algorithm> 
#include <functional> 
#include <cctype>
#include <locale>
#include <sys/stat.h>
#include <sstream>
#include <dirent.h>
using namespace std;

void ftp(int serverfd);
int recvline(int serverfd,string& info);
int sendInfo(int socketfd,const void* buffer,size_t length);
void *get_in_addr (struct sockaddr *sa);
int socket_connection (const char *host, const char *port);
string getip(int m_sd);
string int2str(int k);
int IpSepPort(string& ipport,string& ipstr,string& portstr);
void getport(string ownip,string& portstr, string& port);
int client_listen(const char *port);
int accept_conn(int server_fd);
int bindsocket(const char *port);
int sendData_B(int serverfd, FILE* fd,int size);
int recvData_B(int serverfd, FILE* fd);
int server_conn (int sock_fd,const char *host, const char *port);
int recvInfo(int serverfd, string& result);

//处理命令中的空白符（空格等）
static inline string &ltrim(string &s) 
{
    s.erase(s.begin(), find_if(s.begin(), s.end(), not1(ptr_fun<int, int>(isspace))));
    return s;
}

static inline string &rtrim(string &s) 
{
    s.erase(find_if(s.rbegin(), s.rend(), not1(ptr_fun<int, int>(isspace))).base(), s.end());
    return s;
}

static inline string &trim(string &s) 
{
    return ltrim(rtrim(s));
}

string remember = "";//标记缓冲区字符位置
string Client_DPORT=int2str(4024+rand()%60000);//被动模式下的客户端随机数据端口

string res;

int main(int argc, char **argv)
{
	if(argc<3)
    {
		cout<<"按以下格式输入: $./client <host> <port>";
		return 0;
	}
	int serverfd;
	while(1){
	if( (serverfd = socket_connection(argv[1],argv[2]) ) > 0 )
    	{
		//发送身份验证信息
		string user,pass;
		recvline(serverfd,res);//读一行服务器发来的消息
		cout<<"Response: "<<res<<endl;
		cout<<"User Name: "<<endl;
		getline(cin,user);//获取输入
		string userstr = user+"\r\n";
		sendInfo(serverfd,userstr.c_str(),userstr.size());
		recvline(serverfd,res);
		cout<<"Response: "<<res<<endl;
		if(res.compare(0,strlen("332"),"332") == 0)
		{
			cout<<"wrong, input again：";
			continue;
		}
		cout<<"Input Password: "<<endl;
		getline(cin,pass);
		string passstr = pass+"\r\n";
		sendInfo(serverfd,passstr.c_str(),passstr.size());
		recvline(serverfd,res);
		cout<<"Response: "<<res<<endl;
		if(res.compare(0,strlen("530"),"530") == 0)
		{
			cout<<"wrong, input again：";
			continue;
		}
		
		ftp(serverfd);	//进入ftp功能	
	
	}
	else{
		cerr<<"Cannot connect to server"<<endl;
		break;
	  }
	}
	
	return 0;
}
void ftp(int serverfd){

	while(1)
        {
			cout<<"ftp>>";
			string userInput;
			getline(cin,userInput);
			ltrim(userInput);
			if(userInput.compare(0,strlen("put"),"put") == 0)
            {
				int pid = fork();
				if(pid != 0)
                {
					int stat;
					wait(&stat);
					recvline(serverfd,res);
					cout<<"Response: "<<res<<endl;
				}
                else
                {
                    //子进程
					string path = userInput.substr(3); //获取文件名
					path = trim(path);

					//获取文件大小
					struct stat st;
					int statcode = stat(path.c_str(), &st);
					int size = st.st_size;
					if(statcode == -1)
                    {
						cout<<strerror(errno)<<endl;
						continue;
					}
					
					cout<<"Choose mode of Data Transfer:PORT or PASV\n";
					string types;
					int dataportserverfd;//服务器数据端口
					int dataportclientfd;//客户端数据端口
					while(true){
						getline(cin,types);
						if(types.compare(0,strlen("PORT"),"PORT") == 0){
							
							//二进制模式
							string typei = "TYPE I\r\n";
							sendInfo(serverfd,typei.c_str(),typei.size());
							recvline(serverfd,res);
							cout<<"Response: "<<res<<endl;

							// 申请一个随机端口（>1024）发数据
							string portstr,port;
							getport(getip(serverfd),portstr,port);
					
							// 监听
							dataportserverfd = client_listen(port.c_str());
							
							sendInfo(serverfd,portstr.c_str(),portstr.size());
							recvline(serverfd,res);
							cout<<"Response: "<<res<<endl;
							
							// 发送STOR命令
							string storstr = "STOR "+path+"\r\n";
							sendInfo(serverfd,storstr.c_str(),storstr.size());
							recvline(serverfd,res);
							cout<<"Response: "<<res<<endl;
							dataportclientfd = accept_conn(dataportserverfd);
							// 打开文件，发送数据
							FILE* filer;
							filer=fopen(path.c_str(),"rb");
							cout<<"DATA TRANSFER"<<endl;
							int len = sendData_B(dataportclientfd,filer,size);
					
							fclose(filer);
							close(dataportclientfd);
							close(dataportserverfd);
							break;
						}else if(types.compare(0,strlen("PASV"),"PASV") == 0){
							
							//二进制模式
							string typei = "TYPE I\r\n";
							sendInfo(serverfd,typei.c_str(),typei.size());
							recvline(serverfd,res);
							cout<<"Response: "<<res<<endl;
							
							string pasvstr = "PASV\r\n";
							sendInfo(serverfd,pasvstr.c_str(),pasvstr.size());
							recvline(serverfd,res);
							cout<<"Response: "<<res<<endl;
							
							recvline(serverfd,res);
							string ipport=res;
							ipport = trim(ipport);
							string ip,port,portstr;
							IpSepPort(ipport,ip,port); // 将ipport拆成ip和port
					
							dataportserverfd = bindsocket(Client_DPORT.c_str()); // 绑定服务器端数据端口
							dataportclientfd = server_conn(dataportserverfd,ip.c_str(),port.c_str());
					
					
					
							// 发送STOR命令
							string storstr = "STOR "+path+"\r\n";
							sendInfo(serverfd,storstr.c_str(),storstr.size());
							recvline(serverfd,res);
							cout<<"Response: "<<res<<endl;
							if(res.compare(0,strlen("550"),"550") == 0)
                    					{				
							close(dataportserverfd);
							continue;
							}
							// 打开文件，发送数据
							FILE* filer;
							filer=fopen(path.c_str(),"rb");
							cout<<"DATA TRANSFER"<<endl;
							int len = sendData_B(dataportclientfd,filer,size);
							fclose(filer);
							close(dataportclientfd);
							close(dataportserverfd);
							
							break;
							
						}else{
							cout<<"Wrong,Please input again:\n";
						}
					}
					
										
				
				}
			}
            else if(userInput.compare(0,strlen("get"),"get") == 0)
            {
				int pid = fork();
				if(pid != 0)
                {
					int stat;
					wait(&stat);
					recvline(serverfd,res);
					cout<<"Response: "<<res<<endl;	
				}
                else
                {
					
					
					cout<<"Choose mode of Data Transfer:PORT or PASV\n";
					string types;
					int dataportserverfd;//服务器数据端口
					int dataportclientfd;//客户端数据端口
					string path = userInput.substr(3); //获取文件名
					path = trim(path);
					
					while(true){
						getline(cin,types);
						if(types.compare(0,strlen("PORT"),"PORT") == 0){
							string typei = "TYPE I\r\n";
							sendInfo(serverfd,typei.c_str(),typei.size());
							recvline(serverfd,res);
							cout<<"Response: "<<res<<endl;

							// 申请一个随机端口（>1024）收数据
							
							string portstr,port;
							getport(getip(serverfd),portstr,port);
					
							// 监听
							dataportserverfd = client_listen(port.c_str());
							sendInfo(serverfd,portstr.c_str(),portstr.size());
							recvline(serverfd,res);
							cout<<"Response: "<<res<<endl;

							

							string getstr = "RETR "+path+"\r\n";
							sendInfo(serverfd,getstr.c_str(),getstr.size());
							recvline(serverfd,res);


							cout<<"Response: "<<res<<endl;
							if(res.compare(0,strlen("550"),"550") == 0)
                    					{
								close(dataportserverfd);
								continue;
							}
							dataportclientfd = accept_conn(dataportserverfd);
					
							FILE* filew;
							// 接收数据，保存到文件
							filew=fopen(path.c_str(),"wb");
							cout<<"DATA TRANSFER"<<endl;
							int len = recvData_B(dataportclientfd,filew);
							cout<<"Bytes Received : "<<len<<endl;
							fclose(filew);
							close(dataportclientfd);
							close(dataportserverfd);
						
							break;
						}else if(types.compare(0,strlen("PASV"),"PASV") == 0){
							string typei = "TYPE I\r\n";
							sendInfo(serverfd,typei.c_str(),typei.size());
							recvline(serverfd,res);
							cout<<"Response: "<<res<<endl;

							string pasvstr = "PASV\r\n";
							sendInfo(serverfd,pasvstr.c_str(),pasvstr.size());
							recvline(serverfd,res);
							cout<<"Response: "<<res<<endl;
							
							recvline(serverfd,res);
							string ipport=res;
							ipport = trim(ipport);
							string ip,port,portstr;
							IpSepPort(ipport,ip,port); // 将ipport拆成ip和port
					
							dataportserverfd = bindsocket(Client_DPORT.c_str()); // 绑定服务器端数据端口
							dataportclientfd = server_conn(dataportserverfd,ip.c_str(),port.c_str());
							
							FILE* filew;
							// 接收数据，保存到文件
							filew=fopen(path.c_str(),"wb");
							cout<<"DATA TRANSFER"<<endl;
							int len = recvData_B(dataportclientfd,filew);
							cout<<"Bytes Received : "<<len<<endl;
							fclose(filew);
							close(dataportclientfd);
							close(dataportserverfd);
							
							break;
							
						}else{
							cout<<"Wrong,Please input again:\n";
						}
					}
					
				}
			}
			else if(userInput.compare(0,strlen("dir"),"dir") == 0)
			{
				int pid = fork();
				if(pid != 0)
                {
					int stat;
					wait(&stat);
					recvline(serverfd,res);
					cout<<"Response: "<<res<<endl;	
				}
                else
                {
					//子进程接收数据
					string portstr,port;
					getport(getip(serverfd),portstr,port);
					int dataportserverfd = client_listen(port.c_str());
					sendInfo(serverfd,portstr.c_str(),portstr.size());
					recvline(serverfd,res);
					cout<<"Response: "<<res<<endl;
					sendInfo(serverfd,"LIST\r\n",strlen("LIST\r\n"));
					recvline(serverfd,res);
					cout<<"Response: "<<res<<endl;
					int dataportclientfd = accept_conn(dataportserverfd);
					recvInfo(dataportclientfd,res);
					cout<<"------------DATA---------"<<endl;
					cout<<"Response: "<<res<<endl;
					cout<<"-------END---------"<<endl;
				
				}
			}
			else if(userInput.compare(0,strlen("cd"),"cd") == 0)
			{
					string path = userInput.substr(2);
					path = trim(path);
					string cwdstr = "CWD "+path+"\r\n";
					sendInfo(serverfd,cwdstr.c_str(),cwdstr.size());
					recvline(serverfd,res);
					cout<<"Response: "<<res<<endl;
				
			}
			else if(userInput.compare(0,strlen("pwd"),"pwd") == 0)
			{
				string pwdstr = "PWD\r\n";
				sendInfo(serverfd,pwdstr.c_str(),pwdstr.size());
				recvline(serverfd,res);
				cout<<"Response: "<<res<<endl;
				
			}
			else if(userInput.compare(0,strlen("client_dir"),"client_dir") == 0)
			{
				DIR *dp;
				struct dirent *ep;     
				dp = opendir ("./");
				cout<<"------------DATA---------"<<endl;
				if (dp != NULL)
				{
				    while (ep = readdir (dp))
						cout<<ep->d_name<<endl;
				    closedir (dp);
				}
				
				else
			    	perror ("Couldn't open the directory");
			    	cout<<"-------END---------"<<endl;
			}
			else if(userInput.compare(0,strlen("client_cd"),"client_cd") == 0)
			{
				string path = userInput.substr(4);
				path = trim(path);
				int stat = chdir(path.c_str());
				if(stat==0)
					cout<<"Directory Successfully Changed"<<endl;
				else
					cout<<strerror(errno)<<endl;
			}
			else if(userInput.compare(0,strlen("client_pwd"),"client_pwd") == 0)
			{
				char cwd[1024];
			    if(getcwd(cwd, sizeof(cwd)) != NULL)
			       cout<<"Current Dir: "<<cwd<<endl;
			    else
			       perror("getcwd() error");

			}
			else if(userInput.compare(0,strlen("quit"),"quit") == 0)
			{
				close(serverfd);
				exit(0);
			}
			else if(userInput.compare(0,strlen("?"),"?") == 0)
			{
				cout<<"Supported Commands:"<<endl;
				cout<<"1) get\nDownload files from the server"<<endl;
				cout<<"2) put\nUpload files to server"<<endl;
				cout<<"3) pwd\nDisplay the current directory of the server"<<endl;
				cout<<"4) dir\nList subdirectories and files under the current directory of the server"<<endl;
				cout<<"5) cd\nChange the current server directory"<<endl;
				cout<<"6) ?\nDisplay executable commands "<<endl;
				cout<<"7) quit\nExit and return"<<endl;
				cout<<"8) client_pwd\nDisplay the current directory of the client"<<endl;
				cout<<"9) client_cd\nChange the current client directory"<<endl;
				cout<<"10) client_dir\nList subdirectories and files under the current directory of the client"<<endl;
				
			}
			else
			{
				cout<<"UNKNOWN COMMAND"<<endl;	
			}
		}	
		//	
}
//接受服务器的信息
int recvInfo(int serverfd, string& result)
{
	int len=0;
	while(1)
	{
		char buf[10001];
		int bytesRead;
		if((bytesRead = recv(serverfd,buf,10000,0)) >0)
		{
			result += string(buf,buf+bytesRead);
			len+=bytesRead;
		}
		else if(bytesRead<0)
		{
			return -1;
		}
		else
		{
			return len;
		}
	}
}


//以二进制格式从缓冲区接收文件，再存放到客户端
int recvData_B(int serverfd, FILE* fd)
{
	unsigned char buf[10001];
	int bytesRead=0;
	int len=0;
	while((bytesRead = recv(serverfd,buf,10000,0)) > 0)
	{
		len+=bytesRead;
		fwrite(buf,1,bytesRead,fd);
	}
	if(bytesRead < 0)
	{
		cerr<<"Error Occurred";
		return -1;
	}
	else
	{
		return len;
	}
}

//以二进制格式发送指定文件到缓冲区，再发送服务器
int sendData_B(int serverfd, FILE* fd,int size)
{
	unsigned char buf[100001];
	int bytesSent=0;
	while(size > 0)
	{
		int bytesRead = fread(buf,1,100000,fd);
		int stat = sendInfo(serverfd,buf,bytesRead);
		if(stat != 0 )
		{
			cout<<"ERROR IN SENDING"<<endl;
			return -1;
		}
		size = size - bytesRead;
	}
	return 0;	
}

//接受服务器连接
int accept_conn(int server_fd)
{
	struct sockaddr_storage their_addr;
	char s[INET6_ADDRSTRLEN];
	socklen_t sin_size = sizeof their_addr;

	int client_fd = accept(server_fd, (struct sockaddr *)&their_addr, &sin_size);
	if (client_fd == -1)
	{
	  perror("accept");
	  return -1;
	}

	inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
	struct timeval tv;
	tv.tv_sec = 120;
	tv.tv_usec = 0; 

	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));

	return client_fd;
}

//监听数据发送端口
int client_listen(const char *port)
{
	struct addrinfo hints, *res;
	int sock_fd;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int addr_status = getaddrinfo(NULL, port, &hints, &res);
	if (addr_status != 0)
	{
	  fprintf(stderr, "Cannot get info\n");
	  return -1;
	}

	struct addrinfo* p;
	for (p = res; p != NULL; p = p->ai_next)
	{
	  sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
	  if (sock_fd < 0)
	  {
	    perror("server: cannot open socket");
	    continue;
	  }

	  int yes = 1;
	  int opt_status = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	  if (opt_status == -1)
	  {
	    perror("server: setsockopt");
	    exit(1);
	  }

	  int bind_status = bind(sock_fd, p->ai_addr, p->ai_addrlen);
	  if (bind_status != 0)
	  {
	    close(sock_fd);
	    perror("server: Cannot bind socket");
	    continue;
	  }
	  break;
	}

	if (p == NULL)
	{
	  fprintf(stderr, "server: failed to bind\n");
	  return -2;
	}

	freeaddrinfo(res);

	if (listen(sock_fd, 100) == -1) 
    {
	  perror("listen");
	  exit(1);
	}

	return sock_fd;
}

//int转化string
string int2str(int k)
{
	stringstream ss;
	ss<<k;
	return ss.str();
}

//随机产生端口，并封装PORT标准指令
void getport(string ip,string& portstr, string& port)
{
	for (int i = 0; i < ip.size(); ++i)
	{
		if(ip[i] == '.') ip[i] = ',';
	}
	int portnum = 1024 + rand() % 60000;
	string p1 = int2str(portnum/256);
	string p2 = int2str(portnum%256);
	portstr = "PORT "+ip+","+p1+","+p2+"\r\n";
	port = int2str(portnum);
}

//获取当前进程的ip地址
string getip(int m_sd)
{
	struct sockaddr_in localAddress;
	socklen_t addressLength = sizeof(localAddress);
	getsockname(m_sd, (struct sockaddr*)&localAddress, &addressLength);
	return string(inet_ntoa(localAddress.sin_addr));
}


//发送消息
int sendInfo(int socketfd,const void* buffer,size_t length)
{
	size_t i = 0;
	while(i < length)
	{
		int byteSent = send(socketfd,buffer,length - i,MSG_NOSIGNAL);
		if(byteSent == -1)
		{
			return errno;
		}
		else
		{
			i += byteSent;
		}
	}
	return 0;
} 

//支持ipv4和ipv6
void *get_in_addr (struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) 
	{
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

//socket连接
int socket_connection (const char *host, const char *port)
{
 
  struct addrinfo hints, *res;
  int sock_fd;

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  int addr_status = getaddrinfo(host, port, &hints, &res);
  if (addr_status != 0)
  {
    fprintf(stderr, "Cannot get address info\n");
    return -1;
  }

  struct addrinfo* p;
  for (p = res; p != NULL; p = p->ai_next)
  {

    sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sock_fd < 0)
    {
      perror("client: cannot open socket");
      continue;
    }

    //连接
    int connect_status = connect(sock_fd, p->ai_addr, p->ai_addrlen);
    if (connect_status < 0)
    {
      close(sock_fd);
      perror("client: connect");
      continue;
    }
    break;
  }

  //无法绑定
  if (p == NULL)
  {
    fprintf(stderr, "client: failed to connect\n");
    return -2;
  }

  char s[INET6_ADDRSTRLEN];
  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), s, sizeof s);

  freeaddrinfo(res);

  return sock_fd;
}


//从服务器发来的消息中读一行
int recvline(int serverfd,string& info)
{
	char buffer[501];
	info = remember;
	int byteRead = recv(serverfd,buffer,500,0);
	while(byteRead > 0)
	{
		info += string(buffer,buffer+byteRead);
		int pos = info.find("\r\n");
		if(pos!=string::npos)
		{
			//一行结束
			remember = info.substr(pos+2);
			info = info.substr(0,pos+2);
			break;
		}
		byteRead = recv(serverfd,buffer,500,0);
	}
	if(byteRead < 0)
	{
		cerr<<"Error Occurred";
		return -1;
	}
	else
	{
		return 0;
	}
}
int IpSepPort(string& ipport,string& ipstr,string& portstr)
{
	int cnt=0,pos;
	string ip = ipport;
	for (int i = 0; i < ipport.size(); i++)
	{
		if(ip[i]==',')
		{
			ip[i] = '.';
			cnt++;
			if(cnt==4)
			{
				pos = i;
				break;
			}
		}
	}
	
	if(cnt!=4) return -1;
	ipstr = ip.substr(0,pos);
	string port = ip.substr(pos+1);
	int val=0;
	int i=0;

	while(i<port.size())
	{
		if(port[i] == ',') break;
		val = 10*val +  (port[i] - '0');
		i++;
	}
	val = 256*val;
	int portval = val;
	val = 0;
	i++;
	while(i<port.size())
	{
		val = 10*val + (port[i] - '0');
		i++;
	}
	portval = portval + val;

	stringstream ss;
	ss<<portval;
	portstr = ss.str();

	return 0;
}
int bindsocket(const char *port)
{
	//创建地址结构
	struct addrinfo hints, *res;
	int sock_fd;
	//配置地址属性
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	int addr_status = getaddrinfo(NULL, port, &hints, &res);
	if (addr_status != 0)
	{
	  fprintf(stderr, "Cannot get info\n");
	  return -1;
	}

	// 循环直到找到第一个能连接的
	struct addrinfo *p;
	for (p = res; p != NULL; p = p->ai_next)
	{
	  // 创建socket
	  sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
	  if (sock_fd < 0)
	  {
	    perror("server: cannot open socket");
	    continue;
	  }

	  // 设置socket选项
	  int yes = 1;
	  int opt_status = setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
	  if (opt_status == -1)
	  {
	    perror("server: setsockopt");
	    exit(1);
	  }

	  // socket与port绑定
	  int bind_status = bind(sock_fd, p->ai_addr, p->ai_addrlen);
	  if (bind_status != 0)
	  {
	    close(sock_fd);
	    perror("server: Cannot bind socket");
	    continue;
	  }
	  break;
	}

	//无法绑定
	if (p == NULL)
	{
	  fprintf(stderr, "server: failed to bind\n");
	  return -2;
	}

	freeaddrinfo(res);

	return sock_fd;
}
//与服务器建立连接
int server_conn (int sock_fd,const char *host, const char *port)
{
	struct addrinfo hints, *res;

	// 配置地址属性

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	getaddrinfo(host, port, &hints, &res);

	// 连接
	int stat = connect(sock_fd, res->ai_addr, res->ai_addrlen);
	if(stat==-1)
	{
		cout<<"Connect Error "<<strerror(errno)<<endl;
		return -1;
	}
  
  return sock_fd;
}
