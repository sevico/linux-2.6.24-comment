struct sigframe
{
	//保存返回地址
	char __user *pretcode;
	//信号
	int sig;
	//保存一组寄存器上下文
	struct sigcontext sc;
	//保存浮点寄存器上下文
	struct _fpstate fpstate;
	unsigned long extramask[_NSIG_WORDS-1];
	//保存进入 sigreturn系统调用的代码
	char retcode[8];
};

struct rt_sigframe
{
	char __user *pretcode;
	int sig;
	struct siginfo __user *pinfo;
	void __user *puc;
	struct siginfo info;
	struct ucontext uc;
	struct _fpstate fpstate;
	char retcode[8];
};
