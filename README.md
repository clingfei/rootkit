# Rootkit

## hide module

内核中的模块信息定义在linux/module.h中，

```C
struct module {
    enum module_state state;
    
    /* Member of list of modules */
    struct list_head list;
    
}
```

通过THIS_MODULE宏获得当前的module信息

隐藏module的方式：将当前module从链表中删除，需要恢复时再重新插入链表。

## hide directories

```C
struct linux_dirent64 {
    u64         d_ino;
    s64         d_off;
    unsigned short      d_reclen;			//目录项长度，单位为字节
    unsigned char       d_type;
    char        d_name[];					//文件名
};
```

```c
static asmlinkage long (*getdents64)(unsigned long fd, struct linux_dirent64 __user *dirent, unsigned long count);
```

getdents64的返回值为目录项的总长度，dirent是linux_dirent64结构体的集合，其中每个结构体代表一个目录项的抽象，可以通过current_dir + current_dir->d_reclen来获得下一个目录项。对每个目录项判断其d_name是否与要隐藏的相同，若相同则跳过，并在总长度中减去对应的d_reclen。

getdent与getdents64类似。

## hide process

与文件隐藏类似，区别在于进程号是动态分配的，因此不能采用硬编码的形式隐藏。我们hook kill系统调用，利用Kill的pid参数传递给模块作为要隐藏的进程的进程号。然后hook getdents64和getdents两个系统调用，将每个目录项的d_name与pid相比较，若相同则隐藏。

## hide ports

```C
struct sock {
	struct sock_common __sk_common
#define sk_node			__sk_common.skc_node
//...
}
```

```C
struct sock_common {
	/* redacted for clarity */
	
	/* skc_dport && skc_num must be grouped as well */
	union {
		__portpair skc_portpair;
		struct {
			__be16			skc_dport;
			__u16			skc_num;
		};
	};
	/* redacted for clarity */
};
```

在sock的定义中，有

```C
#define sk_num			__sk_common.skc_num
```

而__sk_common.skc_num与skc_dport组成的结构体定义在union中，因此可以通过指向sock的指针的sk_num字段来获得正在监听的本地端口。

检测方式：

```
sudo netstat -tunelp   #查看不同的端口 协议 进程

nc -lvnp port   #判断port是否被占用
```



## Reference

1. Linux syscall.h: [linux/syscalls.h at b07175dc41babfec057f494d22a750af755297d8 · torvalds/linux (github.com)](https://github.com/torvalds/linux/blob/b07175dc41babfec057f494d22a750af755297d8/include/linux/syscalls.h#L468)
2. Linux syscall Reference: [Linux Syscall Reference (paolostivanin.com)](https://syscalls64.paolostivanin.com/)
3. pt_regs: [linux/ptrace.h at 15bc20c6af4ceee97a1f90b43c0e386643c071b4 · torvalds/linux (github.com)](https://github.com/torvalds/linux/blob/15bc20c6af4ceee97a1f90b43c0e386643c071b4/arch/x86/include/asm/ptrace.h#L12)

