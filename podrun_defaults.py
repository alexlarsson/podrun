storage_path = "/var/lib/containers/storage"

seccomp_policy = {
    "architectures" : [
        "SCMP_ARCH_X86_64",
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
    ],
    "defaultAction" : "SCMP_ACT_ERRNO",
    "defaultErrnoRet" : 38,
    "syscalls" : [
        {
            "action" : "SCMP_ACT_ERRNO",
            "errnoRet" : 1,
            "names" : [
                "bdflush",
                "io_pgetevents",
                "kexec_file_load",
                "kexec_load",
                "migrate_pages",
                "move_pages",
                "nfsservctl",
                "nice",
                "oldfstat",
                "oldlstat",
                "oldolduname",
                "oldstat",
                "olduname",
                "pciconfig_iobase",
                "pciconfig_read",
                "pciconfig_write",
                "sgetmask",
                "ssetmask",
                "swapcontext",
                "swapoff",
                "swapon",
                "sysfs",
                "uselib",
                "userfaultfd",
                "ustat",
                "vm86",
                "vm86old",
                "vmsplice"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "names" : [
                "_llseek",
                "_newselect",
                "accept",
                "accept4",
                "access",
                "adjtimex",
                "alarm",
                "bind",
                "brk",
                "capget",
                "capset",
                "chdir",
                "chmod",
                "chown",
                "chown32",
                "clock_adjtime",
                "clock_adjtime64",
                "clock_getres",
                "clock_getres_time64",
                "clock_gettime",
                "clock_gettime64",
                "clock_nanosleep",
                "clock_nanosleep_time64",
                "clone",
                "clone3",
                "close",
                "close_range",
                "connect",
                "copy_file_range",
                "creat",
                "dup",
                "dup2",
                "dup3",
                "epoll_create",
                "epoll_create1",
                "epoll_ctl",
                "epoll_ctl_old",
                "epoll_pwait",
                "epoll_pwait2",
                "epoll_wait",
                "epoll_wait_old",
                "eventfd",
                "eventfd2",
                "execve",
                "execveat",
                "exit",
                "exit_group",
                "faccessat",
                "faccessat2",
                "fadvise64",
                "fadvise64_64",
                "fallocate",
                "fanotify_mark",
                "fchdir",
                "fchmod",
                "fchmodat",
                "fchown",
                "fchown32",
                "fchownat",
                "fcntl",
                "fcntl64",
                "fdatasync",
                "fgetxattr",
                "flistxattr",
                "flock",
                "fork",
                "fremovexattr",
                "fsconfig",
                "fsetxattr",
                "fsmount",
                "fsopen",
                "fspick",
                "fstat",
                "fstat64",
                "fstatat64",
                "fstatfs",
                "fstatfs64",
                "fsync",
                "ftruncate",
                "ftruncate64",
                "futex",
                "futex_time64",
                "futimesat",
                "get_robust_list",
                "get_thread_area",
                "getcpu",
                "getcwd",
                "getdents",
                "getdents64",
                "getegid",
                "getegid32",
                "geteuid",
                "geteuid32",
                "getgid",
                "getgid32",
                "getgroups",
                "getgroups32",
                "getitimer",
                "get_mempolicy",
                "getpeername",
                "getpgid",
                "getpgrp",
                "getpid",
                "getppid",
                "getpriority",
                "getrandom",
                "getresgid",
                "getresgid32",
                "getresuid",
                "getresuid32",
                "getrlimit",
                "getrusage",
                "getsid",
                "getsockname",
                "getsockopt",
                "gettid",
                "gettimeofday",
                "getuid",
                "getuid32",
                "getxattr",
                "inotify_add_watch",
                "inotify_init",
                "inotify_init1",
                "inotify_rm_watch",
                "io_cancel",
                "io_destroy",
                "io_getevents",
                "io_setup",
                "io_submit",
                "ioctl",
                "ioprio_get",
                "ioprio_set",
                "ipc",
                "keyctl",
                "kill",
                "lchown",
                "lchown32",
                "lgetxattr",
                "link",
                "linkat",
                "listen",
                "listxattr",
                "llistxattr",
                "lremovexattr",
                "lseek",
                "lsetxattr",
                "lstat",
                "lstat64",
                "madvise",
                "mbind",
                "memfd_create",
                "memfd_secret",
                "mincore",
                "mkdir",
                "mkdirat",
                "mknod",
                "mknodat",
                "mlock",
                "mlock2",
                "mlockall",
                "mmap",
                "mmap2",
                "mount",
                "move_mount",
                "mprotect",
                "mq_getsetattr",
                "mq_notify",
                "mq_open",
                "mq_timedreceive",
                "mq_timedreceive_time64",
                "mq_timedsend",
                "mq_timedsend_time64",
                "mq_unlink",
                "mremap",
                "msgctl",
                "msgget",
                "msgrcv",
                "msgsnd",
                "msync",
                "munlock",
                "munlockall",
                "munmap",
                "name_to_handle_at",
                "nanosleep",
                "newfstatat",
                "open",
                "openat",
                "openat2",
                "open_tree",
                "pause",
                "pidfd_getfd",
                "pidfd_open",
                "pidfd_send_signal",
                "pipe",
                "pipe2",
                "pivot_root",
                "pkey_alloc",
                "pkey_free",
                "pkey_mprotect",
                "poll",
                "ppoll",
                "ppoll_time64",
                "prctl",
                "pread64",
                "preadv",
                "preadv2",
                "prlimit64",
                "pselect6",
                "pselect6_time64",
                "pwrite64",
                "pwritev",
                "pwritev2",
                "read",
                "readahead",
                "readdir",
                "readlink",
                "readlinkat",
                "readv",
                "reboot",
                "recv",
                "recvfrom",
                "recvmmsg",
                "recvmmsg_time64",
                "recvmsg",
                "remap_file_pages",
                "removexattr",
                "rename",
                "renameat",
                "renameat2",
                "restart_syscall",
                "rmdir",
                "rseq",
                "rt_sigaction",
                "rt_sigpending",
                "rt_sigprocmask",
                "rt_sigqueueinfo",
                "rt_sigreturn",
                "rt_sigsuspend",
                "rt_sigtimedwait",
                "rt_sigtimedwait_time64",
                "rt_tgsigqueueinfo",
                "sched_get_priority_max",
                "sched_get_priority_min",
                "sched_getaffinity",
                "sched_getattr",
                "sched_getparam",
                "sched_getscheduler",
                "sched_rr_get_interval",
                "sched_rr_get_interval_time64",
                "sched_setaffinity",
                "sched_setattr",
                "sched_setparam",
                "sched_setscheduler",
                "sched_yield",
                "seccomp",
                "select",
                "semctl",
                "semget",
                "semop",
                "semtimedop",
                "semtimedop_time64",
                "send",
                "sendfile",
                "sendfile64",
                "sendmmsg",
                "sendmsg",
                "sendto",
                "setns",
                "set_mempolicy",
                "set_robust_list",
                "set_thread_area",
                "set_tid_address",
                "setfsgid",
                "setfsgid32",
                "setfsuid",
                "setfsuid32",
                "setgid",
                "setgid32",
                "setgroups",
                "setgroups32",
                "setitimer",
                "setpgid",
                "setpriority",
                "setregid",
                "setregid32",
                "setresgid",
                "setresgid32",
                "setresuid",
                "setresuid32",
                "setreuid",
                "setreuid32",
                "setrlimit",
                "setsid",
                "setsockopt",
                "setuid",
                "setuid32",
                "setxattr",
                "shmat",
                "shmctl",
                "shmdt",
                "shmget",
                "shutdown",
                "sigaltstack",
                "signalfd",
                "signalfd4",
                "sigreturn",
                "socket",
                "socketcall",
                "socketpair",
                "splice",
                "stat",
                "stat64",
                "statfs",
                "statfs64",
                "statx",
                "symlink",
                "symlinkat",
                "sync",
                "sync_file_range",
                "syncfs",
                "sysinfo",
                "syslog",
                "tee",
                "tgkill",
                "time",
                "timer_create",
                "timer_delete",
                "timer_getoverrun",
                "timer_gettime",
                "timer_gettime64",
                "timer_settime",
                "timer_settime64",
                "timerfd_create",
                "timerfd_gettime",
                "timerfd_gettime64",
                "timerfd_settime",
                "timerfd_settime64",
                "times",
                "tkill",
                "truncate",
                "truncate64",
                "ugetrlimit",
                "umask",
                "umount",
                "umount2",
                "uname",
                "unlink",
                "unlinkat",
                "unshare",
                "utime",
                "utimensat",
                "utimensat_time64",
                "utimes",
                "vfork",
                "wait4",
                "waitid",
                "waitpid",
                "write",
                "writev"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "args" : [
                {
                    "index" : 0,
                    "op" : "SCMP_CMP_EQ",
                    "value" : 0
                }
            ],
            "names" : [
                "personality"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "args" : [
                {
                    "index" : 0,
                    "op" : "SCMP_CMP_EQ",
                    "value" : 8
                }
            ],
            "names" : [
                "personality"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "args" : [
                {
                    "index" : 0,
                    "op" : "SCMP_CMP_EQ",
                    "value" : 131072
                }
            ],
            "names" : [
                "personality"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "args" : [
                {
                    "index" : 0,
                    "op" : "SCMP_CMP_EQ",
                    "value" : 131080
                }
            ],
            "names" : [
                "personality"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "args" : [
                {
                    "index" : 0,
                    "op" : "SCMP_CMP_EQ",
                    "value" : 4294967295
                }
            ],
            "names" : [
                "personality"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "names" : [
                "arch_prctl"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "names" : [
                "modify_ldt"
            ]
        },
        {
            "action" : "SCMP_ACT_ERRNO",
            "errnoRet" : 1,
            "names" : [
                "open_by_handle_at"
            ]
        },
        {
            "action" : "SCMP_ACT_ERRNO",
            "errnoRet" : 1,
            "names" : [
                "bpf",
                "fanotify_init",
                "lookup_dcookie",
                "perf_event_open",
                "quotactl",
                "setdomainname",
                "sethostname",
                "setns"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "names" : [
                "chroot"
            ]
        },
        {
            "action" : "SCMP_ACT_ERRNO",
            "errnoRet" : 1,
            "names" : [
                "delete_module",
                "init_module",
                "finit_module",
                "query_module"
            ]
        },
        {
            "action" : "SCMP_ACT_ERRNO",
            "errnoRet" : 1,
            "names" : [
                "acct"
            ]
        },
        {
            "action" : "SCMP_ACT_ERRNO",
            "errnoRet" : 1,
            "names" : [
                "kcmp",
                "process_madvise",
                "process_vm_readv",
                "process_vm_writev",
                "ptrace"
            ]
        },
        {
            "action" : "SCMP_ACT_ERRNO",
            "errnoRet" : 1,
            "names" : [
                "iopl",
                "ioperm"
            ]
        },
        {
            "action" : "SCMP_ACT_ERRNO",
            "errnoRet" : 1,
            "names" : [
                "settimeofday",
                "stime",
                "clock_settime",
                "clock_settime64"
            ]
        },
        {
            "action" : "SCMP_ACT_ERRNO",
            "errnoRet" : 1,
            "names" : [
                "vhangup"
            ]
        },
        {
            "action" : "SCMP_ACT_ERRNO",
            "args" : [
                {
                    "index" : 0,
                    "op" : "SCMP_CMP_EQ",
                    "value" : 16
                },
                {
                    "index" : 2,
                    "op" : "SCMP_CMP_EQ",
                    "value" : 9
                }
            ],
            "errnoRet" : 22,
            "names" : [
                "socket"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "args" : [
                {
                    "index" : 2,
                    "op" : "SCMP_CMP_NE",
                    "value" : 9
                }
            ],
            "names" : [
                "socket"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "args" : [
                {
                    "index" : 0,
                    "op" : "SCMP_CMP_NE",
                    "value" : 16
                }
            ],
            "names" : [
                "socket"
            ]
        },
        {
            "action" : "SCMP_ACT_ALLOW",
            "args" : [
                {
                    "index" : 2,
                    "op" : "SCMP_CMP_NE",
                    "value" : 9
                }
            ],
            "names" : [
                "socket"
            ]
        }
    ]
}

masked_paths = [
    "/proc/acpi",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/fs/selinux",
    "/sys/dev/block"
]

readonly_paths = [
    "/proc/asound",
    "/proc/bus",
    "/proc/fs",
    "/proc/irq",
    "/proc/sys",
    "/proc/sysrq-trigger"
]

caps = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_NET_BIND_SERVICE",
    "CAP_SETFCAP",
    "CAP_SETGID",
    "CAP_SETPCAP",
    "CAP_SETUID",
    "CAP_SYS_CHROOT"
]

system_mounts = [
    {
        "destination" : "/proc",
        "options" : [
            "nosuid",
            "noexec",
            "nodev"
        ],
        "source" : "proc",
        "type" : "proc"
    },
    {
        "destination" : "/dev",
        "options" : [
            "nosuid",
            "strictatime",
            "mode=755",
            "size=65536k"
        ],
        "source" : "tmpfs",
        "type" : "tmpfs"
    },
    {
        "destination" : "/sys",
        "options" : [
            "nosuid",
            "noexec",
            "nodev",
            "ro"
        ],
        "source" : "sysfs",
        "type" : "sysfs"
    },
    {
        "destination" : "/dev/pts",
        "options" : [
            "nosuid",
            "noexec",
            "newinstance",
            "ptmxmode=0666",
            "mode=0620",
            "gid=5"
        ],
        "source" : "devpts",
        "type" : "devpts"
    },
    {
        "destination" : "/dev/mqueue",
        "options" : [
            "nosuid",
            "noexec",
            "nodev"
        ],
        "source" : "mqueue",
        "type" : "mqueue"
    },
    {
        "destination" : "/sys/fs/cgroup",
        "options" : [
            "rprivate",
            "nosuid",
            "noexec",
            "nodev",
            "relatime",
            "ro"
        ],
        "source" : "cgroup",
        "type" : "cgroup"
    }
]

env = [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "TERM=xterm",
]

container_config = {
    "annotations": {
    },
    "hostname": "localhost",
    "linux": {
        "maskedPaths" : masked_paths,
        "readonlyPaths": readonly_paths,
        "namespaces": [
            { "type" : "pid"},
            { "type" : "network" },
            {"type" : "ipc"},
            {"type" : "uts"},
            {"type" : "mount"},
            {"type" : "cgroup"}
        ],
        "resources" : {
            "pids" : {
                "limit" : 2048
            }
        },
        "seccomp": seccomp_policy,
        "sysctl" : {
            "net.ipv4.ping_group_range" : "0 0"
        }
    },
    "mounts" : system_mounts,
    "ociVersion" : "1.0.2-dev",
    "process" : {
        "capabilities" : {
            "bounding": caps,
            "effective": caps,
            "inheritable": caps,
            "permitted": caps
        },
        "oomScoreAdj" : 0,
        "rlimits" : [
            {
                "hard" : 1048576,
                "soft" : 1048576,
                "type" : "RLIMIT_NOFILE"
            },
            {
                "hard" : 4194304,
                "soft" : 4194304,
                "type" : "RLIMIT_NPROC"
            }
        ],
        "user" : {
            "gid" : 0,
            "uid" : 0,
            "umask" : 18
        },
        "cwd" : "/",
        "terminal" : False,
        "args" : [ "sh" ],
        "env" : env
    },
    "root" : {
        "path" : ""
    }
}
