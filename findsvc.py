from idc import *
from idaapi import *
from idautils import *




SVC_DIC={"f0001":"__ARM_NR_breakpoint","f0002":"__ARM_NR_cacheflush","f0003":"__ARM_NR_usr26","f0004":"__ARM_NR_usr32","f0005":"__ARM_NR_set_tls","0":"__NR_restart_syscall","1":"__NR_exit","2":"__NR_fork","3":"__NR_read","4":"__NR_write","5":"__NR_open","6":"__NR_close","8":"__NR_creat","9":"__NR_link","10":"__NR_unlink","11":"__NR_execve","12":"__NR_chdir","13":"__NR_time","14":"__NR_mknod","15":"__NR_chmod","16":"__NR_lchown","19":"__NR_lseek","20":"__NR_getpid","21":"__NR_mount","22":"__NR_umount","23":"__NR_setuid","24":"__NR_getuid","25":"__NR_stime","26":"__NR_ptrace","27":"__NR_alarm","29":"__NR_pause","30":"__NR_utime","33":"__NR_access","34":"__NR_nice","36":"__NR_sync","37":"__NR_kill","38":"__NR_rename","39":"__NR_mkdir","40":"__NR_rmdir","41":"__NR_dup","42":"__NR_pipe","43":"__NR_times","45":"__NR_brk","46":"__NR_setgid","47":"__NR_getgid","49":"__NR_geteuid","50":"__NR_getegid","51":"__NR_acct","52":"__NR_umount2","54":"__NR_ioctl","55":"__NR_fcntl","57":"__NR_setpgid","60":"__NR_umask","61":"__NR_chroot","62":"__NR_ustat","63":"__NR_dup2","64":"__NR_getppid","65":"__NR_getpgrp","66":"__NR_setsid","67":"__NR_sigaction","70":"__NR_setreuid","71":"__NR_setregid","72":"__NR_sigsuspend","73":"__NR_sigpending","74":"__NR_sethostname","75":"__NR_setrlimit","76":"__NR_getrlimit","77":"__NR_getrusage","78":"__NR_gettimeofday","79":"__NR_settimeofday","80":"__NR_getgroups","81":"__NR_setgroups","82":"__NR_select","83":"__NR_symlink","85":"__NR_readlink","86":"__NR_uselib","87":"__NR_swapon","88":"__NR_reboot","89":"__NR_readdir","90":"__NR_mmap","91":"__NR_munmap","92":"__NR_truncate","93":"__NR_ftruncate","94":"__NR_fchmod","95":"__NR_fchown","96":"__NR_getpriority","97":"__NR_setpriority","99":"__NR_statfs","100":"__NR_fstatfs","102":"__NR_socketcall","103":"__NR_syslog","104":"__NR_setitimer","105":"__NR_getitimer","106":"__NR_stat","107":"__NR_lstat","108":"__NR_fstat","111":"__NR_vhangup","113":"__NR_syscall","114":"__NR_wait4","115":"__NR_swapoff","116":"__NR_sysinfo","117":"__NR_ipc","118":"__NR_fsync","119":"__NR_sigreturn","120":"__NR_clone","121":"__NR_setdomainname","122":"__NR_uname","124":"__NR_adjtimex","125":"__NR_mprotect","126":"__NR_sigprocmask","128":"__NR_init_module","129":"__NR_delete_module","131":"__NR_quotactl","132":"__NR_getpgid","133":"__NR_fchdir","134":"__NR_bdflush","135":"__NR_sysfs","136":"__NR_personality","138":"__NR_setfsuid","139":"__NR_setfsgid","140":"__NR__llseek","141":"__NR_getdents","142":"__NR__newselect","143":"__NR_flock","144":"__NR_msync","145":"__NR_readv","146":"__NR_writev","147":"__NR_getsid","148":"__NR_fdatasync","149":"__NR__sysctl","150":"__NR_mlock","151":"__NR_munlock","152":"__NR_mlockall","153":"__NR_munlockall","154":"__NR_sched_setparam","155":"__NR_sched_getparam","156":"__NR_sched_setscheduler","157":"__NR_sched_getscheduler","158":"__NR_sched_yield","159":"__NR_sched_get_priority_max","160":"__NR_sched_get_priority_min","161":"__NR_sched_rr_get_interval","162":"__NR_nanosleep","163":"__NR_mremap","164":"__NR_setresuid","165":"__NR_getresuid","168":"__NR_poll","169":"__NR_nfsservctl","170":"__NR_setresgid","171":"__NR_getresgid","172":"__NR_prctl","173":"__NR_rt_sigreturn","174":"__NR_rt_sigaction","175":"__NR_rt_sigprocmask","176":"__NR_rt_sigpending","177":"__NR_rt_sigtimedwait","178":"__NR_rt_sigqueueinfo","179":"__NR_rt_sigsuspend","180":"__NR_pread64","181":"__NR_pwrite64","182":"__NR_chown","183":"__NR_getcwd","184":"__NR_capget","185":"__NR_capset","186":"__NR_sigaltstack","187":"__NR_sendfile","190":"__NR_vfork","191":"__NR_ugetrlimit","192":"__NR_mmap2","193":"__NR_truncate64","194":"__NR_ftruncate64","195":"__NR_stat64","196":"__NR_lstat64","197":"__NR_fstat64","198":"__NR_lchown32","199":"__NR_getuid32","200":"__NR_getgid32","201":"__NR_geteuid32","202":"__NR_getegid32","203":"__NR_setreuid32","204":"__NR_setregid32","205":"__NR_getgroups32","206":"__NR_setgroups32","207":"__NR_fchown32","208":"__NR_setresuid32","209":"__NR_getresuid32","210":"__NR_setresgid32","211":"__NR_getresgid32","212":"__NR_chown32","213":"__NR_setuid32","214":"__NR_setgid32","215":"__NR_setfsuid32","216":"__NR_setfsgid32","217":"__NR_getdents64","218":"__NR_pivot_root","219":"__NR_mincore","220":"__NR_madvise","221":"__NR_fcntl64","224":"__NR_gettid","225":"__NR_readahead","226":"__NR_setxattr","227":"__NR_lsetxattr","228":"__NR_fsetxattr","229":"__NR_getxattr","230":"__NR_lgetxattr","231":"__NR_fgetxattr","232":"__NR_listxattr","233":"__NR_llistxattr","234":"__NR_flistxattr","235":"__NR_removexattr","236":"__NR_lremovexattr","237":"__NR_fremovexattr","238":"__NR_tkill","239":"__NR_sendfile64","240":"__NR_futex","241":"__NR_sched_setaffinity","242":"__NR_sched_getaffinity","243":"__NR_io_setup","244":"__NR_io_destroy","245":"__NR_io_getevents","246":"__NR_io_submit","247":"__NR_io_cancel","248":"__NR_exit_group","249":"__NR_lookup_dcookie","250":"__NR_epoll_create","251":"__NR_epoll_ctl","252":"__NR_epoll_wait","253":"__NR_remap_file_pages","256":"__NR_set_tid_address","257":"__NR_timer_create","258":"__NR_timer_settime","259":"__NR_timer_gettime","260":"__NR_timer_getoverrun","261":"__NR_timer_delete","262":"__NR_clock_settime","263":"__NR_clock_gettime","264":"__NR_clock_getres","265":"__NR_clock_nanosleep","266":"__NR_statfs64","267":"__NR_fstatfs64","268":"__NR_tgkill","269":"__NR_utimes","270":"__NR_arm_fadvise64_64","271":"__NR_pciconfig_iobase","272":"__NR_pciconfig_read","273":"__NR_pciconfig_write","274":"__NR_mq_open","275":"__NR_mq_unlink","276":"__NR_mq_timedsend","277":"__NR_mq_timedreceive","278":"__NR_mq_notify","279":"__NR_mq_getsetattr","280":"__NR_waitid","281":"__NR_socket","282":"__NR_bind","283":"__NR_connect","284":"__NR_listen","285":"__NR_accept","286":"__NR_getsockname","287":"__NR_getpeername","288":"__NR_socketpair","289":"__NR_send","290":"__NR_sendto","291":"__NR_recv","292":"__NR_recvfrom","293":"__NR_shutdown","294":"__NR_setsockopt","295":"__NR_getsockopt","296":"__NR_sendmsg","297":"__NR_recvmsg","298":"__NR_semop","299":"__NR_semget","300":"__NR_semctl","301":"__NR_msgsnd","302":"__NR_msgrcv","303":"__NR_msgget","304":"__NR_msgctl","305":"__NR_shmat","306":"__NR_shmdt","307":"__NR_shmget","308":"__NR_shmctl","309":"__NR_add_key","310":"__NR_request_key","311":"__NR_keyctl","312":"__NR_semtimedop","313":"__NR_vserver","314":"__NR_ioprio_set","315":"__NR_ioprio_get","316":"__NR_inotify_init","317":"__NR_inotify_add_watch","318":"__NR_inotify_rm_watch","319":"__NR_mbind","320":"__NR_get_mempolicy","321":"__NR_set_mempolicy","322":"__NR_openat","323":"__NR_mkdirat","324":"__NR_mknodat","325":"__NR_fchownat","326":"__NR_futimesat","327":"__NR_fstatat64","328":"__NR_unlinkat","329":"__NR_renameat","330":"__NR_linkat","331":"__NR_symlinkat","332":"__NR_readlinkat","333":"__NR_fchmodat","334":"__NR_faccessat","335":"__NR_pselect6","336":"__NR_ppoll","337":"__NR_unshare","338":"__NR_set_robust_list","339":"__NR_get_robust_list","340":"__NR_splice","341":"__NR_arm_sync_file_range","342":"__NR_tee","343":"__NR_vmsplice","344":"__NR_move_pages","345":"__NR_getcpu","346":"__NR_epoll_pwait","347":"__NR_kexec_load","348":"__NR_utimensat","349":"__NR_signalfd","350":"__NR_timerfd_create","351":"__NR_eventfd","352":"__NR_fallocate","353":"__NR_timerfd_settime","354":"__NR_timerfd_gettime","355":"__NR_signalfd4","356":"__NR_eventfd2","357":"__NR_epoll_create1","358":"__NR_dup3","359":"__NR_pipe2","360":"__NR_inotify_init1","361":"__NR_preadv","362":"__NR_pwritev","363":"__NR_rt_tgsigqueueinfo","364":"__NR_perf_event_open","365":"__NR_recvmmsg","366":"__NR_accept4","367":"__NR_fanotify_init","368":"__NR_fanotify_mark","369":"__NR_prlimit64","370":"__NR_name_to_handle_at","371":"__NR_open_by_handle_at","372":"__NR_clock_adjtime","373":"__NR_syncfs","374":"__NR_sendmmsg","375":"__NR_setns","376":"__NR_process_vm_readv","377":"__NR_process_vm_writev","378":"__NR_kcmp","379":"__NR_finit_module","380":"__NR_sched_setattr","381":"__NR_sched_getattr"}



def getFuncByAddr(currentAddr):
    return idaapi.get_func(currentAddr)


def getFuncStartByAddr(currentAddr):
    # getFuncByAddr(ea).startEA
    return idc.GetFunctionAttr(currentAddr, FUNCATTR_START)


def getFuncEndByAddr(currentAddr):
    # getFuncByAddr(ea).endEA
    return idc.GetFunctionAttr(currentAddr, FUNCATTR_END)


def getOpIns(currentAddr):
    return idc.GetMnem(currentAddr).lower()


def getOpnd(currentAddr, whichone):
    return idc.GetOpnd(currentAddr, whichone)


# return string
def decCodeByAddr(currentAddr):
    return idc.GetDisasm(currentAddr)


def reverseFindInFunc(target, startAddr):
    pos = -1
    start = getFuncStartByAddr(startAddr)
    end = getFuncEndByAddr(startAddr)
    # print('end = ',hex(end),'start = ',hex(start))
    target = target.strip('\n')
    pos = startAddr
    while pos < end and pos > start:
        line = decCodeByAddr(pos)
        if target.lower() in line.lower():
            break
        pos = idc.PrevHead(startAddr)
    return pos


def getInt(num):
    num = str(num)
    if num.lower().startswith('0xf00'):
        num = num.replace('0x', '')
        return num
    if num.lower().startswith('0x'):
        num = num.replace('0x', '')
        return str(int(num, 16))
    return num


def getSVCNumInThisFunc(pos):
    ret = None;
    items = list(FuncItems(pos))
    for item in items:
        item_code = decCodeByAddr(item)
        opins = getOpIns(item)
        if opins in 'svc' and getOpnd(item, 0) == '0':
            r7pos = reverseFindInFunc("r7", item)
            if r7pos == -1:
                print 'no r7'
            svc_num = getOpnd(r7pos, 1)
            ret = svc_num.replace('#', '').replace('=', '')
            # print 'func-->' + hex(getFuncByAddr(r7pos).startEA).upper() + ' r7 ins-->' + hex(
            #     r7pos) + ' instruction-->' + decCodeByAddr(r7pos)+' sigNum--> '+getInt(ret)
            break
    return ret
#
for i in Functions():
    n = getSVCNumInThisFunc(i)
    n = getInt(n).lower()
    if n!='None'.lower():
        newFuncName=SVC_DIC[n]
        MakeName(i,newFuncName)
        AddBpt(i)