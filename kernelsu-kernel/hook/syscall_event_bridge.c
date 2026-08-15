#include "linux/compiler.h"
#include "linux/cred.h"
#include "linux/jump_label.h"
#include "linux/printk.h"
#include "selinux/selinux.h"
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/static_key.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/mm.h>

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "hook/tp_marker.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "policy/app_profile.h"
#include "runtime/ksud.h"
#include "sulog/event.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"
#include "feature/adb_root.h"

// 仅对指定包名的 App 跳过 sucompat 逻辑，使其 stat/faccessat 调用回归原生，
// 从而规避基于 stat 时延差的 root 检测。完全在模块内完成，无需任何外部脚本。
// 匹配来源用 /proc/pid/cmdline 的首字段(即完整包名，如 com.chunqiunativecheck)，
// 该字段是进程级、所有线程共享，不受线程池线程名影响，因此比 comm 可靠。
// 包名编译期固定，如需增减改 ksu_hide_pkg 列表即可，跨手机通用(不依赖 uid)。
static const char *const ksu_hide_pkg[] = {
    "com.chunqiunativecheck",
    "com.zhenxi.hunter",
};

static inline bool ksu_is_hidden_app(void)
{
    char buf[128];
    int len, pkg_len, i;

    // get_cmdline 读取当前进程 cmdline，返回写入字节数；首参数是包名，以 '\0' 结尾。
    len = get_cmdline(current, buf, sizeof(buf) - 1);
    if (len <= 0) {
        pr_err("KSU_HIDE: get_cmdline failed len=%d pid=%d\n", len, current->pid);
        return false;
    }
    buf[len] = '\0';
    // 取第一个 '\0' 之前的字符串作为包名(忽略后续参数)。
    pkg_len = strnlen(buf, len);
    if (pkg_len == 0) {
        pr_err("KSU_HIDE: empty cmdline pid=%d\n", current->pid);
        return false;
    }

    pr_err("KSU_HIDE: cmdline=[%s] len=%d pid=%d\n", buf, len, current->pid);

    for (i = 0; i < ARRAY_SIZE(ksu_hide_pkg); i++) {
        const char *pkg = ksu_hide_pkg[i];
        int n = strlen(pkg);

        if (strncmp(buf, pkg, n) == 0)
            return true;
    }
    return false;
}

static int ksu_handle_init_mark_tracker(const char __user **filename_user)
{
    char path[64];
    unsigned long addr;
    const char __user *fn;
    long ret;

    if (unlikely(!filename_user))
        return 0;

    addr = untagged_addr((unsigned long)*filename_user);
    fn = (const char __user *)addr;
    ret = strncpy_from_user(path, fn, sizeof(path));
    if (ret < 0)
        return 0;

    path[sizeof(path) - 1] = '\0';
    if (unlikely(strcmp(path, KSUD_PATH) == 0)) {
        pr_info("hook_manager: escape to root for init executing ksud: %d\n", current->pid);
        escape_to_root_for_init();
    } else if (likely(strstr(path, "/app_process") == NULL && strstr(path, "/adbd") == NULL)) {
        pr_info("hook_manager: unmark %d exec %s\n", current->pid, path);
        ksu_clear_task_tracepoint_flag_if_needed(current);
    }

    return 0;
}

long __nocfi ksu_hook_newfstatat(int orig_nr, const struct pt_regs *regs)
{
    pr_err("KSU_HOOK: newfstatat enter pid=%d\n", current->pid);
    if (ksu_is_hidden_app())
        return ksu_syscall_table[orig_nr](regs);

    if (!ksu_su_compat_enabled)
        return ksu_syscall_table[orig_nr](regs);

    return ksu_handle_stat_sucompat(orig_nr, (struct pt_regs *)regs);
}

long __nocfi ksu_hook_faccessat(int orig_nr, const struct pt_regs *regs)
{
    if (ksu_is_hidden_app())
        return ksu_syscall_table[orig_nr](regs);

    if (!ksu_su_compat_enabled)
        return ksu_syscall_table[orig_nr](regs);

    return ksu_handle_faccessat_sucompat(orig_nr, (struct pt_regs *)regs);
}

DEFINE_STATIC_KEY_TRUE(ksud_execve_key);

void ksu_stop_ksud_execve_hook()
{
    static_branch_disable(&ksud_execve_key);
}

long __nocfi ksu_hook_execve(int orig_nr, const struct pt_regs *regs)
{
    const char __user **filename_user = (const char __user **)&PT_REGS_PARM1(regs);
    const char __user *const __user *argv_user = (const char __user *const __user *)PT_REGS_PARM2(regs);
    bool current_is_init = is_init(current_cred());
    struct ksu_sulog_pending_event *pending_root_execve = NULL;
    long ret;

    if (static_branch_unlikely(&ksud_execve_key))
        ksu_execve_hook_ksud(regs);

    if (current_euid().val == 0)
        pending_root_execve = ksu_sulog_capture_root_execve(*filename_user, argv_user, GFP_KERNEL);

    if (current->pid != 1 && current_is_init) {
        ksu_handle_init_mark_tracker(filename_user);
        ret = ksu_adb_root_handle_execve((struct pt_regs *)regs);
        if (ret) {
            pr_err("adb root failed: %ld\n", ret);
        }
    } else if (ksu_su_compat_enabled) {
        ret = ksu_handle_execve_sucompat(filename_user, orig_nr, (struct pt_regs *)regs);
        ksu_sulog_emit_pending(pending_root_execve, ret, GFP_KERNEL);
        return ret;
    }

    ret = ksu_syscall_table[orig_nr](regs);
    ksu_sulog_emit_pending(pending_root_execve, ret, GFP_KERNEL);
    return ret;
}

long __nocfi ksu_hook_setresuid(int orig_nr, const struct pt_regs *regs)
{
    uid_t old_uid = current_uid().val;
    long ret = ksu_syscall_table[orig_nr](regs);

    if (ret < 0)
        return ret;

    ksu_handle_setresuid(old_uid, current_uid().val);
    return ret;
}
