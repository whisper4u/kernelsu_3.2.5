#include "linux/compiler.h"
#include "linux/cred.h"
#include "linux/jump_label.h"
#include "linux/printk.h"
#include "linux/spinlock.h"
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

// 对指定包名的 App 跳过 sucompat 逻辑，使其 stat/faccessat 调用回归原生，
// 从而规避基于 stat 时延差的 root 检测。完全在模块内完成，无需任何外部脚本。
//
// 设计要点(解决跨手机通用 + 热路径零额外延迟两个问题):
// 1. 包名编译期固定(ksu_hide_pkg)，跨手机通用，不依赖写死的 uid。
// 2. 热路径用 uid 比对(O(1))，与已验证可用的 a5f82e3 同开销，避免 get_cmdline 的延迟。
// 3. uid 通过"惰性填充"得到: 慢路径(仅未缓存的进程触发一次)用 get_cmdline 识别包名，
//    命中后把 current_uid() 写入 ksu_hide_uids[] 缓存，之后该 uid 全程走快路径。
static const char *const ksu_hide_pkg[] = {
    "com.chunqiunativecheck",
    "com.zhenxi.hunter",
    "icu.nullptr.nativetest",
};

#define KSU_HIDE_UID_MAX 8
// 命中包名的 uid 会被填入 ksu_hide_uids[]; 已扫描确认非隐藏的 uid 填入 ksu_scanned_uids[]。
// 0 表示槽位空闲。两个数组保证每个 uid 最多触发一次 get_cmdline，之后全程 O(1) 比对。
static uid_t ksu_hide_uids[KSU_HIDE_UID_MAX];
static uid_t ksu_scanned_uids[KSU_HIDE_UID_MAX];
static DEFINE_SPINLOCK(ksu_hide_uid_lock);

// 在已扫描数组中查找/写入 uid。返回 true 表示已存在(找到了)。
static bool ksu_scanned_remember(uid_t uid)
{
    unsigned long flags;
    int slot;

    spin_lock_irqsave(&ksu_hide_uid_lock, flags);
    for (slot = 0; slot < KSU_HIDE_UID_MAX; slot++) {
        if (ksu_scanned_uids[slot] == uid)
            break;
    }
    if (slot == KSU_HIDE_UID_MAX) {
        for (slot = 0; slot < KSU_HIDE_UID_MAX; slot++) {
            if (ksu_scanned_uids[slot] == 0) {
                ksu_scanned_uids[slot] = uid;
                break;
            }
        }
    }
    spin_unlock_irqrestore(&ksu_hide_uid_lock, flags);
    return slot < KSU_HIDE_UID_MAX;
}

// 慢路径: 用 cmdline 判断当前进程包名是否在隐藏列表。命中则缓存其 uid。
// 无论命中与否，都把当前 uid 记入"已扫描"，避免后续重复 get_cmdline。
static bool ksu_match_pkg_and_cache_uid(void)
{
    char buf[128];
    int len, pkg_len, i;
    uid_t uid;
    unsigned long flags;
    int slot;
    bool matched = false;

    len = get_cmdline(current, buf, sizeof(buf) - 1);
    if (len <= 0)
        goto out_scan;
    buf[len] = '\0';
    pkg_len = strnlen(buf, len);
    if (pkg_len == 0)
        goto out_scan;

    for (i = 0; i < ARRAY_SIZE(ksu_hide_pkg); i++) {
        const char *pkg = ksu_hide_pkg[i];
        int n = strlen(pkg);
        if (strncmp(buf, pkg, n) != 0)
            continue;

        // 命中包名，把 uid 缓存起来，后续走 O(1) 快路径。
        uid = current_uid().val;
        if (uid == 0)
            goto out_scan; // 不应隐藏 root 进程

        spin_lock_irqsave(&ksu_hide_uid_lock, flags);
        for (slot = 0; slot < KSU_HIDE_UID_MAX; slot++) {
            if (ksu_hide_uids[slot] == uid)
                break;
        }
        if (slot == KSU_HIDE_UID_MAX) {
            for (slot = 0; slot < KSU_HIDE_UID_MAX; slot++) {
                if (ksu_hide_uids[slot] == 0) {
                    ksu_hide_uids[slot] = uid;
                    break;
                }
            }
        }
        spin_unlock_irqrestore(&ksu_hide_uid_lock, flags);
        matched = true;
        break;
    }

out_scan:
    // 记录已扫描，后续该 uid 直接走快路径，不再 get_cmdline。
    ksu_scanned_remember(current_uid().val);
    return matched;
}

static inline bool ksu_is_hidden_app(void)
{
    uid_t uid = current_uid().val;
    int i;

    // 快路径 1: 直接比对已缓存的隐藏 uid，O(1)。
    for (i = 0; i < KSU_HIDE_UID_MAX; i++) {
        if (ksu_hide_uids[i] != 0 && ksu_hide_uids[i] == uid)
            return true;
    }

    // 快路径 2: 已扫描确认非隐藏，O(1) 直接返回。
    for (i = 0; i < KSU_HIDE_UID_MAX; i++) {
        if (ksu_scanned_uids[i] == uid)
            return false;
    }

    // 慢路径: 当前 uid 既不在隐藏列表也不在已扫描列表，用 cmdline 判断包名并缓存。
    return ksu_match_pkg_and_cache_uid();
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
