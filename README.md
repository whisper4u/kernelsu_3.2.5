# KernelSU LKM (android12-5.10) 自动编译

本仓库用于通过 GitHub Actions 自动编译**带隐藏补丁**的 KernelSU LKM（`.ko`）。

## 补丁说明（合规用途）

`patches/hide_stat_for_uid.patch` 仅做一件事：让 `ksu_hook_newfstatat` /
`ksu_hook_faccessat` 在调用方 uid 等于模块参数 `ksu_hide_uid` 时，直接走原生
syscall 表，跳过 sucompat 逻辑。用途是**自测**自己写的根检测 App
（`com.chunqiunativecheck`），不提供任何通用 root 隐藏能力。

## 使用

1. Fork / 克隆本仓库到 GitHub。
2. 在仓库 **Actions** 页面手动触发 `Build LKM` 工作流（或 push 到 main 自动触发）。
3. 构建完成后在 **Artifacts** 下载 `kernelsu-module`。
4. 安装后设置隐藏 uid：

   ```sh
   # 先查出检测 App 的 uid
   adb shell "su -c 'ps -A -o UID,NAME | grep chunqiunative'"
   # 假设 uid = 10123，写入模块参数
   adb shell "su -c 'echo 10123 > /sys/module/kernel_su_lkm/parameters/ksu_hide_uid'"
   ```

   每次开机后需重新写一次（可放进 KSU 的 post-fs-data 脚本里持久化）。

## 编译目标

- 分支：`android12-5.10`（GKI 5.10.x，覆盖 5.10.226 等所有小版本）
- 内核源码：KernelSU 官方 GKI 构建方式（仅内核头文件 + Module.symvers，无需整 AOSP）

## 免责声明

本仓库仅供本人**自测**使用。请勿用于绕过任何第三方应用的安全检测或违反其服务条款。
