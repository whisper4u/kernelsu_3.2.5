#!/system/bin/sh
# 开机后自动把指定包名的 uid 写入 KernelSU 模块参数 ksu_hide_uid，
# 使这些 App 的 stat/faccessat 调用走原生路径，规避基于时延差的 root 检测。
# 用法: 放入 /data/adb/service.d/ 或 KSU post-mount 目录，开机自动执行。
# 注意: 需 root 权限(脚本由 KSU/root 上下文执行)。

PARAM="/sys/module/kernelsu/parameters/ksu_hide_uid"

# 需要隐藏的包名列表
PACKAGES="com.chunqiunativecheck com.zhenxi.hunter"

# 等待模块参数文件出现
for i in $(seq 1 30); do
    [ -w "$PARAM" ] && break
    sleep 1
done
[ -w "$PARAM" ] || exit 1

UIDS=""
for pkg in $PACKAGES; do
    line=$(pm list packages -U 2>/dev/null | grep "package:$pkg ")
    uid=$(echo "$line" | sed 's/.*uid:\([0-9]*\).*/\1/')
    if [ -n "$uid" ] && [ "$uid" != "$line" ]; then
        UIDS="$UIDS $uid"
    fi
done

UIDS=$(echo $UIDS | tr -s ' ' | sed 's/^ //')
[ -z "$UIDS" ] && exit 0

echo "$UIDS" > "$PARAM"
exit 0
