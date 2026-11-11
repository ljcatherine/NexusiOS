import NexusCore

enum HostMetricsCommand {
    /// Read-only Linux interfaces; no user values or shell input are interpolated.
    static func snapshot(timeout: Int) -> String {
        let body = #"""
        printf 'nexus_metrics\t1\n'
        if [ -r /proc/sys/kernel/random/boot_id ]; then
          IFS= read -r boot_id < /proc/sys/kernel/random/boot_id
          printf 'boot_id\t%s\n' "$boot_id"
        fi
        if [ -r /proc/uptime ]; then awk '{ print "uptime\t" $1 }' /proc/uptime; fi
        if [ -r /proc/loadavg ]; then awk '{ print "load\t" $1 "\t" $2 "\t" $3 }' /proc/loadavg; fi
        if [ -r /proc/stat ]; then awk '$1 ~ /^cpu[0-9]+$/ { count++ } END { if (count > 0) print "cpu_count\t" count }' /proc/stat; fi
        if [ -r /proc/stat ]; then
          read_cpu() { awk '/^cpu / { total=0; for (i=2; i<=9; i++) total += $i; idle=$5+$6; printf "%.0f %.0f\n", total, idle; exit }' /proc/stat; }
          cpu_before=$(read_cpu)
          sleep 1
          cpu_after=$(read_cpu)
          if [ -n "$cpu_before" ] && [ -n "$cpu_after" ]; then
            awk -v before="$cpu_before" -v after="$cpu_after" 'BEGIN { split(before,b," "); split(after,a," "); dt=a[1]-b[1]; di=a[2]-b[2]; if (dt>0 && di>=0 && di<=dt) printf "cpu_utilization\t%.2f\n", (dt-di)*100/dt }'
          fi
        fi
        if [ -r /proc/meminfo ]; then awk '/^MemTotal:/ { total=$2 } /^MemAvailable:/ { available=$2; has_available=1 } END { if (total > 0 && has_available) printf "memory\t%.0f\t%.0f\n", total * 1024, available * 1024 }' /proc/meminfo; fi
        df -Pk / 2>/dev/null | awk 'NR == 2 { printf "filesystem\t%.0f\t%.0f\t%.0f\n", $2 * 1024, $3 * 1024, $4 * 1024 }'
        if [ -r /proc/net/dev ]; then awk 'NR > 2 { interface=$1; sub(/:$/, "", interface); if (interface != "lo") printf "network\t%s\t%s\t%s\n", interface, $2, $10 }' /proc/net/dev; fi
        if command -v nvidia-smi >/dev/null 2>&1; then
          printf 'nvidia_tool\tavailable\n'
          nvidia-smi --query-gpu=index,utilization.gpu,memory.total,memory.used,temperature.gpu --format=csv,noheader,nounits 2>/dev/null |
            awk -F, '{ for (i=1; i<=5; i++) gsub(/^[[:space:]]+|[[:space:]]+$/, "", $i); if ($1 ~ /^[0-9]+$/) printf "nvidia\t%s\t%s\t%s\t%s\t%s\n", $1, $2, $3, $4, $5 }'
        else
          printf 'nvidia_tool\tunavailable\n'
        fi
        """#
        return RemoteCommandTimeout.wrap(body, timeout: timeout, maximum: 120, errorPrefix: "nexus_metrics_error")
    }
}
