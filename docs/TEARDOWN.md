# Teardown — LinuxONE `s390x`

**Owner:** Person 1 · **Verified:** 2026-10-18 on the allocated instance

This removes everything the platform work created, and nothing else. It does
**not** destroy the instance — the instance is Datathon-provided and other
team members may still be using it. Stop here if anything below would remove
shared state.

---

## What this deployment created

| Item | Location | Remove? |
|---|---|---|
| Application tree | `~/aegis` (~60 MB incl. `.venv`) | Yes |
| Service logs | `~/aegis-logs` | Yes |
| Control script | `~/aegis-ctl.sh` | Yes |
| Collectors | `~/collect_preflight.sh`, `~/check_post.sh`, `~/check_manifests.sh`, `~/probe2.sh`, `~/tetragon_check.sh` | Yes |
| Event stream | Redis key `security:events`, `security:smoke_events` | Yes |
| Named FIFO | `/tmp/aegis-feed.jsonl` | Yes |
| Python toolchain | `python3-pip`, `python3-venv`, `redis-server` | **Keep** |
| SSH keypair | `/home/linux1/.ssh` | **Keep** — you need it to reconnect |
| Known-host entry | (on your workstation) | **Keep** |

The `apt` packages were installed from Ubuntu's default repositories. They
are listed as *keep* because removing them can destabilise the base image
(`python3-pip` in particular interacts with system `python3`) and because
tearing down a shared VM's package set is riskier than leaving it.

---

## Procedure

### 1. Stop the services

```bash
bash ~/aegis-ctl.sh stop
```

Verify nothing is still listening:

```bash
ss -ltn | grep -E '6379|8080|8081' || echo "no listeners"
```

Expected: `no listeners` on 8080/8081. Redis may still show 6379 if the
systemd unit is running; that is covered in step 4.

### 2. Remove application state

```bash
rm -rf ~/aegis ~/aegis-logs ~/aegis-ctl.sh
rm -f  ~/collect_preflight.sh ~/check_post.sh ~/check_manifests.sh \
       ~/probe2.sh ~/tetragon_check.sh /tmp/aegis-feed.jsonl
rm -f  ~/aegis-deploy.tar
```

Confirm:

```bash
ls -la ~ | grep -E 'aegis|preflight|manifest|tetragon' || echo "clean"
```

### 3. Clear the event stream

```bash
redis-cli DEL security:events security:smoke_events
redis-cli XLEN security:events      # -> 0
```

> **Do not run `FLUSHALL` on a shared instance** unless you are certain no one
> else is using this Redis. `DEL` on the two named keys is the correct,
> surgical action.

### 4. Redis

```bash
sudo systemctl stop redis-server
sudo systemctl disable redis-server     # prevents restart on reboot
```

If the instance is being returned to the pool, leaving Redis stopped but
enabled means it returns on next boot. Disable it if that matters.

### 5. Verify

```bash
echo "--- listeners ---"
ss -ltn | grep -E '6379|8080|8081' || echo "  none"

echo "--- processes ---"
ps -eo pid,args | grep -E '[d]ashboard_api|[f]orwarder.main|[a]egis-feed' \
  || echo "  none"

echo "--- home ---"
ls ~ | grep -i aegis || echo "  clean"

echo "--- redis ---"
redis-cli ping 2>&1 || echo "  redis stopped"
```

All five checks must report clean/none.

---

## Full instance reset (only if returning the VM)

If the instance is being returned to the organizers and no one else needs it:

```bash
sudo systemctl stop redis-server
sudo apt-get purge -y redis-server python3-pip python3-venv
sudo apt-get autoremove -y
rm -rf ~/aegis ~/aegis-logs ~/.bash_history
```

**Warning:** this removes the Python tooling the rest of the team may rely on.
Confirm with the team first. It also does not remove the SSH authorized key —
that is provisioned by the portal, not by us.

---

## What was deliberately **not** modified

Per the preflight constraints, none of the following were touched, and
teardown must not touch them:

- Kernel parameters (`sysctl`)
- Loaded kernel modules
- `tracefs` / `debugfs` mounts — these are provided by the platform
- Any file under `/etc` other than the systemd unit state in step 4
- Any firewall rule (none was added)

There is nothing to undo at the kernel level. This deployment was entirely
userspace.

---

## Post-teardown credential action

The SSH private key used for this deployment should be rotated once the
Datathon concludes:

1. Create a new key pair in the LinuxONE portal.
2. Replace the key on your workstation.
3. Delete the old private key file from disk.

If the key was ever committed to a repository, copied to a shared location,
or pasted into a chat or issue tracker, rotate it **immediately** rather than
waiting.

---

*Verified against the running state on 2026-10-18. No `docker compose down -v`
appears here because no containers or volumes were ever created on this
host — there is no container runtime.*