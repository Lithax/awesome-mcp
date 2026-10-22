# sandbox-mcp

One MCP server that creates **sandboxes** (Docker/Podman containers, LXC containers, QEMU VMs) and gives the
model **filesystem** and **shell** tools that run *inside* them. It replaces running `fs_mcp` and `shell_mcp`
directly on your machine: their engines are reused, but every tool now takes a `sandbox` argument.

```
uv run sandbox_mcp.py --init-config        # writes ~/.config/sandbox-mcp/config.toml
uv run sandbox_mcp.py --doctor             # which backends work on this machine
uv run sandbox_mcp.py                      # stdio server (what most MCP routers want)
```
No `uv`? `pip install "mcp>=1.12,<2" uvicorn` and run `python sandbox_mcp.py`. Needs Python 3.11+ on the host.
Optional: `pillow` lets `view_image` downscale big images.

## How it is put together (the "backend abstraction")

| Piece | What it is |
|---|---|
| `sbx/backends/{docker,lxc,qemu}.py` | One class per runtime behind a single `Backend` contract: `create/start/stop/destroy/status/info/exec` + images. |
| `sbx/guest/fscore.py` | The `fs_mcp` engine as a stdlib-only library. Runs **in-process** for the host target and is **shipped into the guest** (via the backend's `exec`) for sandboxes, so paths and symlinks are resolved against the *guest's* filesystem, never the host's. Nothing is installed in the guest; the guest only needs `python3` (3.8+; verified on 3.8, 3.9, 3.12). |
| `sbx/shellcore.py` | The `shell_mcp` parser/classifier/redactor/audit as a library, with a pluggable path guard (`GuestPathGuard` judges paths lexically and never touches the host filesystem). Commands run through `Backend.exec`. |
| `sbx/manager.py` | Resolves *defaults < profile < request*, enforces `[limits]`, owns lifecycle, TTL reaping, image allow-lists. |
| `sbx/registry.py` | Durable per-sandbox records with `flock` locks. Sandboxes **survive server restarts**, and several server processes can share one `state_dir`. Only sandboxes in the registry are reachable, so the model can never touch other containers on your machine. |
| `sbx/tools.py`, `sbx/server.py` | The MCP surface, HTTP transport (bearer token), CLI. |

Because the backends are stateless, you can still run three separate servers from one install, sharing a state dir:
`--tools sandbox`, `--tools fs`, `--tools shell`.

## Configuration

Precedence: defaults < config file < CLI flags < `--set KEY=VALUE`. **Unknown keys are errors** (a typo in a
security setting should be loud). See `config.example.toml` for every option. Common CLI flags:

```
--backend docker|lxc|qemu  --image REF  --network none|local|outbound  --cpus 2  --memory-mb 2048
--disk-mb 8192 --ttl 7200  --port 8080:80  --env KEY=VAL  --allow-outbound  --allow-ports
--max-sandboxes 3  --tools fs,shell,sandbox  --default-sandbox dev  --write  --allow-delete
--mount ~/projects/app:/workspace/app:rw   --host-root ~/projects   --transport streamable-http  --set docker.binary=podman  --print-config
```

### Environment settings (per sandbox, set by defaults / `[profiles.*]` / `sandbox_create`)

| Setting | Meaning | Hard ceiling in `[limits]` |
|---|---|---|
| `cpus`, `memory_mb`, `pids` | cgroup caps; swap is always off | `max_cpus`, `max_memory_mb`, `max_pids` |
| `disk_mb` | qemu: size of the CoW overlay (hard). docker: `--storage-opt` if enabled. lxc: not enforced | `max_disk_mb` |
| `network` | `none` (default) / `local` (published ports only, qemu) / `outbound` | `allow_outbound`, `confirm_outbound` |
| `ports` | `[HOST:]GUEST[/proto]`, bound to loopback; host port auto-picked from a range | `allow_ports`, `confirm_ports`, `host_port_min/max`, `max_ports` |
| `env`, `workdir`, `ttl_seconds` | environment, working dir, auto-destroy timer | `max_env_vars`, `max_ttl_seconds` |

With `confirm_outbound` / `confirm_ports` on, granting network or ports asks a **human** (MCP elicitation) each time;
if the client can't ask, the request is refused.

### Backend capability matrix

| | docker/podman | lxc (classic `lxc-*`) | qemu |
|---|---|---|---|
| networks | none, outbound | none, outbound (veth on your bridge) | none, local, outbound (user-mode) |
| published ports | yes (outbound) | no (use the IP from `sandbox_info`) | yes |
| disk cap | best effort | no | yes |
| images | allow-listed pulls | allow-listed `dist/release/arch` from the download template | admin-declared https URL + **mandatory sha256**, or files you drop in `images_dir` |
| exec channel | `docker exec` | `lxc-attach` | QEMU Guest Agent over virtio-serial (no network/SSH) |
| folder mappings | `--mount type=bind` | `lxc.mount.entry` bind (unprivileged: files show as `nobody`, see below) | virtio-9p, mounted in the guest via the agent (guest kernel needs 9p) |

## Folder mappings (making a host folder appear in a sandbox)

You (the administrator) decide which folders of this machine a sandbox can see. Declare them once, then attach them:

```toml
[mounts.project]
host  = "~/projects/demo"      # must be an existing directory on this machine
guest = "/workspace/demo"      # where it appears inside the sandbox
mode  = "rw"                   # "ro" is the default

[sandbox]
mounts = ["project"]           # attached to every new sandbox (or per profile: [profiles.dev] mounts = [...])
```

or just `--mount ~/projects/demo:/workspace/demo:rw` on the command line (repeatable, read-only unless `:rw`; it adds to
whatever the config file attaches). It works the same way on all three backends. Mapped paths are automatically allowed
for the file tools and `run_command`, even outside `[fs] guest_roots`.

**The model never supplies a host path.** By default it cannot choose mappings at all. If you set
`[limits] allow_mount_requests = true`, it may name one of your *declared* mappings in `sandbox_create(mounts=[...])`; a human
is then asked to approve it (`confirm_mounts`), and the prompt shows the real host path and whether it is read-write.
Mappings you attach yourself never prompt. What the model can see about a mapping is its sandbox path and mode, not the
host path (the audit log does record the host side).

What is refused, at startup and again each time a sandbox is created (the folder may have been swapped for a symlink):
a host path that is not an existing directory (so `docker.sock` and friends can't be mapped); `/`, `/proc`, `/sys`, `/dev`,
and `/run` (host service sockets live there; `/run/media` and `/run/mnt` are fine); anything that contains or sits inside the
state dir, this config file, the audit log, or the LXC/QEMU image directories (a writable view of those would let a sandbox rewrite
its own limits or an LXC hook and run code on your machine); the server's own code when the mapping is `rw`; commas/quotes/control characters in
host paths; `..` or characters outside `A-Za-z0-9._/-` in sandbox paths; `/proc`, `/sys`, `/dev` as a target.

Things to know:

* **`rw` means real files.** `run_command` can change or delete them even while `[fs] read_only = true` (that setting only governs
  the file tools; a read-only *mapping* is enforced by the kernel/QEMU and holds for both). The file tools' secret-hiding rules
  (`.env`, SSH keys...) do not stop a shell from reading a mapped file: don't map folders that hold secrets. `delete_path` will
  create a `.mcp-trash/` inside a writable mapping.
* **Ownership.** Docker (rootful): files created by the container's root are root-owned on the host; use rootless podman, or
  `[docker] user = "UID:GID"`. QEMU: the VM's writes appear as *you* (the qemu process's user). LXC (unprivileged): your files show up as
  `nobody` inside, so a read-only mapping works but a writable one needs an idmap in `[lxc] extra_config` (or a world-writable folder);
  privileged LXC has no such issue.
* **SELinux hosts** (Fedora/RHEL): set `[docker] mount_selinux = "shared"` (`:z`) or `"private"` (`:Z`) or the container can't read the folder.
* **QEMU** uses virtio-9p: the guest kernel needs the `9p` and `9pnet_virtio` modules (stock Ubuntu/Debian kernels have them; some very
  trimmed cloud kernels do not, and the VM is then stopped with an error that says so). Mappings are re-mounted every time the VM starts.
  9p is not fast for huge trees of tiny files.
* A symlink inside a mapped folder is followed by the *sandbox*, in the sandbox's own filesystem, never on your host.
* The mapping is fixed when the sandbox is created (stored in its record); editing the config later affects only new sandboxes.

## Security model (what is enforced where)

* **Model controls only validated parameters.** It cannot pass raw `docker` flags, host paths, privileged mode, host
  networking, arbitrary image URLs or arbitrary names; admin-only `extra_args` exist in config.
* **Containers**: `--cap-drop ALL` + a short cap-add list, `no-new-privileges`, memory (swap off)/cpu/pids limits, `--init`,
  core dumps off, bounded logs, `--network none` unless approved. **VMs**: qemu's seccomp sandbox
  (`spawn/elevateprivileges/resourcecontrol/obsolete=deny`), `-nodefaults`, no display, private control sockets, run unprivileged.
  **LXC**: unprivileged by default (root needs `allow_privileged`), cgroup2 caps, extra capability drops.
* **Images**: allow-lists; QEMU base images are never written (per-sandbox overlay), backing-file chains and exotic formats are refused, downloads are HTTPS + sha256 verified.
* **Timeouts really kill**: the deadline runs *inside* the guest (`timeout -s KILL`), because `docker exec`/`lxc-attach`/guest-exec leave the process running when a client disappears.
* **File tools** keep fs_mcp's guarantees (root confinement, symlink resolution, deny/write-deny rules, atomic writes, trash-on-delete, size caps), now evaluated inside the guest. `transfer_files` tars with size/member caps, skips symlinks/devices/protected files, rejects traversal, strips setuid.
* **Shell**: same classifier as `shell_mcp` (block / ask a human / allow, secret redaction, rate limit, concurrency cap). Network tools are judged against *that sandbox's* network mode.
* **Shell sessions** (`sbx/session.py`): `run_command` carries the working directory and *exported* environment variables (`cd`, `export`, `unset`, PATH via e.g. `source venv/bin/activate`) from one call to the next, per named `session` (default `default`). State is captured at shell exit, held on the host and replayed as data (never sourced/eval'd, nothing written in the guest), and re-validated: the cwd goes through the same path guard as an explicit `cwd`, execution-hijack variables (`LD_*`, `BASH_ENV`, `EDITOR`, `PAGER`, ...) are not carried, PATH-style variables must be absolute, sizes are capped. Not persisted: unexported shell variables, functions, aliases, `set` options, background jobs. A timed-out/killed command leaves the session unchanged; stop/start/destroy and server restarts reset sessions. `reset_shell_session` clears them; `shell_info` lists variable *names* only. Disable with `[shell.session] enabled = false`. The host target stays stateless.
* **Host target** (`sandbox="host"`) is off unless `[host] enabled`, read-only unless `fs_write`, shell off unless `[host] shell`. The server's own config, state dir, audit log and code are never writable through it.
* **Audit log** (`[audit] log_file`): tamper-evident hash chain of every call; file contents and env values are never logged. One audit file per server process (the chain is per process).
* HTTP transport requires a ≥16-char bearer token (or `--no-auth` on loopback). Runtime CLIs run with a scrubbed environment.

### Things to know

* Sandbox `env` values are stored with the sandbox (and in the LXC config file) — don't put real secrets there.
* QEMU `outbound` uses user-mode networking: the guest can reach host loopback services at `10.0.2.2`. Use `local`/`none` if that matters. Docker/LXC `outbound` gives the guest whatever your chosen network/bridge allows — point `docker.outbound_network` at a firewalled network for egress control.
* Strict shell modes (`readonly`/`allowlist`) are host-only; sandboxes use `standard`/`permissive` because the sandbox is the boundary.
* File tools need `python3` in the image; `run_command` does not. QEMU images must run `qemu-guest-agent`.
* Running as root is discouraged everywhere (LXC refuses without `allow_privileged`; qemu warns).

## Tools

`sandbox_backends, sandbox_create, sandbox_list, sandbox_info, sandbox_start, sandbox_stop, sandbox_destroy, sandbox_extend,
image_list, image_pull, image_remove` · `list_allowed_directories, list_directory, directory_tree, file_info, read_file,
read_multiple_files, view_image, search_files, grep` · `write_file, append_file, edit_file, create_directory, move_path,
copy_path, delete_path, transfer_files` (write tools exist only with `[fs] read_only = false`; `delete_path` also needs
`allow_delete`) · `run_command, check_command, shell_info, reset_shell_session`.

## Tests and what they do and do not prove

`python -m pytest` (127 tests, plus one opt-in real-guest test): fs engine incl. traversal/symlink/tar attacks; agent protocol on a real Python subprocess;
config validation; manager limits, ports, TTL, rollback; end-to-end over a real MCP stdio client including the human-approval flow.
Exercised against **real** binaries: `qemu-system-x86_64` (every flag we pass is accepted under seccomp, pidfile/QMP,
forced stop, the "image has no guest agent" failure + cleanup), `qemu-img` (overlays, backing-chain refusal), `genisoimage` (seed ISO), the guest agent on Python 3.8/3.9/3.12.
Folder mappings: validation, gating and the exact argv/config each backend emits are unit-tested; the QEMU path is also exercised with a
**real** QEMU (every flag accepted under its seccomp sandbox, the 9p devices appear), and - opt-in, `tests/test_qemu_9p_guest.py` - with a
**real Linux kernel** booted under QEMU running the backend's actual mount script: reads, writes landing on the host with the host user's
ownership (verified both as root and as an unprivileged uid), read-only enforcement, idempotent re-mount, and no symlink leak. The Docker and
LXC mapping paths are **not yet verified against a real daemon / real LXC** (see below).
Exercised against **fakes** only: the Docker and LXC CLIs (command construction, parsing, lifecycle) and the QEMU guest-agent protocol
(a fake agent that executes locally). **Not yet run against: a real Docker/Podman daemon, real LXC, or a real guest OS with
qemu-guest-agent.** Run `--doctor`, then create a sandbox of each kind you intend to use and report anything that differs.
