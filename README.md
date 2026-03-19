# Sutatikku

Sutatikku is a command-line tool that packages dynamically linked ELF binaries or any scripts with their interpreters, their dependent libraries, and arbitrary resource files into a single, self-contained executable.

The resulting binary can be copied to any Linux environment (where libraries are missing or completely different) and executed immediately without any additional runtime.

## Features

-   **Complete Portability**:

    Analyzes shared library dependencies reported by `ldd` and embeds them into the binary. It also supports bundling non-library files like configurations or script source code. At runtime, it uses a novel approach: `seccomp-unotify`-based User-space File Proxy to transparently redirect file access from the target binary to the internal bundle.

-   **Diskless Execution**:

    Can serve bundled files from memory instead of extracting them to a temporary directory. This is ideal for environments with restricted disk access.

-   **Automatic Dependency Profiling**:

    The `--record` mode allows you to trace a live process to see exactly which files it accesses. It then automatically generates a YAML configuration file encompassing all discovered resources.

-   **Rootless Operation (Even without User Namespaces)**: 

    Unlike containers or `chroot`, Sutatikku requires no special privileges to build or run. It does **not** rely on User Namespaces either, making it compatible with Linux distributions where user namespaces are restricted or disabled for security reasons. (e.g. Ubuntu)

## Usage

### Basic Build

Bundle an existing binary into a single file:

```bash
./sutatikku build $(which ls) -o ./myls
./myls /
```

### Customizable YAML Configuration

Use YAML to define environment variables, default arguments, or specific file mappings:

```yaml
# config.yaml syntax example. This config will not be valid on your system as-is
entry:
  path: /usr/bin/python3
  args: ["-c", "print('hello from bundle')"]
files:
  # simple path
  - /usr/lib/python3.12
  # with settings
  - path: ./local_script.py
    map_to: /app/script.py
    prefer_host: false
env:
  - PYTHONPATH=/app
```

```bash
./sutatikku build --config config.yaml -o mypython
```

### Automatic Configuration via Tracing

Identify all files required by a binary by running it:

```bash
# Run curl, record accessed files, and generate a yaml config
./sutatikku gen-config /usr/bin/curl -o curl.yaml --record -- http://example.com
```

## How it Works

A Sutatikku binary consists of a statically linked runner and a compressed payload.

When executed, the runner performs the following steps:
1. Prepares the payload in memory or a temporary directory.
2. Initializes the user-space file proxy using `seccomp-unotify`.
3. Executes the embedded dynamic loader (interpreter) directly, pointing it to the bundled libraries to launch the target process.

## Performance

The overhead of Sutatikku is strictly limited to file-opening operations (`open`, `openat`, `stat`, `access`, etc.).

* App launch speed: Since the Sutatikku runner decompresses the file on launch, your app will take a little longer to start.
* File opening: System calls are intercepted by the Sutatikku proxy process to inject the appropriate file descriptor or `memfd`. This introduces a latency due to context switching.
* No data I/O overhead: However, once a file is opened, operations such as `read`, `write`, and `mmap` occur directly between the kernel and the target process.

## Building the Tool

We provide a Docker environment to build Sutatikku itself as a fully static binary (Alpine/musl based).

```bash
./build_static.sh
```

## Caveats

* Kernel Requirements: Linux Kernel 5.0 or newer is required for `seccomp-unotify` support.
* Single Process Target: The proxy mechanism is designed for the primary target process. If the target forks or executes sub-processes, file access redirection will not be applied to those children.
