# Gozer

Gozer is a small Windows privilege escalation helper. It checks common local misconfigurations such as weak service permissions, writable service binaries, writable scheduled task targets, risky token privileges, and unquoted service paths.

## Build

Build on Windows with:

```bat
build.bat
```

This produces `bin\gozer.exe`.

## Usage

```bat
gozer.exe [MODULE]
```

## Modules

- `all`: run all checks.
- `srv-perm`: check service start, stop, and restart permissions.
- `srv-unquoted`: check for unquoted service paths.
- `file-perm`: check weak file permissions on service paths and scheduled task targets.
- `hidden-task`: recursively search from `C:\` for writable executable/script/task-related files, including `.exe`, `.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.jse`, `.wsf`, `.hta`, `.dll`, and `.lnk`.
- `priv`: list current group memberships and enabled token privileges, highlighting higher-risk entries.

`hidden-task` may take a while because it recursively scans `C:\`.
