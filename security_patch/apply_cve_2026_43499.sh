#!/usr/bin/env bash
set -euo pipefail

kernel_version="${1:-}"
patch_dir="${2:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
rtmutex_file="kernel/locking/rtmutex.c"

if [ -z "$kernel_version" ]; then
  echo "Usage: $0 <kernel-version> [patch-dir]" >&2
  exit 2
fi

if [ ! -f "$rtmutex_file" ]; then
  echo "ERROR: $rtmutex_file not found. Run this from kernel_platform/common." >&2
  exit 1
fi

if grep -q 'struct task_struct \*waiter_task = waiter->task;' "$rtmutex_file"; then
  echo "CVE-2026-43499 rtmutex fix already present; skipping."
  exit 0
fi

try_apply_patch() {
  local patch_file="$1"

  if patch --dry-run -p1 < "$patch_file" >/tmp/cve-2026-43499.patch.log 2>&1; then
    patch -p1 < "$patch_file"
    rm -f /tmp/cve-2026-43499.patch.log
    return 0
  fi

  cat /tmp/cve-2026-43499.patch.log >&2
  rm -f /tmp/cve-2026-43499.patch.log
  return 1
}

append_file() {
  local target="$1"
  local insert_file="$2"
  local tmp_file

  tmp_file="$(mktemp)"
  awk -v insert_file="$insert_file" '
    { print }
    END {
      while ((getline line < insert_file) > 0)
        print line
      close(insert_file)
    }
  ' "$target" > "$tmp_file"
  mv "$tmp_file" "$target"
}

insert_file_before_last_endif() {
  local target="$1"
  local insert_file="$2"
  local tmp_file

  tmp_file="$(mktemp)"
  awk -v insert_file="$insert_file" '
    { lines[NR] = $0; if ($0 ~ /^#endif/) last_endif = NR }
    function emit() {
      while ((getline line < insert_file) > 0)
        print line
      close(insert_file)
    }
    END {
      for (i = 1; i <= NR; i++) {
        if (i == last_endif)
          emit()
        print lines[i]
      }
      if (!last_endif)
        emit()
    }
  ' "$target" > "$tmp_file"
  mv "$tmp_file" "$target"
}

install_scoped_guard_support() {
  local tmp_file

  if [ ! -f "$patch_dir/scoped_guard_cleanup.h" ]; then
    echo "ERROR: scoped_guard cleanup header not found." >&2
    return 1
  fi

  if [ ! -f include/linux/cleanup.h ] ||
     ! grep -q 'scoped_guard' include/linux/cleanup.h; then
    cp "$patch_dir/scoped_guard_cleanup.h" include/linux/cleanup.h
  fi

  if [ -f include/linux/compiler_attributes.h ]; then
    if ! grep -q '^#define __cleanup(func)' include/linux/compiler_attributes.h; then
      insert_file_before_last_endif include/linux/compiler_attributes.h "$patch_dir/scoped_guard_compiler_cleanup.txt"
    fi
  elif [ -f include/linux/compiler.h ]; then
    if ! grep -q '^#define __cleanup(func)' include/linux/compiler.h; then
      append_file include/linux/compiler.h "$patch_dir/scoped_guard_compiler_cleanup.txt"
    fi
  else
    echo "ERROR: neither compiler_attributes.h nor compiler.h found." >&2
    return 1
  fi

  if [ -f include/linux/compiler-clang.h ] &&
     ! grep -q 'Clang prior to 17' include/linux/compiler-clang.h; then
    append_file include/linux/compiler-clang.h "$patch_dir/scoped_guard_compiler_clang.txt"
  fi

  if ! grep -q '#include <linux/cleanup.h>' include/linux/spinlock.h; then
    tmp_file="$(mktemp)"
    awk '
      { print }
      !done && /^#include <linux\/lockdep.h>/ {
        print "#include <linux/cleanup.h>"
        done = 1
      }
      !done && /^#include <linux\/bottom_half.h>/ {
        print "#include <linux/cleanup.h>"
        done = 1
      }
      END {
        if (!done)
          print "#include <linux/cleanup.h>"
      }
    ' include/linux/spinlock.h > "$tmp_file"
    mv "$tmp_file" include/linux/spinlock.h
  fi

  if ! grep -q 'DEFINE_LOCK_GUARD_1(raw_spinlock' include/linux/spinlock.h; then
    tmp_file="$(mktemp)"
    awk -v insert_file="$patch_dir/scoped_guard_spinlock_guards.txt" '
      function emit() {
        while ((getline line < insert_file) > 0)
          print line
        close(insert_file)
      }
      !done && /^#undef __LINUX_INSIDE_SPINLOCK_H/ {
        emit()
        done = 1
      }
      !done && /^#endif .*__LINUX_SPINLOCK_H/ {
        emit()
        done = 1
      }
      { print }
      END {
        if (!done)
          emit()
      }
    ' include/linux/spinlock.h > "$tmp_file"
    mv "$tmp_file" include/linux/spinlock.h
  fi
}

ensure_scoped_guard_support() {
  if grep -qs 'DEFINE_LOCK_GUARD_1(raw_spinlock' include/linux/spinlock.h &&
     grep -qs 'scoped_guard' include/linux/cleanup.h; then
    return 0
  fi

  local guard_patch="$patch_dir/cve-2026-43499-guards.patch"
  if [ ! -f "$guard_patch" ]; then
    echo "ERROR: scoped_guard helper patch not found: $guard_patch" >&2
    return 1
  fi

  echo "Applying scoped_guard/raw_spinlock helper backport..."
  if try_apply_patch "$guard_patch"; then
    return 0
  fi

  echo "Patch helper did not match; installing scoped_guard support directly..."
  install_scoped_guard_support
}

ensure_rtmutex_c99() {
  case "$kernel_version" in
    5.10|5.15)
      ;;
    *)
      return 0
      ;;
  esac

  local makefile="kernel/locking/Makefile"
  if [ ! -f "$makefile" ]; then
    echo "ERROR: $makefile not found." >&2
    return 1
  fi

  if grep -q '^CFLAGS_rtmutex\.o .*std=gnu99' "$makefile"; then
    return 0
  fi

  echo "Forcing rtmutex.o to gnu99 for scoped_guard on 5.x..."
  local tmp_makefile
  tmp_makefile="$(mktemp)"
  awk '
    !done && /^obj-\$\(CONFIG_RT_MUTEXES\).*rtmutex\.o/ {
      print "CFLAGS_REMOVE_rtmutex.o += -std=gnu89"
      print "CFLAGS_rtmutex.o += -std=gnu99"
      done = 1
    }
    { print }
    END {
      if (!done) {
        print "CFLAGS_REMOVE_rtmutex.o += -std=gnu89"
        print "CFLAGS_rtmutex.o += -std=gnu99"
      }
    }
  ' "$makefile" > "$tmp_makefile"
  mv "$tmp_makefile" "$makefile"
}

case "$kernel_version" in
  5.10)
    primary_patch="$patch_dir/cve-2026-43499-rtmutex-5.10.patch"
    fallback_patch="$patch_dir/cve-2026-43499-rtmutex-5.15.patch"
    ;;
  5.15)
    primary_patch="$patch_dir/cve-2026-43499-rtmutex-5.15.patch"
    fallback_patch=""
    ;;
  6.1|6.6)
    primary_patch="$patch_dir/cve-2026-43499-rtmutex-6.1-6.6.patch"
    fallback_patch=""
    ;;
  *)
    echo "ERROR: unsupported kernel version for CVE-2026-43499 patch: $kernel_version" >&2
    exit 1
    ;;
esac

if [ ! -f "$primary_patch" ]; then
  echo "ERROR: patch file not found: $primary_patch" >&2
  exit 1
fi

echo "Applying CVE-2026-43499 rtmutex fix for kernel $kernel_version..."
ensure_scoped_guard_support
ensure_rtmutex_c99

if try_apply_patch "$primary_patch"; then
  echo "CVE-2026-43499 rtmutex fix applied."
  exit 0
fi

if [ -n "${fallback_patch:-}" ] && [ -f "$fallback_patch" ]; then
  echo "Primary patch did not match; trying fallback shape: $(basename "$fallback_patch")"
  if try_apply_patch "$fallback_patch"; then
    echo "CVE-2026-43499 rtmutex fix applied with fallback patch."
    exit 0
  fi
fi

echo "ERROR: failed to apply CVE-2026-43499 rtmutex fix." >&2
exit 1
