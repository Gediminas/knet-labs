//! Attach an aya fentry program to a **kernel-module** function — which aya's
//! `FEntry` can't, since module functions live in *split BTF*
//! (`/sys/kernel/btf/<module>`) whose type ids continue after vmlinux's.
//!
//! `FEntry::load` only targets vmlinux and `attach_btf_obj_fd` is crate-private, so
//! we load + attach via raw `bpf()` syscalls. `BPF_PROG_LOAD` needs:
//!   - `attach_btf_id`     — absolute id = vmlinux type count + module-local index
//!   - `attach_btf_obj_fd` — fd to the kernel's loaded module BTF
//!
//! Instructions come from the public `aya_obj` ELF parser; `relocate_maps`/
//! `relocate_calls` fix the program's map/`.rodata` refs to the maps aya created in
//! `Ebpf::load`, so aya-log `warn!` keeps working via the shared `AYA_LOGS` map.

use std::collections::HashSet;
use std::ffi::CStr;
use std::io;
use std::mem;
use std::os::fd::{AsFd as _, AsRawFd, FromRawFd, OwnedFd, RawFd};

use anyhow::{Context as _, Result, anyhow, bail};
use aya::Ebpf;
use aya::maps::{Map, MapData, MapFd};
use aya_obj::Object;
use aya_obj::generated::{
    bpf_attach_type::BPF_TRACE_FENTRY, bpf_attr, bpf_btf_info, bpf_cmd,
    bpf_prog_type::BPF_PROG_TYPE_TRACING,
};
use libc::c_long;
use log::{info, warn};

/// Keeps the loaded program, its attach link, and the module BTF fd alive.
/// Dropping this detaches the fentry program.
pub struct Fentry {
    _prog_fd: OwnedFd,
    _link_fd: OwnedFd,
    _module_btf_fd: OwnedFd,
}

/// Loads `prog_name` from `elf` as an fentry on the module function `func_name`,
/// resolving the module BTF object named `module_name`. Map / `.rodata`
/// references in the program are relocated against the maps `ebpf` already
/// created (so the program shares aya's `AYA_LOGS` map and logs via `EbpfLogger`).
pub fn attach_fentry(
    ebpf: &Ebpf,
    elf: &[u8],
    prog_name: &str,
    func_name: &str,
    module_name: &str,
) -> Result<Fentry> {
    // 1. Locate the kernel's loaded module BTF object (fd + raw bytes).
    let (module_btf_fd, module_btf) = find_module_btf(module_name)
        .with_context(|| format!("locating kernel BTF object '{module_name}'"))?;

    // 2. Compute the absolute attach_btf_id of `func_name` within the module.
    let (start_id, base_str_len) = vmlinux_meta().context("reading vmlinux BTF")?;
    let local_idx = func_index(&module_btf, func_name, base_str_len)
        .with_context(|| format!("finding FUNC '{func_name}' in '{module_name}' BTF"))?
        .ok_or_else(|| anyhow!("FUNC '{func_name}' not found in '{module_name}' BTF"))?;
    let attach_btf_id = start_id + local_idx;
    info!(
        "split-btf: {func_name} = abs id {attach_btf_id} (start_id {start_id} + local {local_idx})"
    );

    // 3. Parse the ELF and relocate the program's map / `.rodata` references
    //    against the maps aya already loaded. `_map_fds` holds the borrowed fds
    //    open through `BPF_PROG_LOAD` (the relocated instructions embed them).
    let mut obj = Object::parse(elf).context("parsing bpf ELF")?;
    let _map_fds = relocate_against_ebpf(&mut obj, ebpf).context("relocating map references")?;

    // 4. Extract the (now-relocated) program instructions and load it.
    let prog = obj
        .programs
        .get(prog_name)
        .ok_or_else(|| anyhow!("program '{prog_name}' not in ELF"))?;
    let func = obj
        .functions
        .get(&prog.function_key())
        .ok_or_else(|| anyhow!("function for '{prog_name}' not in ELF"))?;

    let prog_fd = load_fentry(
        prog_name,
        &func.instructions,
        &prog.license,
        attach_btf_id,
        module_btf_fd.as_raw_fd(),
    )
    .context("BPF_PROG_LOAD (fentry)")?;

    // 5. Attach with the modern link API. The target was baked in at load time
    //    (attach_btf_obj_fd + attach_btf_id), so target_fd/target_btf_id are 0.
    let link_fd =
        link_create_fentry(prog_fd.as_raw_fd()).context("BPF_LINK_CREATE (fentry attach)")?;

    info!("Hooked  fentry: {prog_name} → {module_name}:{func_name}");
    Ok(Fentry {
        _prog_fd: prog_fd,
        _link_fd: link_fd,
        _module_btf_fd: module_btf_fd,
    })
}

// ---------------------------------------------------------------------------
// Raw bpf() syscall plumbing
// ---------------------------------------------------------------------------

unsafe fn bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> io::Result<i64> {
    // SAFETY: caller passes a zero-initialized bpf_attr with the fields for `cmd` set.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd as c_long,
            attr as *mut bpf_attr as c_long,
            mem::size_of::<bpf_attr>() as c_long,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn zeroed_attr() -> bpf_attr {
    // SAFETY: bpf_attr is a POD union; all-zero is a valid representation.
    unsafe { mem::zeroed() }
}

// ---------------------------------------------------------------------------
// Step 1: find the module BTF object loaded in the kernel
// ---------------------------------------------------------------------------

/// Iterates every BTF object loaded in the kernel and returns the fd + raw bytes
/// of the one named `name`. Requires CAP_SYS_ADMIN (BTF id iteration).
fn find_module_btf(name: &str) -> Result<(OwnedFd, Vec<u8>)> {
    let mut cur = 0u32;
    loop {
        let Some(next) = btf_get_next_id(cur)? else {
            bail!("no kernel BTF object named '{name}' (is the module loaded?)");
        };
        cur = next;

        let fd = match btf_get_fd_by_id(cur) {
            Ok(fd) => fd,
            // The object may have gone away between NEXT_ID and GET_FD_BY_ID.
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => continue,
            Err(e) => return Err(e).context("BPF_BTF_GET_FD_BY_ID"),
        };

        let (this_name, btf_size) = btf_name_and_size(fd.as_raw_fd())?;
        if this_name == name {
            let bytes = btf_raw_bytes(fd.as_raw_fd(), btf_size)?;
            return Ok((fd, bytes));
        }
    }
}

fn btf_get_next_id(id: u32) -> Result<Option<u32>> {
    let mut attr = zeroed_attr();
    attr.__bindgen_anon_6.__bindgen_anon_1.start_id = id;
    match unsafe { bpf(bpf_cmd::BPF_BTF_GET_NEXT_ID, &mut attr) } {
        Ok(_) => Ok(Some(unsafe { attr.__bindgen_anon_6.next_id })),
        Err(e) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(e) => Err(e).context("BPF_BTF_GET_NEXT_ID"),
    }
}

fn btf_get_fd_by_id(id: u32) -> io::Result<OwnedFd> {
    let mut attr = zeroed_attr();
    attr.__bindgen_anon_6.__bindgen_anon_1.btf_id = id;
    let fd = unsafe { bpf(bpf_cmd::BPF_BTF_GET_FD_BY_ID, &mut attr)? } as RawFd;
    // SAFETY: a successful GET_FD_BY_ID returns a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Reads a BTF object's name and total size via BPF_OBJ_GET_INFO_BY_FD.
fn btf_name_and_size(fd: RawFd) -> Result<(String, u32)> {
    let mut namebuf = [0u8; 64];
    let mut info: bpf_btf_info = unsafe { mem::zeroed() };
    info.name = namebuf.as_mut_ptr() as u64;
    info.name_len = namebuf.len() as u32;
    obj_get_info(fd, &mut info)?;

    let name = CStr::from_bytes_until_nul(&namebuf)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok((name, info.btf_size))
}

/// Reads a BTF object's raw bytes via BPF_OBJ_GET_INFO_BY_FD.
fn btf_raw_bytes(fd: RawFd, size: u32) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; size as usize];
    let mut info: bpf_btf_info = unsafe { mem::zeroed() };
    info.btf = buf.as_mut_ptr() as u64;
    info.btf_size = buf.len() as u32;
    obj_get_info(fd, &mut info)?;
    buf.truncate(info.btf_size as usize);
    Ok(buf)
}

fn obj_get_info(fd: RawFd, info: &mut bpf_btf_info) -> Result<()> {
    let mut attr = zeroed_attr();
    attr.info.bpf_fd = fd as u32;
    attr.info.info = info as *mut bpf_btf_info as u64;
    attr.info.info_len = mem::size_of::<bpf_btf_info>() as u32;
    unsafe { bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut attr) }.context("BPF_OBJ_GET_INFO_BY_FD")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Step 2: minimal split-BTF walker
// ---------------------------------------------------------------------------

const BTF_MAGIC: u16 = 0xeb9f;
const BTF_KIND_FUNC: u32 = 12;

/// vmlinux (base) BTF metadata needed to resolve split BTF:
///   * `start_id`     — number of vmlinux type records + 1 (for the implicit
///     `void` at id 0); the absolute id the first module type is assigned.
///   * `base_str_len` — length of vmlinux's string section. Split BTF type name
///     offsets are *global*: an offset `>= base_str_len` points into the
///     module's own string section at `off - base_str_len`.
fn vmlinux_meta() -> Result<(u32, u32)> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux").context("reading vmlinux BTF")?;
    let str_len = btf_header(&data)?.3;
    Ok((count_records(&data)? + 1, str_len))
}

/// Parses the BTF header, returning `(hdr_len, type_off, type_len, str_len)`.
/// `str_off` is folded into the section slicing in [`btf_sections`].
fn btf_header(data: &[u8]) -> Result<(usize, usize, usize, u32)> {
    // struct btf_header { u16 magic; u8 version; u8 flags;
    //   u32 hdr_len, type_off, type_len, str_off, str_len; }
    if data.len() < 24 {
        bail!("BTF too small");
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != BTF_MAGIC {
        bail!("bad BTF magic {magic:#x} (big-endian BTF unsupported)");
    }
    let u32_at = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
    Ok((
        u32_at(4) as usize,  // hdr_len
        u32_at(8) as usize,  // type_off
        u32_at(12) as usize, // type_len
        u32_at(20),          // str_len
    ))
}

/// Splits a BTF blob into its type and string sections.
fn btf_sections(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let (hdr_len, type_off, type_len, str_len) = btf_header(data)?;
    let str_off = u32::from_le_bytes(data[16..20].try_into().unwrap()) as usize;

    let tstart = hdr_len + type_off;
    let sstart = hdr_len + str_off;
    let types = data
        .get(tstart..tstart + type_len)
        .ok_or_else(|| anyhow!("BTF type section out of bounds"))?;
    let strings = data
        .get(sstart..sstart + str_len as usize)
        .ok_or_else(|| anyhow!("BTF string section out of bounds"))?;
    Ok((types, strings))
}

/// Extra bytes following the 12-byte common record header, by BTF kind/vlen.
fn extra_size(kind: u32, vlen: u32) -> usize {
    let vlen = vlen as usize;
    match kind {
        1 => 4,             // INT
        3 => 12,            // ARRAY (btf_array)
        4 | 5 => vlen * 12, // STRUCT / UNION (btf_member)
        6 => vlen * 8,      // ENUM (btf_enum)
        13 => vlen * 8,     // FUNC_PROTO (btf_param)
        14 => 4,            // VAR (btf_var)
        15 => vlen * 12,    // DATASEC (btf_var_secinfo)
        17 => 4,            // DECL_TAG (btf_decl_tag)
        19 => vlen * 12,    // ENUM64 (btf_enum64)
        _ => 0,             // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT, TYPE_TAG
    }
}

/// Walks every record, invoking `visit(index, name_off, kind)`. Stops early if
/// the visitor returns `Some`.
fn walk<T>(types: &[u8], mut visit: impl FnMut(u32, u32, u32) -> Option<T>) -> Result<Option<T>> {
    let mut pos = 0usize;
    let mut idx = 0u32;
    while pos + 12 <= types.len() {
        let name_off = u32::from_le_bytes(types[pos..pos + 4].try_into().unwrap());
        let info = u32::from_le_bytes(types[pos + 4..pos + 8].try_into().unwrap());
        let vlen = info & 0xffff;
        let kind = (info >> 24) & 0x1f;
        if let Some(v) = visit(idx, name_off, kind) {
            return Ok(Some(v));
        }
        pos += 12 + extra_size(kind, vlen);
        idx += 1;
    }
    if pos != types.len() {
        bail!("BTF type section did not end on a record boundary (unknown kind?)");
    }
    Ok(None)
}

fn count_records(data: &[u8]) -> Result<u32> {
    let (types, _) = btf_sections(data)?;
    let mut count = 0u32;
    walk(types, |_, _, _| {
        count += 1;
        None::<()>
    })?;
    Ok(count)
}

/// 0-based record index of the FUNC named `name` within the (split) module BTF.
/// `base_str_len` is vmlinux's string-section length; module name offsets are
/// global, so we subtract it before indexing the module string section.
fn func_index(data: &[u8], name: &str, base_str_len: u32) -> Result<Option<u32>> {
    let (types, strings) = btf_sections(data)?;
    walk(types, |idx, name_off, kind| {
        if kind == BTF_KIND_FUNC && str_at(strings, name_off, base_str_len) == Some(name) {
            Some(idx)
        } else {
            None
        }
    })
}

/// Resolves a split-BTF name offset against the module's string section.
/// Offsets below `base_str_len` live in vmlinux's strings (not loaded here);
/// module function names always sit above it, so those return `None`.
fn str_at(strings: &[u8], off: u32, base_str_len: u32) -> Option<&str> {
    let local = off.checked_sub(base_str_len)? as usize;
    CStr::from_bytes_until_nul(strings.get(local..)?)
        .ok()?
        .to_str()
        .ok()
}

// ---------------------------------------------------------------------------
// Step 3: relocation guard
// ---------------------------------------------------------------------------

/// Resolves the parsed object's map / `.rodata` relocations against the maps
/// `ebpf` already created in `Ebpf::load`, by pairing each map definition with
/// the kernel fd aya holds for it. Returns the borrowed map fds, which must stay
/// open until after `BPF_PROG_LOAD` (the relocated instructions embed their raw
/// fd numbers).
fn relocate_against_ebpf(obj: &mut Object, ebpf: &Ebpf) -> Result<Vec<MapFd>> {
    // Map defs come from the parsed ELF; their kernel fds come from `ebpf`.
    // Clone the defs so the relocation borrow doesn't alias `&mut obj`.
    let defs: Vec<(String, aya_obj::Map)> = obj
        .maps
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let mut fds: Vec<MapFd> = Vec::new();
    let mut tuples: Vec<(&str, RawFd, &aya_obj::Map)> = Vec::new();
    for (name, def) in &defs {
        let Some(map) = ebpf.map(name) else {
            // A referenced map missing here would make aya's relocator fall back
            // to a section lookup and panic. The usual cause is a consumed map
            // (e.g. EbpfLogger::init's `take_map("AYA_LOGS")` run too early).
            warn!("map '{name}' not found in Ebpf; skipping (relocation may fail)");
            continue;
        };
        let Some(md) = map_data(map) else {
            warn!("map '{name}': unsupported map type; skipping (relocation may fail)");
            continue;
        };
        let fd = md
            .info()
            .with_context(|| format!("info for map '{name}'"))?
            .fd()
            .with_context(|| format!("fd for map '{name}'"))?;
        tuples.push((name.as_str(), fd.as_fd().as_raw_fd(), def));
        fds.push(fd);
    }

    let text_sections: HashSet<usize> = obj.functions.keys().map(|(idx, _)| *idx).collect();
    obj.relocate_maps(tuples.into_iter(), &text_sections)
        .context("Object::relocate_maps")?;
    obj.relocate_calls(&text_sections)
        .context("Object::relocate_calls")?;
    Ok(fds)
}

/// Borrows the inner [`MapData`] of a [`Map`] (aya keeps it `pub(crate)`).
///
/// `Map` is a large non-`#[non_exhaustive]` enum that grows across aya releases,
/// so we match the data-bearing types we actually relocate against (array /
/// perf-event / hash maps — incl. `AYA_LOGS` and `.rodata`) and return `None` for
/// anything else rather than requiring an exhaustive match that breaks on upgrade.
fn map_data(map: &Map) -> Option<&MapData> {
    use aya::maps::Map::*;
    // The `_` arm is forward-compat for aya releases that add `Map` variants; on
    // older aya the explicit arms already cover everything, making it unreachable.
    #[allow(unreachable_patterns)]
    match map {
        Array(d) | BloomFilter(d) | CpuMap(d) | DevMap(d) | DevMapHash(d) | HashMap(d)
        | LpmTrie(d) | LruHashMap(d) | PerCpuArray(d) | PerCpuHashMap(d) | PerCpuLruHashMap(d)
        | PerfEventArray(d) | ProgramArray(d) | Queue(d) | RingBuf(d) | SockHash(d)
        | SockMap(d) | SkStorage(d) | Stack(d) | StackTraceMap(d) | Unsupported(d)
        | XskMap(d) => Some(d),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Step 4/5: load + attach
// ---------------------------------------------------------------------------

fn load_fentry(
    name: &str,
    insns: &[aya_obj::generated::bpf_insn],
    license: &CStr,
    attach_btf_id: u32,
    module_btf_fd: RawFd,
) -> Result<OwnedFd> {
    let mut log = vec![0u8; 64 * 1024];
    let mut attr = zeroed_attr();
    {
        let u = unsafe { &mut attr.__bindgen_anon_3 };
        u.prog_type = BPF_PROG_TYPE_TRACING as u32;
        u.expected_attach_type = BPF_TRACE_FENTRY as u32;
        u.insns = insns.as_ptr() as u64;
        u.insn_cnt = insns.len() as u32;
        u.license = license.as_ptr() as u64;
        u.attach_btf_id = attach_btf_id;
        u.__bindgen_anon_1.attach_btf_obj_fd = module_btf_fd as u32;

        let name_bytes = name.as_bytes();
        let n = name_bytes.len().min(u.prog_name.len() - 1);
        for (dst, &src) in u.prog_name.iter_mut().zip(&name_bytes[..n]) {
            *dst = src as _;
        }

        u.log_level = 1;
        u.log_buf = log.as_mut_ptr() as u64;
        u.log_size = log.len() as u32;
    }

    match unsafe { bpf(bpf_cmd::BPF_PROG_LOAD, &mut attr) } {
        Ok(fd) => Ok(unsafe { OwnedFd::from_raw_fd(fd as RawFd) }),
        Err(e) => {
            let log = CStr::from_bytes_until_nul(&log)
                .map(|c| c.to_string_lossy().into_owned())
                .unwrap_or_default();
            if !log.trim().is_empty() {
                warn!("verifier log:\n{log}");
            }
            Err(e).context("bpf(BPF_PROG_LOAD)")
        }
    }
}

/// Attaches a loaded fentry program via the link API (`bpf_link_create`), the
/// modern equivalent of the legacy `BPF_RAW_TRACEPOINT_OPEN` path used by aya.
/// `target_fd` and `target_btf_id` stay 0: fentry's target is fixed at
/// `BPF_PROG_LOAD` time and the verifier already bound it there.
fn link_create_fentry(prog_fd: RawFd) -> Result<OwnedFd> {
    let mut attr = zeroed_attr();
    attr.link_create.__bindgen_anon_1.prog_fd = prog_fd as u32;
    attr.link_create.attach_type = BPF_TRACE_FENTRY as u32;
    let fd = unsafe { bpf(bpf_cmd::BPF_LINK_CREATE, &mut attr)? } as RawFd;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
