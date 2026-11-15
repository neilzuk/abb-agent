//! Discovery of disks, GPT partitions, filesystems and mounts, without external programs
//! (sysfs, GPT table read from the disk, filesystem superblocks, /proc/self/mountinfo).

use btrfs_image::device::Device;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const GUID_ESP: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
pub const GUID_BIOS_BOOT: &str = "21686148-6449-6E6F-744E-656564454649";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fs {
    None,
    Btrfs,
    Vfat,
    /// ext2, ext3 or ext4 (2, 3, 4).
    Ext(u8),
    Xfs,
    Swap,
    /// LVM physical volume.
    Lvm,
    /// LUKS encrypted container.
    Luks,
}

impl Fs {
    /// Name as reported by blkid (`file_system` field of the device spec).
    pub fn name(&self) -> &str {
        match self {
            Fs::None => "",
            Fs::Btrfs => "btrfs",
            Fs::Vfat => "vfat",
            Fs::Ext(2) => "ext2",
            Fs::Ext(3) => "ext3",
            Fs::Ext(_) => "ext4",
            Fs::Xfs => "xfs",
            Fs::Swap => "swap",
            Fs::Lvm => "LVM2_member",
            Fs::Luks => "crypto_LUKS",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Partition {
    /// e.g. "nvme0n1p2"
    pub name: String,
    pub number: u32,
    /// Bytes from the start of the disk.
    pub offset: u64,
    pub length: u64,
    pub type_guid: String,
    pub fs: Fs,
    /// Filesystem UUID (btrfs/ext) or FAT serial "XXXX-XXXX".
    pub fs_uuid: String,
    /// Main mount point ("/" if present), empty if not mounted.
    pub mount_path: String,
    /// All mount points (a btrfs volume is often mounted several times, one per subvolume).
    pub mounts: Vec<String>,
    /// Mounted read-only (meaningful only if mounted).
    pub read_only: bool,
    /// Not mounted here but held by the kernel: mounted in another mount namespace, a member of
    /// a ZFS pool or md array, mapped by device-mapper. Someone may be writing to it.
    pub busy: bool,
}

impl Partition {
    pub fn device(&self) -> PathBuf {
        PathBuf::from("/dev").join(&self.name)
    }

    pub fn is_esp(&self) -> bool {
        self.type_guid == GUID_ESP
    }

    pub fn is_bios_boot(&self) -> bool {
        self.type_guid == GUID_BIOS_BOOT
    }

    /// Someone may be writing to it while it is read: mounted read-write, or held by the kernel.
    pub fn in_use(&self) -> bool {
        if self.mount_path.is_empty() { self.busy } else { !self.read_only }
    }

    /// `attribute` mask of the device spec (1 normal, |8 ESP, |0x40 BIOS boot).
    pub fn attribute(&self) -> u32 {
        if self.is_esp() {
            9
        } else if self.is_bios_boot() {
            65
        } else {
            1
        }
    }
}

#[derive(Clone, Debug)]
pub struct Disk {
    /// e.g. "nvme0n1"
    pub name: String,
    /// Name of its image on the server without ".img": the kernel name the disk had when it
    /// was first backed up, kept when the kernel names it differently (see `state::image_names`).
    pub image: String,
    pub size: u64,
    pub sector_size: u32,
    /// "GPT" (MBR not supported yet).
    pub layout: String,
    /// Sorted by offset.
    pub partitions: Vec<Partition>,
    /// Supported logical volumes mapped linearly inside an LVM partition. The partition table
    /// still contains the LVM PV; these describe where a mounted filesystem's bytes live in it.
    pub lvm_volumes: Vec<LvmVolume>,
}

/// One deliberately narrow LVM mapping: a single, linear LV starting at PE 0 in a PV with one
/// metadata area. That is enough to preserve the PV metadata and place the filesystem bytes at
/// their original disk offsets without having to interpret arbitrary device-mapper stacks.
#[derive(Clone, Debug)]
pub struct LvmVolume {
    /// Kernel name of the GPT partition holding the PV (e.g. `sda3`).
    pub parent: String,
    /// The filesystem exposed by device-mapper. Its `offset` is the physical byte offset in the
    /// disk image, while `device()` is the logical source read and frozen by the agent.
    pub volume: Partition,
}

impl Disk {
    pub fn device(&self) -> PathBuf {
        PathBuf::from("/dev").join(&self.name)
    }

    /// Image name on the server ("nvme0n1.img").
    pub fn image_name(&self) -> String {
        format!("{}.img", self.image)
    }
}

fn read_trim(p: impl AsRef<Path>) -> std::io::Result<String> {
    Ok(fs::read_to_string(p)?.trim().to_string())
}

fn read_u64(p: impl AsRef<Path>) -> std::io::Result<u64> {
    read_trim(&p)?
        .parse()
        .map_err(|_| std::io::Error::other(format!("{}: invalid number", p.as_ref().display())))
}

/// A disk as `status` and the backup view show it: `nvme0n1 (931.5 GiB)`, plus `· system` when
/// it holds `/`.
pub fn label(d: &Disk) -> String {
    let system = system_disk().is_ok_and(|s| s == d.name);
    format!("{} ({}){}", d.name, crate::ui::size(d.size), if system { " · system" } else { "" })
}

/// Disk containing partition `part` (e.g. "nvme0n1p2" → "nvme0n1").
pub fn parent_disk(part: &str) -> std::io::Result<String> {
    // Device-mapper devices do not have a partition parent of their own. Follow their sole
    // slave first (linear LVM and dm-crypt); ambiguous multi-device stacks stay unsupported.
    let slaves = Path::new("/sys/class/block").join(part).join("slaves");
    if let Ok(entries) = fs::read_dir(slaves) {
        let names: Vec<String> = entries
            .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
            .collect();
        match names.as_slice() {
            [only] => return parent_disk(only),
            [] => {}
            _ => return Err(std::io::Error::other(format!("{part}: spans more than one underlying device"))),
        }
    }
    let link = fs::canonicalize(Path::new("/sys/class/block").join(part))?;
    let parent = link.parent().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned());
    match parent {
        Some(p) if Path::new("/sys/block").join(&p).exists() => Ok(p),
        _ => Ok(part.to_string()),
    }
}

/// Whether `name` (under /sys/block) is a physical disk worth backing up: not a virtual
/// device (loop, zram, ram, device-mapper, md, optical) and not removable or on USB.
fn is_internal_disk(name: &str) -> bool {
    const VIRTUAL: &[&str] = &["loop", "zram", "ram", "dm-", "md", "sr", "nbd", "fd"];
    if VIRTUAL.iter().any(|v| name.starts_with(v)) {
        return false;
    }
    let sys = Path::new("/sys/block").join(name);
    if read_trim(sys.join("removable")).is_ok_and(|r| r == "1") || read_u64(sys.join("size")).unwrap_or(0) == 0 {
        return false;
    }
    !fs::canonicalize(&sys).is_ok_and(|p| p.to_string_lossy().contains("/usb"))
}

/// The kernel sees partitions on disk `name` (whatever the table type).
pub fn has_partitions(name: &str) -> bool {
    fs::read_dir(Path::new("/sys/block").join(name))
        .is_ok_and(|d| d.filter_map(|e| e.ok()).any(|e| e.path().join("partition").exists()))
}

/// An identifier of the disk that does not depend on the order the kernel finds disks in: the
/// WWID (NVMe EUI/NGUID, SCSI/SATA WWN) or else model and serial number.
pub fn stable_id(name: &str) -> Option<String> {
    let sys = Path::new("/sys/block").join(name);
    for p in [sys.join("wwid"), sys.join("device/wwid")] {
        if let Ok(w) = read_trim(p)
            && !w.is_empty()
        {
            return Some(w.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    let model = read_trim(sys.join("device/model")).unwrap_or_default();
    // virtio-blk has `serial` on the disk, SCSI/SATA under the device.
    for p in [sys.join("serial"), sys.join("device/serial")] {
        if let Ok(serial) = read_trim(p)
            && !serial.is_empty()
        {
            return Some(format!("{model} {serial}").trim().to_string());
        }
    }
    // SCSI device identification page (what udev's /dev/disk/by-id/scsi-… names come from).
    let vpd = fs::read(sys.join("device/vpd_pg83")).ok().filter(|v| v.len() > 4)?;
    Some(format!("vpd83:{}", vpd.iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

/// Kernel name of a disk named in the configuration: a kernel name ("nvme0n1"), a device path
/// (stable ones such as /dev/disk/by-id/…, also of a partition: its disk is taken), or "system"
/// for the disk holding `/`.
pub fn resolve(entry: &str) -> std::io::Result<String> {
    if entry == "system" {
        return system_disk();
    }
    let name = if entry.starts_with('/') {
        let dev = fs::canonicalize(entry).map_err(|e| std::io::Error::new(e.kind(), format!("{entry}: {e}")))?;
        parent_disk(&dev.file_name().unwrap_or_default().to_string_lossy())?
    } else {
        entry.to_string()
    };
    if !Path::new("/sys/block").join(&name).exists() {
        return Err(std::io::Error::other(format!("{entry}: no such disk")));
    }
    Ok(name)
}

/// Internal disks of the machine, sorted by name.
pub fn internal_disks() -> std::io::Result<Vec<String>> {
    let mut out: Vec<String> = fs::read_dir("/sys/block")?
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .filter(|n| is_internal_disk(n))
        .collect();
    out.sort();
    Ok(out)
}

/// Disk containing the filesystem mounted at `/`.
pub fn system_disk() -> std::io::Result<String> {
    let mounts = mounts()?;
    let root = mounts
        .iter()
        .find(|m| m.target == "/")
        .ok_or_else(|| std::io::Error::other("mount of / not found"))?;
    // By device number: the source may be a name such as /dev/root. Btrfs has an anonymous
    // device number instead, and a real source.
    let dev = match fs::canonicalize(Path::new("/sys/dev/block").join(&root.dev)) {
        Ok(sys) => sys,
        Err(_) => fs::canonicalize(&root.source)?,
    };
    parent_disk(&dev.file_name().unwrap().to_string_lossy())
}

pub struct Mount {
    pub source: String,
    pub target: String,
    /// Superblock options ("rw,…" or "ro,…").
    pub super_options: String,
    /// Device number "major:minor" (anonymous for btrfs).
    pub dev: String,
}

pub fn mounts() -> std::io::Result<Vec<Mount>> {
    Ok(parse_mountinfo(&fs::read_to_string("/proc/self/mountinfo")?))
}

fn parse_mountinfo(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|l| {
            let (a, b) = l.split_once(" - ")?;
            let dev = a.split(' ').nth(2)?.to_string();
            let target = unescape(a.split(' ').nth(4)?);
            let source = unescape(b.split(' ').nth(1)?);
            let super_options = b.split(' ').nth(2).unwrap_or("").to_string();
            Some(Mount { source, target, super_options, dev })
        })
        .collect()
}

/// Mounts of the block device `devpath` whose number is `dev` ("major:minor", from sysfs). The
/// number is what identifies it: the source may be /dev/root, a symlink or a stale name. Btrfs
/// mounts carry an anonymous number, and are recognised by their source.
fn mounts_of<'a>(mounts: &'a [Mount], dev: &str, devpath: &Path) -> Vec<&'a Mount> {
    mounts
        .iter()
        .filter(|m| {
            (!dev.is_empty() && m.dev == dev)
                || Path::new(&m.source) == devpath
                || fs::canonicalize(&m.source).is_ok_and(|p| p == devpath)
        })
        .collect()
}

/// The kernel holds the block device exclusively (a mount, ZFS, md, device-mapper, swap): an
/// exclusive open fails with EBUSY.
fn claimed(devpath: &Path) -> bool {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::OpenOptions::new().read(true).custom_flags(libc::O_EXCL).open(devpath) {
        Ok(_) => false,
        Err(e) => e.raw_os_error() == Some(libc::EBUSY),
    }
}

/// mountinfo encodes spaces and the like as \040.
fn unescape(s: &str) -> String {
    let mut out = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len()
            && let Ok(n) = u8::from_str_radix(&s[i + 1..i + 4], 8) {
                out.push(n as char);
                i += 4;
                continue;
            }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

pub fn scan(name: &str) -> std::io::Result<Disk> {
    let sys = Path::new("/sys/block").join(name);
    let sector_size = read_u64(sys.join("queue/logical_block_size"))? as u32;
    let size = read_u64(sys.join("size"))? * 512;
    let dev = Device::open(&Path::new("/dev").join(name))?;
    let gpt = read_gpt(&dev, sector_size as u64)?;
    let mounts = mounts()?;

    let mut partitions = Vec::new();
    for entry in fs::read_dir(&sys)? {
        let entry = entry?;
        let pname = entry.file_name().to_string_lossy().into_owned();
        let psys = entry.path();
        if !psys.join("partition").exists() {
            continue;
        }
        let number = read_u64(psys.join("partition"))? as u32;
        let offset = read_u64(psys.join("start"))? * 512;
        let length = read_u64(psys.join("size"))? * 512;
        let type_guid = gpt.iter().find(|(n, _)| *n == number).map(|(_, g)| g.clone()).unwrap_or_default();
        let (fs, fs_uuid) = probe_fs(&dev, offset, length)?;
        let pdev = PathBuf::from(format!("/dev/{pname}"));
        let mine = mounts_of(&mounts, &read_trim(psys.join("dev")).unwrap_or_default(), &pdev);
        let read_only = mine.iter().all(|m| m.super_options.split(',').any(|o| o == "ro"));
        let busy = mine.is_empty() && claimed(&pdev);
        let mut targets: Vec<&str> = mine.iter().map(|m| m.target.as_str()).collect();
        targets.sort_by_key(|t| (*t != "/", t.len()));
        partitions.push(Partition {
            name: pname,
            number,
            offset,
            length,
            type_guid,
            fs,
            fs_uuid,
            mount_path: targets.first().map(|t| t.to_string()).unwrap_or_default(),
            mounts: targets.iter().map(|t| t.to_string()).collect(),
            read_only,
            busy,
        });
    }
    partitions.sort_by_key(|p| p.offset);
    let lvm_volumes = discover_lvm(&mut partitions, &mounts);
    Ok(Disk {
        name: name.to_string(),
        image: name.to_string(),
        size,
        sector_size,
        layout: "GPT".into(),
        partitions,
        lvm_volumes,
    })
}

/// An integer printed by LVM with `--units b --nosuffix` (normally `1048576.00`).
fn lvm_integer(s: &str) -> Option<u64> {
    let (whole, fraction) = s.trim().split_once('.').unwrap_or((s.trim(), ""));
    if !fraction.bytes().all(|b| b == b'0') {
        return None;
    }
    whole.parse().ok()
}

/// `(metadata area count, first physical extent byte)` from one `pvs` output line.
fn parse_pvs(line: &str) -> Option<(u64, u64)> {
    let mut f = line.split_whitespace();
    let count = lvm_integer(f.next()?)?;
    let pe_start = lvm_integer(f.next()?)?;
    f.next().is_none().then_some((count, pe_start))
}

/// A single linear device-mapper table: `(length, backing major:minor, backing offset)`, all
/// offsets and lengths in 512-byte sectors.
fn parse_dm_table(text: &str) -> Option<(u64, String, u64)> {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let [line] = lines.as_slice() else { return None };
    let mut f = line.split_whitespace();
    let logical_start: u64 = f.next()?.parse().ok()?;
    let length: u64 = f.next()?.parse().ok()?;
    if logical_start != 0 || f.next()? != "linear" {
        return None;
    }
    let backing = f.next()?.to_string();
    let physical_start: u64 = f.next()?.parse().ok()?;
    f.next().is_none().then_some((length, backing, physical_start))
}

fn command_output(program: &str, args: &[&str], device: Option<&Path>) -> std::io::Result<String> {
    let mut cmd = Command::new(program);
    cmd.args(args).env("LC_ALL", "C");
    if let Some(device) = device {
        cmd.arg(device);
    }
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(std::io::Error::other(format!("{program} failed: {}", String::from_utf8_lossy(&out.stderr).trim())));
    }
    String::from_utf8(out.stdout).map_err(std::io::Error::other)
}

/// Finds the one LVM layout the image code can reproduce safely: one PV metadata area, one
/// device-mapper holder, and one linear segment beginning at PE 0. Anything more complicated
/// remains an ordinary unsupported LVM partition.
fn lvm_volume(p: &Partition, mounts: &[Mount]) -> std::io::Result<Option<LvmVolume>> {
    let pdev = p.device();
    let pvs = command_output(
        "pvs",
        &["--noheadings", "--units", "b", "--nosuffix", "-o", "pv_mda_count,pe_start"],
        Some(&pdev),
    )?;
    let rows: Vec<&str> = pvs.lines().filter(|l| !l.trim().is_empty()).collect();
    let [row] = rows.as_slice() else { return Ok(None) };
    let Some((1, pe_start)) = parse_pvs(row) else { return Ok(None) };

    let holders = Path::new("/sys/class/block").join(&p.name).join("holders");
    let holders: Vec<String> = fs::read_dir(holders)?
        .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect();
    let [dm] = holders.as_slice() else { return Ok(None) };
    if !dm.starts_with("dm-") {
        return Ok(None);
    }
    let dmsys = Path::new("/sys/class/block").join(dm);
    let dm_name = read_trim(dmsys.join("dm/name"))?;
    let table = command_output("dmsetup", &["table", &dm_name], None)?;
    let Some((sectors, backing, physical_sector)) = parse_dm_table(&table) else { return Ok(None) };
    if backing != read_trim(Path::new("/sys/class/block").join(&p.name).join("dev"))? {
        return Ok(None);
    }
    let length = sectors.checked_mul(512).ok_or_else(|| std::io::Error::other("LVM length overflow"))?;
    let physical = physical_sector.checked_mul(512).ok_or_else(|| std::io::Error::other("LVM offset overflow"))?;
    if physical != pe_start || read_u64(dmsys.join("size"))?.checked_mul(512) != Some(length) {
        return Ok(None);
    }
    let offset = p.offset.checked_add(physical).ok_or_else(|| std::io::Error::other("LVM offset overflow"))?;
    if offset.checked_add(length).is_none_or(|end| end > p.offset + p.length) {
        return Ok(None);
    }

    let dmdev = PathBuf::from("/dev").join(dm);
    let dev = Device::open(&dmdev)?;
    let (fs_kind, fs_uuid) = probe_fs(&dev, 0, length)?;
    if !matches!(fs_kind, Fs::Ext(_)) {
        return Ok(None);
    }
    let mine = mounts_of(mounts, &read_trim(dmsys.join("dev")).unwrap_or_default(), &dmdev);
    let read_only = mine.iter().all(|m| m.super_options.split(',').any(|o| o == "ro"));
    let mut targets: Vec<&str> = mine.iter().map(|m| m.target.as_str()).collect();
    targets.sort_by_key(|t| (*t != "/", t.len()));
    let volume = Partition {
        name: dm.clone(),
        number: p.number,
        offset,
        length,
        type_guid: p.type_guid.clone(),
        fs: fs_kind,
        fs_uuid,
        mount_path: targets.first().map(|t| t.to_string()).unwrap_or_default(),
        mounts: targets.iter().map(|t| t.to_string()).collect(),
        read_only,
        busy: false,
    };
    Ok(Some(LvmVolume { parent: p.name.clone(), volume }))
}

fn discover_lvm(partitions: &mut [Partition], mounts: &[Mount]) -> Vec<LvmVolume> {
    let mut out = Vec::new();
    for p in partitions.iter().filter(|p| p.fs == Fs::Lvm) {
        match lvm_volume(p, mounts) {
            Ok(Some(v)) => out.push(v),
            Ok(None) => {}
            Err(e) => eprintln!("/dev/{}: LVM discovery: {e}", p.name),
        }
    }
    // Make selection and restore metadata recognise which physical PV holds the system volume.
    for p in partitions.iter_mut() {
        let mine: Vec<&Partition> = out.iter().filter(|v| v.parent == p.name).map(|v| &v.volume).collect();
        if let [v] = mine.as_slice() {
            p.mount_path = v.mount_path.clone();
            p.mounts = v.mounts.clone();
            p.read_only = v.read_only;
        }
    }
    out
}

fn guid(b: &[u8]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}",
        u32::from_le_bytes(b[0..4].try_into().unwrap()),
        u16::from_le_bytes(b[4..6].try_into().unwrap()),
        u16::from_le_bytes(b[6..8].try_into().unwrap()),
        b[8],
        b[9],
        b[10..16].iter().map(|x| format!("{x:02X}")).collect::<String>()
    )
}

/// (partition number, type GUID) from the primary GPT table.
fn read_gpt(dev: &Device, sector: u64) -> std::io::Result<Vec<(u32, String)>> {
    let mut hdr = vec![0u8; sector as usize];
    dev.read_exact_at(&mut hdr, sector)?;
    if &hdr[0..8] != b"EFI PART" {
        return Err(std::io::Error::other("the disk has no GPT table (MBR not supported yet)"));
    }
    let entries_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
    let count = u32::from_le_bytes(hdr[80..84].try_into().unwrap()) as usize;
    let esize = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as usize;
    let mut table = vec![0u8; count * esize];
    dev.read_exact_at(&mut table, entries_lba * sector)?;
    Ok((0..count)
        .filter_map(|i| {
            let e = &table[i * esize..(i + 1) * esize];
            (e[..16] != [0u8; 16]).then(|| (i as u32 + 1, guid(&e[..16])))
        })
        .collect())
}

fn uuid_str(b: &[u8]) -> String {
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// Filesystem type and UUID from known superblocks.
fn probe_fs(dev: &Device, offset: u64, length: u64) -> std::io::Result<(Fs, String)> {
    if length < 128 * 1024 {
        return Ok((Fs::None, String::new()));
    }
    let mut head = vec![0u8; 128 * 1024];
    dev.read_exact_at(&mut head, offset)?;
    if &head[0x10040..0x10048] == b"_BHRfS_M" {
        return Ok((Fs::Btrfs, uuid_str(&head[0x10020..0x10030])));
    }
    if u16::from_le_bytes(head[1080..1082].try_into().unwrap()) == 0xEF53 {
        let sb = &head[1024..2048];
        let feat = |o: usize| u32::from_le_bytes(sb[o..o + 4].try_into().unwrap());
        // ext4: extent, 64bit, flex_bg, huge_file, … ; ext3: journal.
        let version = if feat(0x60) & !0x16 != 0 || feat(0x64) & !0x7 != 0 {
            4
        } else if feat(0x5C) & 0x4 != 0 {
            3
        } else {
            2
        };
        return Ok((Fs::Ext(version), uuid_str(&sb[0x68..0x78])));
    }
    if &head[0..4] == b"XFSB" {
        return Ok((Fs::Xfs, uuid_str(&head[32..48])));
    }
    if head[510] == 0x55 && head[511] == 0xAA {
        let serial = |o: usize| {
            let s = u32::from_le_bytes(head[o..o + 4].try_into().unwrap());
            format!("{:04X}-{:04X}", s >> 16, s & 0xffff)
        };
        if &head[0x52..0x57] == b"FAT32" {
            return Ok((Fs::Vfat, serial(0x43)));
        }
        if &head[0x36..0x39] == b"FAT" {
            return Ok((Fs::Vfat, serial(0x27)));
        }
    }
    if &head[512..520] == b"LABELONE" && &head[536..544] == b"LVM2 001" {
        return Ok((Fs::Lvm, String::new()));
    }
    if &head[0..6] == b"LUKS\xba\xbe" {
        return Ok((Fs::Luks, String::new()));
    }
    if &head[4086..4096] == b"SWAPSPACE2" {
        return Ok((Fs::Swap, uuid_str(&head[1036..1052])));
    }
    Ok((Fs::None, String::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOUNTINFO: &str = "\
22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/root rw
23 22 0:31 /@home /home rw,relatime shared:2 - btrfs /dev/nvme0n1p3 rw,subvolid=257,subvol=/@home
24 22 259:1 / /boot ro,relatime shared:3 - vfat /dev/disk/by-uuid/ABCD-1234 ro,fmask=0022
25 22 0:22 / /proc rw,nosuid shared:4 - proc proc rw
26 22 259:4 / /mnt/my\\040disk rw shared:5 - ext4 /dev/nvme0n1p4 rw
";

    #[test]
    fn mounts_matched_by_device_number() {
        let m = parse_mountinfo(MOUNTINFO);
        assert_eq!(m.len(), 5);
        assert_eq!((m[0].dev.as_str(), m[0].source.as_str(), m[0].target.as_str()), ("259:2", "/dev/root", "/"));
        assert_eq!(m[4].target, "/mnt/my disk");
        // ext4 mounted from /dev/root: found by its number.
        let root = mounts_of(&m, "259:2", Path::new("/dev/zznvme0n1p2"));
        assert_eq!(root.iter().map(|m| m.target.as_str()).collect::<Vec<_>>(), ["/"]);
        assert!(!root[0].super_options.split(',').any(|o| o == "ro"));
        // vfat mounted through a symlink, read-only.
        let boot = mounts_of(&m, "259:1", Path::new("/dev/zznvme0n1p1"));
        assert_eq!(boot.len(), 1);
        assert!(boot[0].super_options.split(',').any(|o| o == "ro"));
        // btrfs: anonymous number, found by its source.
        let home = mounts_of(&m, "259:3", Path::new("/dev/nvme0n1p3"));
        assert_eq!(home.iter().map(|m| m.target.as_str()).collect::<Vec<_>>(), ["/home"]);
        // Nothing else claims an unrelated device.
        assert!(mounts_of(&m, "8:1", Path::new("/dev/zzsda1")).is_empty());
    }

    #[test]
    fn in_use() {
        let mut p = Partition {
            name: "x".into(),
            number: 1,
            offset: 0,
            length: 0,
            type_guid: String::new(),
            fs: Fs::None,
            fs_uuid: String::new(),
            mount_path: String::new(),
            mounts: vec![],
            read_only: true,
            busy: false,
        };
        assert!(!p.in_use());
        p.busy = true;
        assert!(p.in_use());
        (p.busy, p.mount_path, p.read_only) = (true, "/boot".into(), true);
        assert!(!p.in_use());
        p.read_only = false;
        assert!(p.in_use());
    }

    #[test]
    fn parses_the_supported_lvm_reports() {
        assert_eq!(parse_pvs("  1  1048576.00\n"), Some((1, 1 << 20)));
        assert_eq!(parse_pvs("  2  1048576.00\n"), Some((2, 1 << 20)));
        assert_eq!(parse_pvs("  1  1048576.50\n"), None);
        assert_eq!(parse_dm_table("0 209715200 linear 8:3 2048\n"), Some((209715200, "8:3".into(), 2048)));
        assert_eq!(parse_dm_table("1 209715200 linear 8:3 2048\n"), None);
        assert_eq!(parse_dm_table("0 100 linear 8:3 2048\n100 100 linear 8:3 4096\n"), None);
        assert_eq!(parse_dm_table("0 100 crypt aes 00 0 8:3 2048\n"), None);
    }
}
