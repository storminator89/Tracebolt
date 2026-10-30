use crate::protocol::Sample;
use anyhow::Result;
use std::{
    mem::{size_of, zeroed},
    ptr::null_mut,
    thread,
    time::Duration,
};
use windows_sys::Win32::System::Threading::GetSystemTimes;
use windows_sys::Win32::{
    Foundation::FILETIME,
    Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW},
    System::SystemInformation::{
        GetSystemDirectoryW, GetTickCount64, GlobalMemoryStatusEx, MEMORYSTATUSEX,
    },
};

fn times() -> Option<(u64, u64)> {
    unsafe {
        let (mut idle, mut kernel, mut user): (FILETIME, FILETIME, FILETIME) =
            (zeroed(), zeroed(), zeroed());
        if GetSystemTimes(&mut idle, &mut kernel, &mut user) == 0 {
            return None;
        }
        let ticks = |t: FILETIME| ((t.dwHighDateTime as u64) << 32) | t.dwLowDateTime as u64;
        Some((ticks(idle), ticks(kernel).checked_add(ticks(user))?))
    }
}

pub fn collect() -> Result<Sample> {
    let before = times();
    thread::sleep(Duration::from_millis(500));
    let cpu = before.zip(times()).and_then(|((i0, t0), (i1, t1))| {
        let total = t1.checked_sub(t0)?;
        let idle = i1.checked_sub(i0)?;
        (total > 0 && idle <= total).then(|| 100.0 * (total - idle) as f64 / total as f64)
    });
    unsafe {
        let mut memory: MEMORYSTATUSEX = zeroed();
        memory.dwLength = size_of::<MEMORYSTATUSEX>() as u32;
        let memory = if GlobalMemoryStatusEx(&mut memory) != 0
            && memory.ullTotalPhys > 0
            && memory.ullAvailPhys <= memory.ullTotalPhys
        {
            Some(
                100.0 * (memory.ullTotalPhys - memory.ullAvailPhys) as f64
                    / memory.ullTotalPhys as f64,
            )
        } else {
            None
        };
        let mut path = [0u16; 32768];
        let length = GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) as usize;
        let mut disk = None;
        if length >= 3 && length < path.len() && path[1] == b':' as u16 && path[2] == b'\\' as u16 {
            path[3] = 0;
            if GetDriveTypeW(path.as_ptr()) == 3 {
                let (mut available, mut total) = (0, 0);
                if GetDiskFreeSpaceExW(path.as_ptr(), &mut available, &mut total, null_mut()) != 0
                    && total > 0
                    && available <= total
                {
                    disk = Some(100.0 * (total - available) as f64 / total as f64);
                }
            }
        }
        Ok(Sample {
            cpu,
            memory,
            disk,
            uptime: format!("{} seconds", GetTickCount64() / 1000),
        })
    }
}
