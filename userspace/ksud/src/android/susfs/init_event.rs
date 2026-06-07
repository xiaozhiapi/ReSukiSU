use std::fs;

use anyhow::Result;
use inotify::{Inotify, WatchMask};
use log::{info, warn};

use crate::android::susfs::api;
use crate::android::susfs::config;
use crate::android::susfs::config::data::Data;

fn is_sdcard_mounted() -> bool {
    let file = match fs::read_to_string("/proc/mounts") {
        Ok(f) => f,
        Err(_) => return false,
    };

    for line in file.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() > 1 {
            let mount_point = parts[1];
            if mount_point == "/sdcard" || mount_point.contains("/storage/emulated") {
                return true;
            }
        }
    }
    false
}

pub fn on_boot_completed() -> Result<()> {
    let config = config::read_config();

    let _ = crate::android::utils::create_daemon(true);

    let mut inotify = Inotify::init()?;

    inotify
        .watches()
        .add("/proc/self/mounts", WatchMask::MODIFY)?;

    let mut buffer = [0; 1024];
    loop {
        let mut events = inotify.read_events_blocking(&mut buffer)?;
        if events.next().is_some() && is_sdcard_mounted() {
            break;
        }
    }

    if !apply_config(&config) {
        warn!("failed to set susfs config on boot-completed with wait");
    }

    Ok(())
}

pub fn on_services() {
    // let config = config::read_config();

    // apply_sus_paths(&config);
    // apply_sus_maps(&config);
}

fn apply_sus_paths(config: &Data) -> bool {
    let mut success = true;

    for sus_path in &config.sus_path.sus_path {
        if sus_path.trim().is_empty() {
            continue;
        }
        success |= apply_sus_path_entry(&api::SusPathType::Normal, "sus_path", sus_path);
    }
    for sus_path_loop in &config.sus_path.sus_path_loop {
        if sus_path_loop.trim().is_empty() {
            continue;
        }
        success |= apply_sus_path_entry(&api::SusPathType::Loop, "sus_path_loop", sus_path_loop);
    }

    success
}

fn apply_sus_path_entry(path_type: &api::SusPathType, label: &str, path: &str) -> bool {
    match api::add_sus_path(path_type, &path) {
        Ok(()) => true,
        Err(e) if is_already_applied_error(&e) => {
            info!("{label} '{path}' is already applied");
            true
        }
        Err(e) => {
            warn!("failed to add {label} '{path}': {e}");
            false
        }
    }
}

fn apply_sus_maps(config: &Data) -> bool {
    let mut success = true;

    for sus_map in &config.sus_map {
        if sus_map.trim().is_empty() {
            continue;
        }
        match api::add_sus_map(sus_map.as_str()) {
            Ok(()) => {}
            Err(e) if is_already_applied_error(&e) => {
                info!("sus_map '{sus_map}' is already applied");
            }
            Err(e) => {
                warn!("failed to add sus_map '{sus_map}': {e}");
                success = false;
            }
        }
    }

    success
}

pub fn on_post_fs_data() {
    let config = config::read_config();

    if let Err(e) = api::set_uname(&config.common.spoof_version, &config.common.spoof_release) {
        warn!("failed to set uname: {e}");
    }

    if let Err(e) = api::enable_avc_log_spoofing(config.common.avc_spoofing.into()) {
        warn!("failed to enable avc log spoofing: {e}");
    }

    if let Err(e) = api::enable_log(config.common.enable_susfs_log.into()) {
        warn!("failed to enable susfs log: {e}");
    }

    if let Err(e) =
        api::hide_sus_mnts_for_non_su_procs(config.common.hide_sus_mnts_for_non_su_procs.into())
    {
        warn!("failed to hide sus mnts for non su procs: {e}");
    }

    // apply_sus_paths(&config);

    apply_sus_kstat_additions(&config);
}

pub fn on_post_mount() {
    let config = config::read_config();

    // apply_sus_paths(&config);
    // apply_sus_maps(&config);

    apply_kstat_updates(&config);
}

fn apply_config(config: &Data) -> bool {
    let mut success = false;
    success |= apply_sus_paths(config);
    success |= apply_sus_maps(config);
    success |= apply_sus_kstat_additions(config);
    success |= apply_kstat_updates(config);

    success
}

fn apply_sus_kstat_additions(config: &Data) -> bool {
    let mut success = true;

    for sus_kstat in &config.kstat.sus_kstat {
        if sus_kstat.trim().is_empty() {
            continue;
        }
        match api::add_sus_kstat(sus_kstat.as_str()) {
            Ok(()) => {}
            Err(e) if is_already_applied_error(&e) => {
                info!("sus_kstat '{sus_kstat}' is already applied");
            }
            Err(e) => {
                warn!("failed to add sus_kstat '{sus_kstat}': {e}");
                success = false;
            }
        }
    }
    for statically in &config.kstat.statically {
        if statically.path.trim().is_empty() {
            continue;
        }
        match api::add_sus_kstat_statically(
            &statically.path,
            &statically.ino,
            &statically.dev,
            &statically.nlink,
            &statically.size,
            &statically.atime,
            &statically.atime_nsec,
            &statically.mtime,
            &statically.mtime_nsec,
            &statically.ctime,
            &statically.ctime_nsec,
            &statically.blocks,
            &statically.blksize,
        ) {
            Ok(()) => {}
            Err(e) if is_already_applied_error(&e) => {
                info!(
                    "sus_kstat_statically '{}' is already applied",
                    statically.path
                );
            }
            Err(e) => {
                warn!(
                    "failed to add sus_kstat_statically '{}': {}",
                    statically.path, e
                );
                success = false;
            }
        }
    }

    success
}

fn apply_kstat_updates(config: &Data) -> bool {
    let mut success = true;

    for update_kstat in &config.kstat.update_kstat {
        if update_kstat.trim().is_empty() {
            continue;
        }
        match api::update_sus_kstat(update_kstat.as_str()) {
            Ok(()) => {}
            Err(e) if is_already_applied_error(&e) => {
                info!("sus_kstat '{update_kstat}' is already updated");
            }
            Err(e) => {
                warn!("failed to update sus_kstat '{update_kstat}': {e}");
                success = false;
            }
        }
    }
    for full_clone in &config.kstat.full_clone {
        if full_clone.trim().is_empty() {
            continue;
        }
        match api::update_sus_kstat_full_clone(full_clone.as_str()) {
            Ok(()) => {}
            Err(e) if is_already_applied_error(&e) => {
                info!("sus_kstat_full_clone '{full_clone}' is already updated");
            }
            Err(e) => {
                warn!("failed to update sus_kstat_full_clone '{full_clone}': {e}");
                success = false;
            }
        }
    }

    success
}

fn is_already_applied_error(e: &anyhow::Error) -> bool {
    let message = e.to_string();
    message.contains("SuSFS error: -17")
        || message.contains("SuSFS error: 17")
        || message.contains("File exists")
        || message.contains("os error 17")
}
