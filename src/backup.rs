use anyhow::{Context, Result};
use chrono::Local;
use log::{debug, info, warn};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Создает бекап файла перед его модификацией
pub async fn backup_file<P: AsRef<Path>>(file_path: P) -> Result<PathBuf> {
    let path = file_path.as_ref();

    if !path.exists() {
        debug!("Файл {:?} не существует, бекап не требуется", path);
        return Ok(path.to_path_buf());
    }

    let timestamp = Local::now().format("%Y%m%d%H%M%S").to_string();
    let backup_dir = PathBuf::from("server-settings/backups");
    fs::create_dir_all(&backup_dir).with_context(|| {
        format!(
            "Не удалось создать директорию для бекапов: {:?}",
            backup_dir
        )
    })?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Не удалось получить имя файла из пути"))?
        .to_string_lossy();

    let backup_path = backup_dir.join(format!("{}_{}", file_name, timestamp));

    fs::copy(path, &backup_path)
        .with_context(|| format!("Не удалось создать бекап файла {:?}", path))?;

    info!("Создан бекап {:?} -> {:?}", path, backup_path);

    Ok(backup_path)
}

/// Восстанавливает файл из бекапа
pub async fn restore_from_backup<P: AsRef<Path>>(backup_path: P, original_path: P) -> Result<()> {
    let src = backup_path.as_ref();
    let dst = original_path.as_ref();

    if !src.exists() {
        return Err(anyhow::anyhow!("Бекап {:?} не существует", src));
    }

    // Создаем директорию для оригинального файла, если она не существует
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Не удалось создать директорию: {:?}", parent))?;
    }

    fs::copy(src, dst).with_context(|| {
        format!(
            "Не удалось восстановить файл из бекапа {:?} в {:?}",
            src, dst
        )
    })?;

    info!("Файл восстановлен из бекапа {:?} -> {:?}", src, dst);

    Ok(())
}

/// Удаляет старые бекапы (оставляет последние N бекапов для каждого файла)
pub async fn clean_old_backups(keep_last: usize) -> Result<()> {
    let backup_dir = PathBuf::from("server-settings/backups");

    if !backup_dir.exists() {
        debug!("Директория бекапов не существует, нечего очищать");
        return Ok(());
    }

    // Получаем список всех файлов в директории бекапов
    let mut entries = fs::read_dir(&backup_dir)
        .with_context(|| format!("Не удалось прочитать директорию бекапов: {:?}", backup_dir))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_file())
        .map(|entry| entry.path())
        .collect::<Vec<_>>();

    // Группируем файлы по основному имени (без временной метки)
    let mut files_by_name = std::collections::HashMap::new();

    for path in entries {
        if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
            if let Some(base_name) = file_name.split('_').next() {
                files_by_name
                    .entry(base_name.to_string())
                    .or_insert_with(Vec::new)
                    .push(path.clone());
            }
        }
    }

    // Для каждой группы файлов оставляем только последние keep_last
    for (name, mut files) in files_by_name {
        if files.len() <= keep_last {
            continue;
        }

        // Сортируем файлы по времени создания (от новых к старым)
        files.sort_by(|a, b| {
            let a_meta = fs::metadata(a);
            let b_meta = fs::metadata(b);

            match (a_meta, b_meta) {
                (Ok(a_meta), Ok(b_meta)) => match (a_meta.created(), b_meta.created()) {
                    (Ok(a_time), Ok(b_time)) => b_time.cmp(&a_time),
                    _ => std::cmp::Ordering::Equal,
                },
                _ => std::cmp::Ordering::Equal,
            }
        });

        // Удаляем старые файлы, оставляя keep_last
        for file in files.iter().skip(keep_last) {
            if let Err(e) = fs::remove_file(file) {
                warn!("Не удалось удалить старый бекап {:?}: {}", file, e);
            } else {
                debug!("Удален старый бекап: {:?}", file);
            }
        }
    }

    info!("Очистка старых бекапов завершена");

    Ok(())
}
