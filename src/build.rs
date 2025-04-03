use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    // Убедимся, что сборка выполняется в релизном режиме
    let profile = env::var("PROFILE").unwrap();
    if profile != "release" {
        return;
    }

    // Определяем путь к скомпилированному бинарнику
    let target_dir = PathBuf::from(env::var("OUT_DIR").unwrap())
        .ancestors()
        .nth(3) // Получаем корневой `target` (из `OUT_DIR`)
        .unwrap()
        .join("release");

    let old_bin = target_dir.join(env::var("CARGO_PKG_NAME").unwrap());
    let new_bin_name = "Init_server";
    let project_root = target_dir.parent().unwrap().to_path_buf();
    let output_dir = project_root.join("release");
    let new_bin_path = output_dir.join(new_bin_name);

    // Создаём папку `release`, если её нет
    fs::create_dir_all(&output_dir).unwrap();

    // Переименовываем и перемещаем бинарник
    if let Err(e) = fs::rename(&old_bin, &new_bin_path) {
        eprintln!("Ошибка при перемещении файла: {}", e);
    }
}
