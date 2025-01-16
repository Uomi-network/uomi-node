use std::env;
use std::path::Path;
use fs_extra::file::copy_with_progress;
use fs_extra::file::CopyOptions;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    println!("📦 Building in: {}", out_dir);
    
    let mut options = CopyOptions::new();
    options.overwrite = true;

    let ipfs_files = [
        "ipfs_macOS",
        "ipfs_linux_amd64",
        "ipfs_linux_arm64"
    ];

    for file in ipfs_files.iter() {
        let src_path = Path::new("src").join(file);
        let dest_path = Path::new(&out_dir).join(file);

        if src_path.exists() {
            copy_with_progress(&src_path, &dest_path, &options, |_| {})
                .unwrap_or_else(|e| panic!("Failed to copy {}: {}", file, e));
            
            println!("✅ Copied {} to build directory", file);
            println!("cargo:rerun-if-changed=src/{}", file);
        } else {
            println!("⚠️  Warning: {} not found in src directory, maybe you need to download it!", file);
        }
    }
}