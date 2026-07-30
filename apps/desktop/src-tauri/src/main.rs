// Release 构建下不弹终端窗口
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    miaovps_desktop_lib::run()
}
