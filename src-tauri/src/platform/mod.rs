mod macos;

pub use macos::{
    SavedProxy, beep, cert_is_trusted, ensure_trusted, install_proxy, process_name,
    refresh_bypass_domains, restore_proxy,
};
