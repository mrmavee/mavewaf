//! UI rendering.
//!
//! Loads HTML templates from the `templates/` directory and injects dynamic content.

mod pages;

pub use pages::{
    get_access_page, get_block_page, get_captcha_page, get_error_page, get_queue_page,
};
