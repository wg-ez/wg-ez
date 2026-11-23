#![forbid(unsafe_code)]

//! Setup gating for the web layer.

use super::{SETUP_DONE, SETUP_ENDPOINT, SetupError};

/// Setup API entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestedSetupStep {
    Step2,
    Step3,
}

/// Gate a setup route:
/// - setup finished -> [`SetupError::State`] ("already finished",
///   handlers: 400/403);
/// - `current == 1` allows only [`RequestedSetupStep::Step2`];
/// - `current == 3` allows only [`RequestedSetupStep::Step3`];
/// - any other current step, or a step mismatch -> [`SetupError::State`]
///   ("invalid setup step").
pub fn check_setup_step(current: i64, requested: RequestedSetupStep) -> Result<(), SetupError> {
    if current == SETUP_DONE {
        return Err(SetupError::State("setup already finished".to_string()));
    }
    let allowed = match current {
        1 => requested == RequestedSetupStep::Step2,
        SETUP_ENDPOINT => requested == RequestedSetupStep::Step3,
        _ => {
            return Err(SetupError::State("invalid setup step".to_string()));
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(SetupError::State("invalid setup step".to_string()))
    }
}

/// Page middleware: while unfinished, any non-setup page redirects
/// to `/setup/<step>`; once finished, `/setup/*` redirects to `/login`.
/// Setup API calls (`/api/setup/*`) always pass through.
///
/// Exception: at [`SETUP_ENDPOINT`] the admin already exists, so `/login`
/// stays reachable. Without this, a browser that refused the step-2 session
/// cookie (e.g. `Secure` over plain HTTP) could never authenticate again.
pub fn setup_page_redirect(setup_step: i64, path: &str) -> Option<String> {
    let is_setup_page = path == "/setup" || path.starts_with("/setup/");
    let is_setup_api = path.starts_with("/api/setup/");
    let is_relogin = setup_step == SETUP_ENDPOINT && path == "/login";
    if setup_step != SETUP_DONE {
        if is_setup_page || is_setup_api || is_relogin {
            None
        } else {
            Some(format!("/setup/{setup_step}"))
        }
    } else if is_setup_page {
        Some("/login".to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_gating_matches_v15() {
        use RequestedSetupStep as R;
        assert!(check_setup_step(1, R::Step2).is_ok());
        assert!(check_setup_step(1, R::Step3).is_err());
        assert!(check_setup_step(3, R::Step3).is_ok());
        assert!(check_setup_step(3, R::Step2).is_err());
        assert!(check_setup_step(0, R::Step2).is_err());
        assert!(check_setup_step(2, R::Step2).is_err());
    }

    #[test]
    fn page_redirects() {
        assert_eq!(setup_page_redirect(1, "/"), Some("/setup/1".to_string()));
        assert_eq!(setup_page_redirect(3, "/setup/3"), None);
        assert_eq!(
            setup_page_redirect(3, "/api/client"),
            Some("/setup/3".to_string())
        );
        assert_eq!(setup_page_redirect(3, "/api/setup/3"), None);
        // At the endpoint step the admin exists: re-login must stay possible.
        assert_eq!(setup_page_redirect(3, "/login"), None);
        assert_eq!(
            setup_page_redirect(1, "/login"),
            Some("/setup/1".to_string())
        );
        assert_eq!(
            setup_page_redirect(0, "/setup/1"),
            Some("/login".to_string())
        );
        assert_eq!(setup_page_redirect(0, "/"), None);
        assert_eq!(setup_page_redirect(0, "/login"), None);
    }
}
