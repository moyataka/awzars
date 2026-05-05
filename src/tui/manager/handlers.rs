//! Per-mode key handlers and the form save/refresh helpers.
//!
//! Split out of `mod.rs` so the event loop / mouse routing / type
//! definitions stay in one place and the long body of mode-specific
//! state transitions lives here. Methods exposed to mod.rs are marked
//! `pub(super)`; everything else is module-private.

use super::{ConfigManager, Mode, StatusLevel, Tab};
use crate::error::{AwzarsError, Result};
use crate::tui::aws_config::{
    build_awzars_credential_process, detect_awzars_binary, load_aws_integration, save_aws_config,
};
use crate::tui::form::{AwsProfileForm, ProfileForm, AWS_IDX_SOURCE_PROFILE};
use crate::tui::form_ops::{key_to_field_op, move_index, FieldOp};
use crossterm::event::{KeyCode, KeyModifiers};

impl ConfigManager {
    // ---- Browse mode ----

    pub(super) fn handle_browse(&mut self, mods: KeyModifiers, code: KeyCode) -> Result<()> {
        match (mods, code) {
            (KeyModifiers::CONTROL, KeyCode::Char('c'))
            | (_, KeyCode::Char('q'))
            | (_, KeyCode::Esc) => {
                return Err(AwzarsError::UserQuit);
            }
            (_, KeyCode::Char('?')) => {
                self.show_help = true;
            }
            // Tab switching
            (_, KeyCode::Tab) => {
                self.active_tab = match self.active_tab {
                    Tab::Awzars => Tab::AwsConfig,
                    Tab::AwsConfig => Tab::Awzars,
                };
                self.status = None;
            }
            (KeyModifiers::SHIFT, KeyCode::BackTab) => {
                self.active_tab = match self.active_tab {
                    Tab::Awzars => Tab::AwsConfig,
                    Tab::AwsConfig => Tab::Awzars,
                };
                self.status = None;
            }
            (_, KeyCode::Char('1')) => {
                self.active_tab = Tab::Awzars;
                self.status = None;
            }
            (_, KeyCode::Char('2')) => {
                self.active_tab = Tab::AwsConfig;
                self.status = None;
            }
            _ => match self.active_tab {
                Tab::Awzars => self.handle_browse_awzars(mods, code),
                Tab::AwsConfig => self.handle_browse_aws(mods, code),
            },
        }
        Ok(())
    }

    fn handle_browse_awzars(&mut self, mods: KeyModifiers, code: KeyCode) {
        match (mods, code) {
            (_, KeyCode::Up) | (_, KeyCode::Char('k')) => self.move_awzars_selection(-1),
            (_, KeyCode::Down) | (_, KeyCode::Char('j')) => self.move_awzars_selection(1),
            (_, KeyCode::Char('a')) => self.start_add_awzars(),
            (_, KeyCode::Char('c')) => self.start_clone_awzars(),
            (_, KeyCode::Char('e')) | (_, KeyCode::Enter) => self.start_edit_awzars(),
            (_, KeyCode::Char('d')) => self.start_delete_awzars(),
            _ => {}
        }
    }

    fn handle_browse_aws(&mut self, mods: KeyModifiers, code: KeyCode) {
        match (mods, code) {
            (_, KeyCode::Up) | (_, KeyCode::Char('k')) => self.move_aws_selection(-1),
            (_, KeyCode::Down) | (_, KeyCode::Char('j')) => self.move_aws_selection(1),
            (_, KeyCode::Char('a')) => self.start_add_aws(),
            (_, KeyCode::Char('e')) | (_, KeyCode::Enter) => self.start_edit_aws(),
            (_, KeyCode::Char('d')) => self.start_delete_aws(),
            (_, KeyCode::Char('l')) => self.start_link_picker(),
            _ => {}
        }
    }

    // ---- Selection movement ----

    pub(super) fn move_awzars_selection(&mut self, delta: i32) {
        let len = self.profile_names.len();
        if len == 0 {
            return;
        }
        let current = self.awzars_list_state.selected().unwrap_or(0);
        let new = move_index(current, delta, len);
        self.awzars_list_state.select(Some(new));
        self.awzars_selected = new;
    }

    pub(super) fn move_aws_selection(&mut self, delta: i32) {
        let len = self.aws_profiles.len();
        if len == 0 {
            return;
        }
        let current = self.aws_list_state.selected().unwrap_or(0);
        let new = move_index(current, delta, len);
        self.aws_list_state.select(Some(new));
        self.aws_selected = new;
    }

    // ---- Awzars CRUD ----

    fn start_add_awzars(&mut self) {
        self.mode = Mode::AddAwzars;
        self.form = Some(ProfileForm::new_empty());
        self.status = Some((
            StatusLevel::Info,
            "Add awzars profile — Ctrl+S save, Esc cancel".into(),
        ));
    }

    fn start_clone_awzars(&mut self) {
        let name = match self.profile_names.get(self.awzars_selected) {
            Some(n) => n.clone(),
            None => {
                self.status = Some((StatusLevel::Warning, "No profile selected to clone".into()));
                return;
            }
        };
        let profile = match self.config.get_profile(&name) {
            Ok(p) => p.clone(),
            Err(_) => {
                self.status = Some((
                    StatusLevel::Error,
                    format!("Cannot read profile '{}'", name),
                ));
                return;
            }
        };
        self.mode = Mode::AddAwzars;
        self.form = Some(ProfileForm::clone_from(&name, &profile));
        self.status = Some((
            StatusLevel::Info,
            format!("Clone from '{}' — Ctrl+S save, Esc cancel", name),
        ));
    }

    fn start_edit_awzars(&mut self) {
        if let Some(name) = self.profile_names.get(self.awzars_selected) {
            if let Ok(profile) = self.config.get_profile(name) {
                self.mode = Mode::EditAwzars;
                self.form = Some(ProfileForm::from_profile(name, profile));
                self.status = Some((
                    StatusLevel::Info,
                    "Edit awzars profile — Ctrl+S save, Esc cancel".into(),
                ));
            }
        }
    }

    fn start_delete_awzars(&mut self) {
        if let Some(name) = self.profile_names.get(self.awzars_selected).cloned() {
            self.mode = Mode::DeleteConfirm {
                target: name,
                is_awzars: true,
            };
            self.status = None;
        }
    }

    fn save_awzars_form(&mut self) {
        let form = match self.form.as_ref() {
            Some(f) => f,
            None => return,
        };

        let was_add = form.original_name.is_none();

        match form.to_profile() {
            Ok((name, mut profile)) => {
                // Snapshot the prior profile (under the original name on edit,
                // or the new name on add) for two purposes:
                //   * preserve password-lock state across saves (the form
                //     does not surface those fields)
                //   * detect identity-defining changes that invalidate any
                //     cached STS session for this profile
                let prev_profile = form
                    .original_name
                    .as_deref()
                    .and_then(|n| self.config.profiles.get(n))
                    .or_else(|| self.config.profiles.get(&name))
                    .cloned();

                if let Some(ref prev) = prev_profile {
                    profile.lock_verifier = prev.lock_verifier.clone();
                    profile.lock_ttl_hours = prev.lock_ttl_hours;
                    profile.lock_ai_markers = prev.lock_ai_markers.clone();
                }

                let identity_changed = prev_profile
                    .as_ref()
                    .map(|prev| crate::config::cleanup::credential_identity_changed(prev, &profile))
                    .unwrap_or(false);

                let renamed_from = form
                    .original_name
                    .as_deref()
                    .filter(|orig| *orig != name.as_str())
                    .map(|s| s.to_string());

                if let Some(ref original) = renamed_from {
                    self.config.remove_profile(original);
                }
                self.config.set_profile(&name, profile);
                if let Err(e) = self.config.save() {
                    self.status = Some((StatusLevel::Error, format!("Save failed: {}", e)));
                    return;
                }

                // Wipe stale cached/keyring STS credentials so the next
                // `credential-process` call re-authenticates against the
                // current profile rather than returning a session minted for
                // the previous role / tenant / app id.
                let mut warnings: Vec<String> = Vec::new();
                if let Some(ref orig) = renamed_from {
                    warnings.extend(
                        crate::config::cleanup::invalidate_cached_credentials(orig)
                            .into_iter()
                            .map(|w| format!("{}: {}", orig, w)),
                    );
                }
                if identity_changed {
                    warnings.extend(
                        crate::config::cleanup::invalidate_cached_credentials(&name)
                            .into_iter()
                            .map(|w| format!("{}: {}", name, w)),
                    );
                }

                self.refresh_awzars_list(&name);
                self.form = None;
                self.status = if warnings.is_empty() {
                    Some((StatusLevel::Success, format!("Profile '{}' saved", name)))
                } else {
                    Some((
                        StatusLevel::Warning,
                        format!(
                            "Profile '{}' saved (credential cache cleanup warnings: {})",
                            name,
                            warnings.join("; ")
                        ),
                    ))
                };
                // Brand-new profile? Offer a password lock now so the user
                // doesn't have to remember to run `awzars set-password` later.
                self.mode = if was_add {
                    Mode::SetPasswordPrompt { name: name.clone() }
                } else {
                    Mode::Browse
                };
            }
            Err(errors) => {
                self.status = Some((StatusLevel::Error, errors.join("; ")));
            }
        }
    }

    pub(super) fn handle_set_password_prompt(&mut self, code: KeyCode, name: String) -> Result<()> {
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                self.pending_action = Some(super::PendingAction::SetPassword { name });
                self.mode = Mode::Browse;
            }
            _ => {
                self.mode = Mode::Browse;
                // Keep the existing post-save status — don't clobber it.
            }
        }
        Ok(())
    }

    fn refresh_awzars_list(&mut self, focus_name: &str) {
        self.profile_names = self.config.profiles.keys().cloned().collect();
        self.profile_names.sort();
        self.awzars_selected = self
            .profile_names
            .iter()
            .position(|n| n == focus_name)
            .unwrap_or(0);
        self.awzars_list_state.select(Some(self.awzars_selected));
    }

    // ---- AWS CRUD ----

    fn start_add_aws(&mut self) {
        self.mode = Mode::ProfileTypePicker;
        self.profile_type_picker_selected = 0;
        self.profile_type_picker_state.select(Some(0));
        self.status = Some((
            StatusLevel::Info,
            "Choose profile type — Enter select, Esc cancel".into(),
        ));
    }

    fn start_edit_aws(&mut self) {
        if let Some(entry) = self.aws_profiles.get(self.aws_selected).cloned() {
            let profiles = self.profile_names.clone();
            let aws_names = self
                .aws_profiles
                .iter()
                .filter(|p| !p.is_assume_role())
                .map(|p| (p.name.clone(), p.uses_awzars))
                .collect();
            self.mode = Mode::EditAws;
            self.aws_form = Some(AwsProfileForm::from_entry(&entry, profiles, aws_names));
            self.status = Some((
                StatusLevel::Info,
                "Edit AWS profile — Ctrl+S save, Esc cancel".into(),
            ));
        }
    }

    fn start_delete_aws(&mut self) {
        if let Some(entry) = self.aws_profiles.get(self.aws_selected).cloned() {
            if !entry.uses_awzars {
                self.status = Some((
                    StatusLevel::Warning,
                    "Cannot delete non-awzars AWS profiles".into(),
                ));
                return;
            }
            self.mode = Mode::DeleteConfirm {
                target: entry.name,
                is_awzars: false,
            };
            self.status = None;
        }
    }

    fn save_aws_form(&mut self) {
        let form = match self.aws_form.as_ref() {
            Some(f) => f,
            None => return,
        };

        match form.to_entry() {
            Ok(entry) => {
                let focus_name = entry.name.clone();
                // Check if rename
                if let Some(ref original) = form.original_name {
                    if original != &entry.name {
                        self.aws_profiles.retain(|p| p.name != *original);
                    }
                }
                // Update or insert
                if let Some(existing) = self.aws_profiles.iter_mut().find(|p| p.name == entry.name)
                {
                    *existing = entry;
                } else {
                    self.aws_profiles.push(entry);
                }

                if let Err(e) = save_aws_config(&self.aws_profiles, self.config.aws_config_path.as_deref()) {
                    self.status = Some((StatusLevel::Error, format!("Save failed: {}", e)));
                    return;
                }

                self.refresh_aws_list(&focus_name);
                self.aws_form = None;
                self.mode = Mode::Browse;
                self.status = Some((
                    StatusLevel::Success,
                    format!("AWS profile '{}' saved", focus_name),
                ));
            }
            Err(errors) => {
                self.status = Some((StatusLevel::Error, errors.join("; ")));
            }
        }
    }

    fn refresh_aws_list(&mut self, focus_name: &str) {
        self.aws_data = load_aws_integration(self.config.aws_config_path.as_deref());
        self.aws_profiles = self.aws_data.all_profiles.clone();
        self.aws_selected = self
            .aws_profiles
            .iter()
            .position(|p| p.name == focus_name)
            .unwrap_or(0);
        self.aws_list_state.select(Some(self.aws_selected));
    }

    // ---- Link picker ----

    fn start_link_picker(&mut self) {
        if !self.profile_names.is_empty() {
            self.mode = Mode::LinkPicker;
            self.link_picker_selected = 0;
            self.link_picker_state.select(Some(0));
            self.status = Some((
                StatusLevel::Info,
                "Select awzars profile to link — Esc cancel".into(),
            ));
        } else {
            self.status = Some((StatusLevel::Warning, "No awzars profiles to link".into()));
        }
    }

    pub(super) fn handle_link_picker(&mut self, code: KeyCode) -> Result<()> {
        let total = self.profile_names.len() + 1; // profiles + "Unlink" option
        match code {
            KeyCode::Up | KeyCode::Char('k') if self.link_picker_selected > 0 => {
                self.link_picker_selected -= 1;
                self.link_picker_state
                    .select(Some(self.link_picker_selected));
            }
            KeyCode::Down | KeyCode::Char('j') if self.link_picker_selected < total - 1 => {
                self.link_picker_selected += 1;
                self.link_picker_state
                    .select(Some(self.link_picker_selected));
            }
            KeyCode::Esc => {
                self.mode = Mode::Browse;
                self.status = None;
            }
            KeyCode::Enter => {
                self.apply_link();
            }
            _ => {}
        }
        Ok(())
    }

    fn apply_link(&mut self) {
        let aws_entry = match self.aws_profiles.get(self.aws_selected) {
            Some(e) => e.clone(),
            None => return,
        };

        let profile_count = self.profile_names.len();

        if self.link_picker_selected >= profile_count {
            // "Unlink" selected
            if let Some(entry) = self.aws_profiles.get_mut(self.aws_selected) {
                entry.credential_process = None;
                entry.uses_awzars = false;
                entry.awzars_profile = None;
            }
            self.status = Some((
                StatusLevel::Success,
                format!("Unlinked '{}'", aws_entry.name),
            ));
        } else {
            // Link to selected awzars profile
            let awzars_name = match self.profile_names.get(self.link_picker_selected) {
                Some(n) => n.clone(),
                None => return,
            };
            let binary = detect_awzars_binary(aws_entry.credential_process.as_deref());
            let cp = if binary == "awzars" {
                build_awzars_credential_process(&awzars_name)
            } else {
                format!("{} credential-process --profile {}", binary, awzars_name)
            };

            if let Some(entry) = self.aws_profiles.get_mut(self.aws_selected) {
                entry.credential_process = Some(cp);
                entry.uses_awzars = true;
                entry.awzars_profile = Some(awzars_name.clone());
            }
            self.status = Some((
                StatusLevel::Success,
                format!(
                    "Linked '{}' → awzars profile '{}'",
                    aws_entry.name, awzars_name
                ),
            ));
        }

        if let Err(e) = save_aws_config(&self.aws_profiles, self.config.aws_config_path.as_deref()) {
            self.status = Some((StatusLevel::Error, format!("Save failed: {}", e)));
        } else {
            self.refresh_aws_list(&aws_entry.name);
        }

        self.mode = Mode::Browse;
    }

    // ---- Profile type picker ----

    pub(super) fn handle_profile_type_picker(&mut self, code: KeyCode) -> Result<()> {
        match code {
            KeyCode::Up | KeyCode::Char('k') if self.profile_type_picker_selected > 0 => {
                self.profile_type_picker_selected -= 1;
                self.profile_type_picker_state
                    .select(Some(self.profile_type_picker_selected));
            }
            KeyCode::Down | KeyCode::Char('j') if self.profile_type_picker_selected < 1 => {
                self.profile_type_picker_selected += 1;
                self.profile_type_picker_state
                    .select(Some(self.profile_type_picker_selected));
            }
            KeyCode::Esc => {
                self.mode = Mode::Browse;
                self.status = None;
            }
            KeyCode::Enter => {
                let is_assume_role = self.profile_type_picker_selected == 1;
                let profiles = self.profile_names.clone();
                let aws_names = self
                    .aws_profiles
                    .iter()
                    .filter(|p| !p.is_assume_role())
                    .map(|p| (p.name.clone(), p.uses_awzars))
                    .collect();
                self.mode = Mode::AddAws;
                let mut form = AwsProfileForm::new_empty(profiles, aws_names);
                form.is_assume_role = is_assume_role;
                self.aws_form = Some(form);
                let kind = if is_assume_role {
                    "assume-role"
                } else {
                    "base"
                };
                self.status = Some((
                    StatusLevel::Info,
                    format!("Add {} AWS profile — Ctrl+S save, Esc cancel", kind),
                ));
            }
            _ => {}
        }
        Ok(())
    }

    // ---- Delete confirm ----

    pub(super) fn handle_delete_confirm(&mut self, code: KeyCode) -> Result<()> {
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                let (target, is_awzars) = match &self.mode {
                    Mode::DeleteConfirm { target, is_awzars } => (target.clone(), *is_awzars),
                    _ => unreachable!(),
                };

                if is_awzars {
                    match crate::config::cleanup::delete_awzars_profile(&target) {
                        Err(e) => {
                            self.status =
                                Some((StatusLevel::Error, format!("Delete failed: {}", e)));
                        }
                        Ok(report) => {
                            // Reload config from disk so in-memory state matches.
                            if let Ok(cfg) = crate::config::Config::load() {
                                self.config = cfg;
                            }
                            self.profile_names = self.config.profiles.keys().cloned().collect();
                            self.profile_names.sort();
                            if self.awzars_selected >= self.profile_names.len()
                                && !self.profile_names.is_empty()
                            {
                                self.awzars_selected = self.profile_names.len() - 1;
                            }
                            self.awzars_list_state.select(Some(self.awzars_selected));

                            let orphans = report.orphaned_aws_profiles;
                            let warnings = report.warnings;

                            if !warnings.is_empty() {
                                let mut msg = format!(
                                    "Profile '{}' deleted with warnings: {}",
                                    target,
                                    warnings.join("; ")
                                );
                                if !orphans.is_empty() {
                                    msg.push_str(&format!(
                                        ". ~/.aws/config still references this profile in: {} (edit to remove)",
                                        orphans.join(", ")
                                    ));
                                }
                                self.status = Some((StatusLevel::Warning, msg));
                            } else if !orphans.is_empty() {
                                self.status = Some((
                                    StatusLevel::Warning,
                                    format!(
                                        "Profile '{}' deleted. ~/.aws/config still references this profile in: {} (edit ~/.aws/config to remove)",
                                        target,
                                        orphans.join(", ")
                                    ),
                                ));
                            } else {
                                self.status = Some((
                                    StatusLevel::Success,
                                    format!("Profile '{}' deleted", target),
                                ));
                            }
                        }
                    }
                } else {
                    self.aws_profiles.retain(|p| p.name != target);
                    if let Err(e) = save_aws_config(&self.aws_profiles, self.config.aws_config_path.as_deref()) {
                        self.status = Some((StatusLevel::Error, format!("Save failed: {}", e)));
                    } else {
                        self.refresh_aws_list_after_delete();
                        self.status = Some((
                            StatusLevel::Success,
                            format!("AWS profile '{}' deleted", target),
                        ));
                    }
                }
                self.mode = Mode::Browse;
            }
            _ => {
                self.mode = Mode::Browse;
                self.status = None;
            }
        }
        Ok(())
    }

    fn refresh_aws_list_after_delete(&mut self) {
        self.aws_data = load_aws_integration(self.config.aws_config_path.as_deref());
        self.aws_profiles = self.aws_data.all_profiles.clone();
        if self.aws_selected >= self.aws_profiles.len() && !self.aws_profiles.is_empty() {
            self.aws_selected = self.aws_profiles.len() - 1;
        }
        self.aws_list_state.select(Some(self.aws_selected));
    }

    pub(super) fn handle_unsaved_confirm(&mut self, code: KeyCode, is_awzars: bool) -> Result<()> {
        match code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                // Save and close
                if is_awzars {
                    self.save_awzars_form();
                } else {
                    self.save_aws_form();
                }
                // If save failed, mode stays in the form; otherwise back to browse
                if !matches!(
                    self.mode,
                    Mode::EditAwzars | Mode::AddAwzars | Mode::EditAws | Mode::AddAws
                ) {
                    // save succeeded, mode is already Browse
                }
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                // Discard and close
                if is_awzars {
                    self.form = None;
                } else {
                    self.aws_form = None;
                }
                self.mode = Mode::Browse;
                self.status = None;
            }
            KeyCode::Esc => {
                // Cancel — go back to editing
                if is_awzars {
                    self.mode = if self
                        .form
                        .as_ref()
                        .is_some_and(|f| f.original_name.is_some())
                    {
                        Mode::EditAwzars
                    } else {
                        Mode::AddAwzars
                    };
                } else {
                    self.mode = if self
                        .aws_form
                        .as_ref()
                        .is_some_and(|f| f.original_name.is_some())
                    {
                        Mode::EditAws
                    } else {
                        Mode::AddAws
                    };
                }
                self.status = None;
            }
            _ => {}
        }
        Ok(())
    }

    // ---- Awzars form handling ----

    pub(super) fn handle_awzars_form(&mut self, mods: KeyModifiers, code: KeyCode) -> Result<()> {
        let form = match self.form.as_mut() {
            Some(f) => f,
            None => {
                self.mode = Mode::Browse;
                return Ok(());
            }
        };

        if form.is_editing() {
            // Check if we should intercept for region autocomplete
            if form.has_region_suggestions() {
                match (mods, code) {
                    (_, KeyCode::Enter) => {
                        form.accept_region_suggestion();
                        if let Some(field) = form.editing_field_mut() {
                            field.finish_edit();
                        }
                        return Ok(());
                    }
                    (_, KeyCode::Tab) | (_, KeyCode::Up) | (_, KeyCode::Char('k')) => {
                        form.move_region_suggestion(-1);
                        return Ok(());
                    }
                    (_, KeyCode::Down) | (_, KeyCode::Char('j')) => {
                        form.move_region_suggestion(1);
                        return Ok(());
                    }
                    _ => {}
                }
            }

            let cancel_info = if let (_, KeyCode::Esc) = (mods, code) {
                let idx = form
                    .fields
                    .iter()
                    .position(|f| f.editing)
                    .unwrap_or(form.focused);
                let original = form.original_values[idx].clone();
                Some(original)
            } else {
                None
            };

            if let Some(field) = form.editing_field_mut() {
                match (mods, code) {
                    (_, KeyCode::Enter) => field.finish_edit(),
                    (_, KeyCode::Esc) => {
                        if let Some(original) = &cancel_info {
                            field.cancel_edit(original);
                        }
                    }
                    other => {
                        if let Some(op) = key_to_field_op(other.0, other.1) {
                            field.apply(op);
                        }
                    }
                }
            }
            form.update_region_suggestions();
            return Ok(());
        }

        match (mods, code) {
            (_, KeyCode::Esc) => {
                if form.is_dirty() {
                    self.mode = Mode::UnsavedConfirm { is_awzars: true };
                    self.status = Some((
                        StatusLevel::Warning,
                        "Unsaved changes! [y] save, [n] discard, [Esc] cancel".into(),
                    ));
                } else {
                    self.form = None;
                    self.mode = Mode::Browse;
                    self.status = None;
                }
            }
            (KeyModifiers::CONTROL, KeyCode::Char('s')) => self.save_awzars_form(),
            (KeyModifiers::CONTROL, KeyCode::Char('d')) => {
                if let Some(field) = form.focused_field_mut() {
                    field.value.clear();
                    field.cursor_pos = 0;
                }
            }
            (_, KeyCode::Up)
            | (_, KeyCode::Char('k'))
            | (KeyModifiers::SHIFT, KeyCode::BackTab) => {
                form.move_focus(-1);
            }
            (_, KeyCode::Down) | (_, KeyCode::Char('j')) | (_, KeyCode::Tab) => {
                form.move_focus(1);
            }
            (_, KeyCode::Enter) => {
                if form.toggle_focused.is_some() {
                    form.toggle_current();
                } else if let Some(field) = form.focused_field_mut() {
                    field.start_edit();
                }
            }
            (_, KeyCode::Char(' ')) if form.toggle_focused.is_some() => {
                form.toggle_current();
            }
            _ => {}
        }
        Ok(())
    }

    // ---- AWS form handling ----

    pub(super) fn handle_aws_form(&mut self, mods: KeyModifiers, code: KeyCode) -> Result<()> {
        let form = match self.aws_form.as_mut() {
            Some(f) => f,
            None => {
                self.mode = Mode::Browse;
                return Ok(());
            }
        };

        if form.is_editing() {
            // Check if we should intercept for credential_process autocomplete
            if form.has_suggestions() {
                match (mods, code) {
                    (_, KeyCode::Enter) => {
                        form.accept_suggestion();
                        if let Some(field) = form.editing_field_mut() {
                            field.finish_edit();
                        }
                        return Ok(());
                    }
                    (_, KeyCode::Tab) | (_, KeyCode::Up) | (_, KeyCode::Char('k')) => {
                        form.move_suggestion(-1);
                        return Ok(());
                    }
                    (_, KeyCode::Down) | (_, KeyCode::Char('j')) => {
                        form.move_suggestion(1);
                        return Ok(());
                    }
                    _ => {}
                }
            }

            // Check if we should intercept for source_profile autocomplete
            if form.has_source_suggestions() {
                match (mods, code) {
                    (_, KeyCode::Enter) => {
                        form.accept_source_suggestion();
                        if let Some(field) = form.editing_field_mut() {
                            field.finish_edit();
                        }
                        return Ok(());
                    }
                    (_, KeyCode::Tab) | (_, KeyCode::Up) | (_, KeyCode::Char('k')) => {
                        form.move_source_suggestion(-1);
                        return Ok(());
                    }
                    (_, KeyCode::Down) | (_, KeyCode::Char('j')) => {
                        form.move_source_suggestion(1);
                        return Ok(());
                    }
                    _ => {}
                }
            }

            // Check if we should intercept for region autocomplete
            if form.has_region_suggestions() {
                match (mods, code) {
                    (_, KeyCode::Enter) => {
                        form.accept_region_suggestion();
                        if let Some(field) = form.editing_field_mut() {
                            field.finish_edit();
                        }
                        return Ok(());
                    }
                    (_, KeyCode::Tab) | (_, KeyCode::Up) | (_, KeyCode::Char('k')) => {
                        form.move_region_suggestion(-1);
                        return Ok(());
                    }
                    (_, KeyCode::Down) | (_, KeyCode::Char('j')) => {
                        form.move_region_suggestion(1);
                        return Ok(());
                    }
                    _ => {}
                }
            }

            let cancel_info = if let (_, KeyCode::Esc) = (mods, code) {
                let idx = form
                    .fields
                    .iter()
                    .position(|f| f.editing)
                    .unwrap_or(form.focused);
                let original = form.original_values[idx].clone();
                Some(original)
            } else {
                None
            };

            if let Some(field) = form.editing_field_mut() {
                match (mods, code) {
                    (_, KeyCode::Enter) => field.finish_edit(),
                    (_, KeyCode::Esc) => {
                        if let Some(original) = &cancel_info {
                            field.cancel_edit(original);
                        }
                    }
                    other => {
                        if let Some(op) = key_to_field_op(other.0, other.1) {
                            field.apply(op);
                        }
                    }
                }
            }

            // Update autocomplete suggestions after any field change
            form.update_suggestions();
            form.update_source_suggestions();
            form.update_region_suggestions();
            return Ok(());
        }

        // Form-level navigation (no field being edited)
        match (mods, code) {
            (_, KeyCode::Esc) => {
                if form.is_dirty() {
                    self.mode = Mode::UnsavedConfirm { is_awzars: false };
                    self.status = Some((
                        StatusLevel::Warning,
                        "Unsaved changes! [y] save, [n] discard, [Esc] cancel".into(),
                    ));
                } else {
                    self.aws_form = None;
                    self.mode = Mode::Browse;
                    self.status = None;
                }
            }
            (KeyModifiers::CONTROL, KeyCode::Char('s')) => self.save_aws_form(),
            (KeyModifiers::CONTROL, KeyCode::Char('d')) => {
                if let Some(field) = form.focused_field_mut() {
                    field.value.clear();
                    field.cursor_pos = 0;
                }
            }
            (_, KeyCode::Up)
            | (_, KeyCode::Char('k'))
            | (KeyModifiers::SHIFT, KeyCode::BackTab) => {
                form.move_focus(-1);
            }
            (_, KeyCode::Down) | (_, KeyCode::Char('j')) | (_, KeyCode::Tab) => {
                form.move_focus(1);
            }
            (_, KeyCode::Enter) => {
                // Clear source_profile field before editing so autocomplete shows all profiles
                let is_source = form.focused_is(AWS_IDX_SOURCE_PROFILE);
                if let Some(field) = form.focused_field_mut() {
                    field.start_edit();
                    if is_source {
                        field.apply(FieldOp::Clear);
                    }
                    form.update_suggestions();
                    form.update_source_suggestions();
                }
            }
            _ => {}
        }
        Ok(())
    }
}
