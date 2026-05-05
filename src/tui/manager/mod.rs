//! TUI config manager for awzars profiles with tab-based UI

use super::aws_config::{load_aws_integration, AwsIntegrationData, AwsProfileEntry};
use super::form::{AwsProfileForm, ProfileForm};
use super::tui_error::TuiResultExt;
use crate::config::Config;
use crate::error::Result;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseButton,
        MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, layout::Rect, widgets::ListState, Terminal};
use std::io;

// ---- Enums ----

#[derive(Debug, Clone, PartialEq)]
enum StatusLevel {
    Info,
    Success,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq)]
enum Tab {
    Awzars,
    AwsConfig,
}

#[derive(Debug, Clone, PartialEq)]
enum Mode {
    Browse,
    EditAwzars,
    AddAwzars,
    EditAws,
    AddAws,
    DeleteConfirm {
        target: String,
        is_awzars: bool,
    },
    LinkPicker,
    ProfileTypePicker,
    UnsavedConfirm {
        is_awzars: bool,
    },
    /// y/N modal asked after a brand-new awzars profile is saved.
    SetPasswordPrompt {
        name: String,
    },
}

/// Action that the event loop runs *between* draw frames by suspending the
/// terminal. Used for any flow that needs to drive `dialoguer` (which expects
/// to own stdin/stdout in cooked mode), since the TUI normally holds the
/// terminal in raw mode + alternate screen.
#[derive(Debug, Clone)]
pub(super) enum PendingAction {
    /// Suspend, run `set_password::run(name, false)`, restore, reload config.
    SetPassword { name: String },
}

// ---- Main struct ----

pub struct ConfigManager {
    config: Config,
    aws_data: AwsIntegrationData,
    aws_profiles: Vec<AwsProfileEntry>,

    active_tab: Tab,
    mode: Mode,

    // Awzars tab state
    profile_names: Vec<String>,
    awzars_selected: usize,
    awzars_list_state: ListState,
    form: Option<ProfileForm>,

    // AWS tab state
    aws_selected: usize,
    aws_list_state: ListState,
    aws_form: Option<AwsProfileForm>,

    // Link picker state
    link_picker_state: ListState,
    link_picker_selected: usize,

    // Profile type picker state
    profile_type_picker_state: ListState,
    profile_type_picker_selected: usize,

    // General
    status: Option<(StatusLevel, String)>,
    show_help: bool,

    // Action queued from a handler, drained by the event loop with the
    // terminal suspended so the action can take over stdin/stdout.
    pub(super) pending_action: Option<PendingAction>,

    // Layout areas from last render (for mouse hit-testing)
    layout_tab_bar: Rect,
    layout_left_panel: Rect,
    layout_right_panel: Rect,
}

impl ConfigManager {
    pub fn new(config: Config) -> Result<Self> {
        let aws_data = load_aws_integration(config.aws_config_path.as_deref());
        let aws_profiles = aws_data.all_profiles.clone();

        let mut profile_names: Vec<String> = config.profiles.keys().cloned().collect();
        profile_names.sort();

        let mut awzars_list_state = ListState::default();
        if !profile_names.is_empty() {
            awzars_list_state.select(Some(0));
        }

        let mut aws_list_state = ListState::default();
        if !aws_profiles.is_empty() {
            aws_list_state.select(Some(0));
        }

        let mut link_picker_state = ListState::default();
        link_picker_state.select(Some(0));

        let mut profile_type_picker_state = ListState::default();
        profile_type_picker_state.select(Some(0));

        Ok(Self {
            config,
            aws_data,
            aws_profiles,
            active_tab: Tab::Awzars,
            mode: Mode::Browse,
            profile_names,
            awzars_selected: 0,
            awzars_list_state,
            form: None,
            aws_selected: 0,
            aws_list_state,
            aws_form: None,
            link_picker_state,
            link_picker_selected: 0,
            profile_type_picker_state,
            profile_type_picker_selected: 0,
            status: None,
            show_help: false,
            pending_action: None,
            layout_tab_bar: Rect::default(),
            layout_left_panel: Rect::default(),
            layout_right_panel: Rect::default(),
        })
    }

    // ---- Run ----

    pub fn run(mut self) -> Result<()> {
        enable_raw_mode().tui()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture).tui()?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).tui()?;

        let result = self.event_loop(&mut terminal);

        execute!(terminal.backend_mut(), DisableMouseCapture).tui()?;
        disable_raw_mode().tui()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen).tui()?;

        result
    }

    fn event_loop(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
        loop {
            terminal.draw(|f| self.render(f)).tui()?;

            if let Some(action) = self.pending_action.take() {
                self.run_pending_action(terminal, action)?;
                continue;
            }

            if event::poll(std::time::Duration::from_millis(100)).tui()? {
                match event::read().tui()? {
                    Event::Key(key) => {
                        if self.show_help {
                            self.show_help = false;
                            continue;
                        }
                        self.handle_key(key.modifiers, key.code)?;
                    }
                    Event::Mouse(mouse) => {
                        if self.show_help {
                            self.show_help = false;
                            continue;
                        }
                        self.handle_mouse(mouse)?;
                    }
                    _ => {}
                }
            }
        }
    }

    /// Hand the terminal back to dialoguer (cooked mode, normal screen),
    /// run the action, then restore the TUI. Errors from the action are
    /// surfaced as a status message rather than propagated, so a failed
    /// password-set doesn't tear down the whole TUI.
    fn run_pending_action(
        &mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
        action: PendingAction,
    ) -> Result<()> {
        execute!(
            terminal.backend_mut(),
            DisableMouseCapture,
            LeaveAlternateScreen
        )
        .tui()?;
        disable_raw_mode().tui()?;
        terminal.show_cursor().tui()?;

        let result = match &action {
            PendingAction::SetPassword { name } => {
                crate::cli::commands::set_password::run(name, false)
            }
        };

        enable_raw_mode().tui()?;
        execute!(
            terminal.backend_mut(),
            EnterAlternateScreen,
            EnableMouseCapture
        )
        .tui()?;
        terminal.clear().tui()?;

        // Lock state lives in the on-disk config, so any successful run mutated
        // a file we no longer mirror in memory — reload to keep edits coherent.
        if let Ok(cfg) = Config::load() {
            self.config = cfg;
        }

        match (result, &action) {
            (Ok(()), PendingAction::SetPassword { name }) => {
                self.status = Some((
                    StatusLevel::Success,
                    format!("Password lock set on '{}'", name),
                ));
            }
            (Err(e), _) => {
                self.status = Some((StatusLevel::Error, format!("Set-password failed: {}", e)));
            }
        }
        Ok(())
    }

    // ---- Key routing ----

    fn handle_mouse(&mut self, mouse: MouseEvent) -> Result<()> {
        match mouse.kind {
            MouseEventKind::ScrollUp => self.handle_scroll(-1),
            MouseEventKind::ScrollDown => self.handle_scroll(1),
            MouseEventKind::Down(MouseButton::Left) => {
                self.handle_click(mouse.column, mouse.row)?
            }
            _ => {}
        }
        Ok(())
    }

    fn handle_scroll(&mut self, delta: i32) {
        if self.mode != Mode::Browse {
            return;
        }
        match self.active_tab {
            Tab::Awzars => self.move_awzars_selection(delta),
            Tab::AwsConfig => self.move_aws_selection(delta),
        }
    }

    fn handle_click(&mut self, col: u16, row: u16) -> Result<()> {
        if self.mode != Mode::Browse {
            return Ok(());
        }

        if rect_contains(self.layout_tab_bar, col, row) {
            let mid = self.layout_tab_bar.x + self.layout_tab_bar.width / 2;
            let new_tab = if col < mid {
                Tab::Awzars
            } else {
                Tab::AwsConfig
            };
            if self.active_tab != new_tab {
                self.active_tab = new_tab;
                self.status = None;
            }
        } else if rect_contains(self.layout_left_panel, col, row) {
            let list_area = self.layout_left_panel;
            let first_item_row = list_area.y + 1;
            let last_item_row = list_area.y + list_area.height.saturating_sub(1);
            if row >= first_item_row && row < last_item_row {
                let visible_offset = (row - first_item_row) as usize;
                match self.active_tab {
                    Tab::Awzars => {
                        let offset = self.awzars_list_state.offset();
                        let idx = offset + visible_offset;
                        if idx < self.profile_names.len() {
                            self.awzars_selected = idx;
                            self.awzars_list_state.select(Some(idx));
                        }
                    }
                    Tab::AwsConfig => {
                        let offset = self.aws_list_state.offset();
                        let idx = offset + visible_offset;
                        if idx < self.aws_profiles.len() {
                            self.aws_selected = idx;
                            self.aws_list_state.select(Some(idx));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_key(&mut self, mods: KeyModifiers, code: KeyCode) -> Result<()> {
        match &self.mode {
            Mode::Browse => self.handle_browse(mods, code),
            Mode::EditAwzars | Mode::AddAwzars => self.handle_awzars_form(mods, code),
            Mode::EditAws | Mode::AddAws => self.handle_aws_form(mods, code),
            Mode::DeleteConfirm { .. } => self.handle_delete_confirm(code),
            Mode::LinkPicker => self.handle_link_picker(code),
            Mode::ProfileTypePicker => self.handle_profile_type_picker(code),
            Mode::UnsavedConfirm { is_awzars } => {
                let is_awzars = *is_awzars;
                self.handle_unsaved_confirm(code, is_awzars)
            }
            Mode::SetPasswordPrompt { name } => {
                let name = name.clone();
                self.handle_set_password_prompt(code, name)
            }
        }
    }
}

mod handlers;
mod render;

fn rect_contains(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x
        && col < rect.x.saturating_add(rect.width)
        && row >= rect.y
        && row < rect.y.saturating_add(rect.height)
}
