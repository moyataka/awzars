//! TUI application for role selection

use super::tui_error::TuiResultExt;
use crate::error::{AwzarsError, Result};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseButton,
        MouseEventKind,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Terminal,
};
use std::io;
use std::time::Duration;

/// Role selector TUI
pub struct RoleSelector {
    roles: Vec<(String, String)>,
    state: ListState,
    search_query: String,
    filtered_indices: Vec<usize>,
    layout_list_area: Rect,
}

impl RoleSelector {
    /// Create a new role selector
    pub fn new(roles: Vec<(String, String)>) -> Self {
        let filtered_indices: Vec<usize> = (0..roles.len()).collect();
        let mut state = ListState::default();
        if !filtered_indices.is_empty() {
            state.select(Some(0));
        }

        Self {
            roles,
            state,
            search_query: String::new(),
            filtered_indices,
            layout_list_area: Rect::default(),
        }
    }

    /// Open TUI and let user select a role
    pub fn select(self) -> Result<Option<String>> {
        // If only one role, auto-select
        if self.roles.len() == 1 {
            return Ok(Some(self.roles[0].0.clone()));
        }

        // Setup terminal
        enable_raw_mode().tui()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture).tui()?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend).tui()?;

        // Run app
        let result = self.run(&mut terminal);

        // Restore terminal
        execute!(terminal.backend_mut(), DisableMouseCapture).tui()?;
        disable_raw_mode().tui()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen).tui()?;

        result
    }

    fn run(
        mut self,
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    ) -> Result<Option<String>> {
        loop {
            terminal.draw(|f| self.render(f)).tui()?;

            if event::poll(Duration::from_millis(100)).tui()? {
                match event::read().tui()? {
                    Event::Key(key) => match (key.modifiers, key.code) {
                        (KeyModifiers::CONTROL, KeyCode::Char('c')) | (_, KeyCode::Esc) => {
                            return Ok(None);
                        }
                        (_, KeyCode::Up) => {
                            self.move_selection(-1);
                        }
                        (_, KeyCode::Down) => {
                            self.move_selection(1);
                        }
                        (_, KeyCode::Enter) => {
                            return self.get_selected_role();
                        }
                        (_, KeyCode::Backspace) => {
                            self.search_query.pop();
                            self.update_filtered();
                        }
                        (_, KeyCode::Char(c)) => {
                            self.search_query.push(c);
                            self.update_filtered();
                        }
                        _ => {}
                    },
                    Event::Mouse(mouse) => match mouse.kind {
                        MouseEventKind::ScrollUp => {
                            self.move_selection(-1);
                        }
                        MouseEventKind::ScrollDown => {
                            self.move_selection(1);
                        }
                        MouseEventKind::Down(MouseButton::Left) => {
                            if let Some(role) = self.handle_list_click(mouse.column, mouse.row)? {
                                return Ok(Some(role));
                            }
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
        }
    }

    fn render(&mut self, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints([
                Constraint::Length(3), // Search
                Constraint::Min(10),   // List
                Constraint::Length(2), // Help
            ])
            .split(f.area());

        self.layout_list_area = chunks[1];

        // Search box
        let search = Paragraph::new(self.search_query.as_str()).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Search (type to filter)"),
        );
        f.render_widget(search, chunks[0]);

        // Role list
        let items: Vec<ListItem> = self
            .filtered_indices
            .iter()
            .map(|&idx| {
                let (role, principal) = &self.roles[idx];
                let role_name = role.split('/').next_back().unwrap_or(role);
                ListItem::new(Line::from(vec![
                    Span::styled(role_name, Style::default().fg(Color::Cyan)),
                    Span::raw(" - "),
                    Span::styled(
                        principal.split('/').next_back().unwrap_or(principal),
                        Style::default().fg(Color::DarkGray),
                    ),
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(format!(
                "Select Role ({}/{})",
                self.filtered_indices.len(),
                self.roles.len()
            )))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, chunks[1], &mut self.state.clone());

        // Help text
        let help = Paragraph::new("↑/↓: Navigate | Enter: Select | Esc: Cancel | Type to search")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(help, chunks[2]);
    }

    fn move_selection(&mut self, delta: i32) {
        let len = self.filtered_indices.len();
        if len == 0 {
            return;
        }

        let current = self.state.selected().unwrap_or(0);
        let new_pos = if delta > 0 {
            (current + delta as usize).min(len - 1)
        } else {
            current.saturating_sub((-delta) as usize)
        };
        self.state.select(Some(new_pos));
    }

    fn update_filtered(&mut self) {
        let query = self.search_query.to_lowercase();
        self.filtered_indices = self
            .roles
            .iter()
            .enumerate()
            .filter(|(_, (role, _))| role.to_lowercase().contains(&query))
            .map(|(idx, _)| idx)
            .collect();

        if self.filtered_indices.is_empty() {
            self.state.select(None);
        } else {
            self.state.select(Some(0));
        }
    }

    fn get_selected_role(&self) -> Result<Option<String>> {
        let selected = self
            .state
            .selected()
            .ok_or_else(|| AwzarsError::Tui("No role selected".to_string()))?;

        if selected >= self.filtered_indices.len() {
            return Ok(None);
        }

        let role_idx = self.filtered_indices[selected];
        Ok(Some(self.roles[role_idx].0.clone()))
    }

    fn handle_list_click(&mut self, col: u16, row: u16) -> Result<Option<String>> {
        let list_area = self.layout_list_area;
        let first_item_row = list_area.y + 1;
        let last_item_row = list_area.y + list_area.height.saturating_sub(1);

        if row < first_item_row
            || row >= last_item_row
            || col < list_area.x
            || col >= list_area.x + list_area.width
        {
            return Ok(None);
        }

        let visible_offset = (row - first_item_row) as usize;
        let offset = self.state.offset();
        let idx = offset + visible_offset;

        if idx < self.filtered_indices.len() {
            self.state.select(Some(idx));
            return self.get_selected_role();
        }

        Ok(None)
    }
}
