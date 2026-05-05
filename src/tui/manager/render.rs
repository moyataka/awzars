//! Rendering for the TUI config manager.
//!
//! Split out of `mod.rs` so the state-machine logic (handlers, mode
//! transitions) is not mixed with widget construction. All methods are
//! `&self` or `&mut self` on `ConfigManager` — there is no behaviour
//! change from the original single-file layout.

use super::{ConfigManager, Mode, StatusLevel, Tab};
use crate::tui::form::{
    ProfileForm, AWS_IDX_CRED_PROC, AWS_IDX_REGION, AWS_IDX_SOURCE_PROFILE, IDX_REGION,
    TOGGLE_COUNT,
};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
};

impl ConfigManager {
    // ---- Rendering ----

    pub(super) fn render(&mut self, f: &mut ratatui::Frame) {
        let outer = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Tab bar
                Constraint::Min(10),   // Content
                Constraint::Length(1), // Status bar
            ])
            .split(f.area());

        self.layout_tab_bar = outer[0];
        let panels = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(outer[1]);
        self.layout_left_panel = panels[0];
        self.layout_right_panel = panels[1];

        self.render_tab_bar(f, outer[0]);

        match self.active_tab {
            Tab::Awzars => self.render_awzars_tab(f, outer[1]),
            Tab::AwsConfig => self.render_aws_tab(f, outer[1]),
        }

        self.render_status_bar(f, outer[2]);

        if self.show_help {
            self.render_help(f);
        }
        if self.mode == Mode::LinkPicker {
            self.render_link_picker(f);
        }
        if self.mode == Mode::ProfileTypePicker {
            self.render_profile_type_picker(f);
        }
        if let Mode::SetPasswordPrompt { name } = &self.mode {
            let name = name.clone();
            self.render_set_password_prompt(f, &name);
        }
    }

    // ---- Tab bar ----

    fn render_tab_bar(&self, f: &mut ratatui::Frame, area: Rect) {
        let tab1_style = if self.active_tab == Tab::Awzars {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let tab2_style = if self.active_tab == Tab::AwsConfig {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let tabs = Paragraph::new(Line::from(vec![
            Span::styled(" [1] awzars Profiles ", tab1_style),
            Span::raw(" "),
            Span::styled("[2] AWS Config ", tab2_style),
        ]));
        f.render_widget(tabs, area);
    }

    // ---- Awzars tab ----

    fn render_awzars_tab(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let main = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(area);

        self.render_awzars_list(f, main[0]);

        match &self.mode {
            Mode::EditAwzars | Mode::AddAwzars | Mode::UnsavedConfirm { is_awzars: true } => {
                self.render_awzars_form(f, main[1]);
            }
            _ => {
                self.render_awzars_details(f, main[1]);
            }
        }
    }

    fn render_awzars_list(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .profile_names
            .iter()
            .map(|name| {
                let aws_count = self.aws_data.for_awzars_profile(name).len();
                let suffix = if aws_count > 0 {
                    format!(" [{}]", aws_count)
                } else {
                    String::new()
                };
                let locked = self
                    .config
                    .profiles
                    .get(name)
                    .map(|p| p.lock_verifier.is_some())
                    .unwrap_or(false);
                let lock_span = if locked {
                    Span::styled(" [locked]", Style::default().fg(Color::Yellow))
                } else {
                    Span::raw("")
                };
                ListItem::new(Line::from(vec![
                    Span::styled(name, Style::default().fg(Color::White)),
                    Span::styled(suffix, Style::default().fg(Color::DarkGray)),
                    lock_span,
                ]))
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" awzars Profiles ({}) ", self.profile_names.len())),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, area, &mut self.awzars_list_state);
    }

    fn render_awzars_details(&self, f: &mut ratatui::Frame, area: Rect) {
        let name = self.profile_names.get(self.awzars_selected);
        let profile = name.and_then(|n| self.config.profiles.get(n));

        let lines = if let (Some(name), Some(profile)) = (name, profile) {
            vec![
                Line::from(vec![
                    Span::styled(" Profile: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        name,
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                field_line("Tenant ID", &profile.azure.tenant_id),
                field_line("App ID URI", &profile.azure.app_id_uri),
                field_line(
                    "Role ARN",
                    profile.role_arn.as_deref().unwrap_or("(not set)"),
                ),
                field_line(
                    "Duration",
                    &ProfileForm::format_duration(&profile.azure.session_duration.to_string()),
                ),
                field_line("Region", profile.region.as_deref().unwrap_or("(not set)")),
                field_line(
                    "Remember Me",
                    ProfileForm::format_toggle(profile.remember_me),
                ),
                field_line("Headless", ProfileForm::format_toggle(profile.headless)),
                field_line("No Sandbox", ProfileForm::format_toggle(profile.no_sandbox)),
                field_line(
                    "Insecure Chrome",
                    ProfileForm::format_toggle(profile.allow_insecure_remote_chrome),
                ),
                field_line(
                    "Locked",
                    &format_lock(profile.lock_verifier.is_some(), profile.lock_ttl_hours),
                ),
            ]
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  No profiles configured.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  Press 'a' to add your first profile.",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        };

        let detail = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Profile Details "),
        );
        f.render_widget(detail, area);
    }

    fn render_awzars_form(&self, f: &mut ratatui::Frame, area: Rect) {
        let form = match &self.form {
            Some(f) => f,
            None => return,
        };

        let title = if self.mode == Mode::AddAwzars {
            " Add awzars Profile "
        } else {
            " Edit awzars Profile "
        };

        let mut lines: Vec<Line> = vec![Line::from("")];

        for (i, field) in form.fields.iter().enumerate() {
            let focused = form.toggle_focused.is_none() && i == form.focused && !form.is_editing();
            let editing = field.editing;
            let label_style = if focused || editing {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let value_style = if editing {
                Style::default().fg(Color::Green)
            } else if focused {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let display_value = if field.editing {
                format!("{}│", field.value)
            } else {
                field.value.clone()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {:>16}: ", field.label), label_style),
                Span::styled(display_value, value_style),
            ]));

            // Show region suggestions below Region field
            if i == IDX_REGION && field.editing && !form.region_suggestions.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "    Regions (Tab to accept):",
                    Style::default().fg(Color::DarkGray),
                )));
                for (si, suggestion) in form.region_suggestions.iter().enumerate() {
                    let is_selected = si == form.region_suggestion_selected;
                    let style = if is_selected {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    let prefix = if is_selected { " ▶ " } else { "   " };
                    lines.push(Line::from(vec![
                        Span::styled(prefix.to_string(), style),
                        Span::styled(suggestion.to_string(), style),
                    ]));
                }
            }
        }

        // Render toggle fields
        for ti in 0..TOGGLE_COUNT {
            let is_focused = form.toggle_focused == Some(ti) && !form.is_editing();
            let style = if is_focused {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::styled(
                    format!("  {:>16}: ", ProfileForm::toggle_label(ti).unwrap_or("?")),
                    style,
                ),
                Span::styled(
                    ProfileForm::format_toggle(form.toggles[ti]).to_string(),
                    style,
                ),
            ]));
        }

        let widget =
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
        f.render_widget(widget, area);
    }

    // ---- AWS tab ----

    fn render_aws_tab(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let main = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
            .split(area);

        self.render_aws_list(f, main[0]);

        match &self.mode {
            Mode::EditAws | Mode::AddAws | Mode::UnsavedConfirm { is_awzars: false } => {
                self.render_aws_form(f, main[1]);
            }
            _ => {
                self.render_aws_details(f, main[1]);
            }
        }
    }

    fn render_aws_list(&mut self, f: &mut ratatui::Frame, area: Rect) {
        let items: Vec<ListItem> = self
            .aws_profiles
            .iter()
            .map(|entry| {
                if entry.is_assume_role() {
                    // Assume-role profile: ↗ name → source
                    let source = entry.source_profile.as_deref().unwrap_or("?");
                    ListItem::new(Line::from(vec![
                        Span::styled("↗ ", Style::default().fg(Color::Yellow)),
                        Span::styled(&entry.name, Style::default().fg(Color::Yellow)),
                        Span::styled(
                            format!(" → {}", source),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]))
                } else {
                    // Base profile: ◆ for awzars, space for others
                    let indicator = if entry.uses_awzars { "◆" } else { " " };
                    let name_style = if entry.uses_awzars {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{} ", indicator), Style::default().fg(Color::Cyan)),
                        Span::styled(&entry.name, name_style),
                    ]))
                }
            })
            .collect();

        let list = List::new(items).block({
            let title = match crate::tui::aws_config::resolve_aws_config_path(
                self.config.aws_config_path.as_deref(),
            ) {
                Some(path) => format!(
                    " AWS Profiles ({}) — {} ",
                    self.aws_profiles.len(),
                    path.display()
                ),
                None => format!(" AWS Profiles ({}) ", self.aws_profiles.len()),
            };
            Block::default().borders(Borders::ALL).title(title)
        })
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        f.render_stateful_widget(list, area, &mut self.aws_list_state);
    }

    fn render_aws_details(&self, f: &mut ratatui::Frame, area: Rect) {
        let entry = self.aws_profiles.get(self.aws_selected);

        let lines = if let Some(entry) = entry {
            let mut lines = vec![
                Line::from(vec![
                    Span::styled(" Profile: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        &entry.name,
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    if entry.uses_awzars {
                        Span::styled(
                            "  (awzars)",
                            Style::default()
                                .fg(Color::Green)
                                .add_modifier(Modifier::BOLD),
                        )
                    } else {
                        Span::raw("")
                    },
                ]),
                Line::from(""),
                field_line("Region", entry.region.as_deref().unwrap_or("(not set)")),
            ];

            // Extra keys (output, sso_*, etc.)
            let mut extra_keys: Vec<&String> = entry.extra.keys().collect();
            extra_keys.sort();
            for key in extra_keys {
                lines.push(field_line(key, &entry.extra[key]));
            }

            lines.push(Line::from(""));
            lines.push(match &entry.credential_process {
                Some(cp) => field_line("Credential Proc", cp),
                None => field_line("Credential Proc", "(none)"),
            });

            if entry.uses_awzars {
                if let Some(ref awzars_prof) = entry.awzars_profile {
                    lines.push(field_line("awzars Profile", awzars_prof));
                }
            }

            if entry.is_assume_role() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "  ── Assume Role ──",
                    Style::default().fg(Color::Yellow),
                )));
                lines.push(field_line(
                    "Source Profile",
                    entry.source_profile.as_deref().unwrap_or("(not set)"),
                ));
                lines.push(field_line(
                    "Role ARN",
                    entry.role_arn.as_deref().unwrap_or("(not set)"),
                ));
                lines.push(field_line(
                    "Session Name",
                    entry.role_session_name.as_deref().unwrap_or("(not set)"),
                ));
            }

            lines
        } else {
            vec![
                Line::from(""),
                Line::from(Span::styled(
                    "  No AWS profiles found.",
                    Style::default().fg(Color::DarkGray),
                )),
                Line::from(Span::styled(
                    "  Press 'a' to add one.",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        };

        let detail = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" AWS Profile Details "),
        );
        f.render_widget(detail, area);
    }

    fn render_aws_form(&self, f: &mut ratatui::Frame, area: Rect) {
        let form = match &self.aws_form {
            Some(f) => f,
            None => return,
        };

        let title = if self.mode == Mode::AddAws {
            " Add AWS Profile "
        } else {
            " Edit AWS Profile "
        };

        let mut lines: Vec<Line> = vec![Line::from("")];

        let visible = form.visible_field_indices();
        for (field_idx, &nav_idx) in visible.iter().enumerate() {
            let field = match form.fields.get(nav_idx) {
                Some(f) => f,
                None => continue,
            };
            let focused = field_idx == form.focused && !form.is_editing();
            let editing = field.editing;
            let label_style = if focused || editing {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let value_style = if editing {
                Style::default().fg(Color::Green)
            } else if focused {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let display_value = if field.editing {
                format!("{}│", field.value)
            } else {
                field.value.clone()
            };
            lines.push(Line::from(vec![
                Span::styled(format!("  {:>18}: ", field.label), label_style),
                Span::styled(display_value, value_style),
            ]));

            // Show region suggestions below Region field
            if nav_idx == AWS_IDX_REGION && field.editing && !form.region_suggestions.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "    Regions (Tab to accept):",
                    Style::default().fg(Color::DarkGray),
                )));
                for (si, suggestion) in form.region_suggestions.iter().enumerate() {
                    let is_selected = si == form.region_suggestion_selected;
                    let style = if is_selected {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    let prefix = if is_selected { " ▶ " } else { "   " };
                    lines.push(Line::from(vec![
                        Span::styled(prefix.to_string(), style),
                        Span::styled(suggestion.to_string(), style),
                    ]));
                }
            }

            // Show autocomplete suggestions below credential_process field
            if nav_idx == AWS_IDX_CRED_PROC && field.editing && !form.suggestions.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "    Suggestions (Tab to accept):",
                    Style::default().fg(Color::DarkGray),
                )));
                for (si, suggestion) in form.suggestions.iter().enumerate() {
                    let is_selected = si == form.suggestion_selected;
                    let style = if is_selected {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    let prefix = if is_selected { " ▶ " } else { "   " };
                    lines.push(Line::from(vec![
                        Span::styled(prefix.to_string(), style),
                        Span::styled(suggestion.clone(), style),
                        Span::styled(
                            format!("  → awzars credential-process --profile {}", suggestion),
                            if is_selected {
                                Style::default().fg(Color::Green)
                            } else {
                                Style::default().fg(Color::Rgb(80, 80, 80))
                            },
                        ),
                    ]));
                }
            }

            // Show autocomplete suggestions below source_profile field
            if nav_idx == AWS_IDX_SOURCE_PROFILE && field.editing && !form.source_suggestions.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::from(Span::styled(
                    "    AWS Profiles (Tab to accept):",
                    Style::default().fg(Color::DarkGray),
                )));
                for (si, (name, uses_awzars)) in form.source_suggestions.iter().enumerate() {
                    let is_selected = si == form.source_suggestion_selected;
                    let style = if is_selected {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    };
                    let prefix = if is_selected { " ▶ " } else { "   " };
                    let awzars_tag = if *uses_awzars {
                        Span::styled(
                            " [awzars]",
                            if is_selected {
                                Style::default().fg(Color::Green)
                            } else {
                                Style::default().fg(Color::Rgb(60, 120, 60))
                            },
                        )
                    } else {
                        Span::raw("")
                    };
                    lines.push(Line::from(vec![
                        Span::styled(prefix.to_string(), style),
                        Span::styled(name.clone(), style),
                        awzars_tag,
                    ]));
                }
            }
        }

        let widget =
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title(title));
        f.render_widget(widget, area);
    }

    // ---- Link picker overlay ----

    fn render_link_picker(&mut self, f: &mut ratatui::Frame) {
        let mut items: Vec<ListItem> = self
            .profile_names
            .iter()
            .map(|name| {
                ListItem::new(Line::from(Span::styled(
                    format!("  awzars: {}", name),
                    Style::default().fg(Color::White),
                )))
            })
            .collect();

        // "Unlink" option at the end
        items.push(ListItem::new(Line::from(Span::styled(
            "  (unlink)",
            Style::default().fg(Color::Red),
        ))));

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Link to awzars Profile "),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        let area = centered_rect(40, 60, f.area());
        f.render_stateful_widget(list, area, &mut self.link_picker_state);
    }

    // ---- Set-password prompt overlay ----

    fn render_set_password_prompt(&mut self, f: &mut ratatui::Frame, name: &str) {
        let area = centered_rect(60, 20, f.area());
        let lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                format!("  Set a password lock for profile '{}'?", name),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  A locked profile requires the password before any login,",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "  credential-process, or list-roles call.",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(""),
            Line::from(vec![
                Span::raw("  "),
                Span::styled(
                    "[y]",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::raw(" set password   "),
                Span::styled("[n]", Style::default().fg(Color::Yellow)),
                Span::raw(" skip"),
            ]),
        ];
        let widget = Paragraph::new(lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Password Lock "),
        );
        f.render_widget(Clear, area);
        f.render_widget(widget, area);
    }

    // ---- Profile type picker overlay ----

    fn render_profile_type_picker(&mut self, f: &mut ratatui::Frame) {
        let items = vec![
            ListItem::new(Line::from(Span::styled(
                "  Base profile (credential_process / standalone)",
                Style::default().fg(Color::White),
            ))),
            ListItem::new(Line::from(Span::styled(
                "  Assume-role profile (source_profile + role_arn)",
                Style::default().fg(Color::Yellow),
            ))),
        ];

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Choose Profile Type "),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        let area = centered_rect(60, 40, f.area());
        f.render_stateful_widget(list, area, &mut self.profile_type_picker_state);
    }

    // ---- Status bar ----

    fn render_status_bar(&self, f: &mut ratatui::Frame, area: Rect) {
        let left = match (&self.active_tab, &self.mode) {
            (_, Mode::DeleteConfirm { .. }) => "[y] confirm delete  [any other] cancel",
            (_, Mode::UnsavedConfirm { .. }) => "[y] save  [n] discard  [Esc] continue editing",
            (Tab::Awzars, Mode::Browse) => {
                "[a]dd  [c]lone  [e]dit  [d]elete  [Tab] switch  [?]help  [q]uit"
            }
            (Tab::AwsConfig, Mode::Browse) => {
                "[a]dd  [e]dit  [d]elete  [l]ink  [Tab] switch  [?]help  [q]uit"
            }
            (_, Mode::EditAwzars | Mode::AddAwzars) => {
                "[↑/↓] fields  [Enter] edit  [Space] toggle  [Ctrl+S] save  [Esc] cancel"
            }
            (_, Mode::EditAws | Mode::AddAws) => {
                "[↑/↓] fields  [Enter] edit  [Ctrl+S] save  [Esc] cancel"
            }
            (_, Mode::LinkPicker) => "[↑/↓] navigate  [Enter] select  [Esc] cancel",
            (_, Mode::ProfileTypePicker) => "[↑/↓] navigate  [Enter] select  [Esc] cancel",
            (_, Mode::SetPasswordPrompt { .. }) => "[y] set password  [n] skip",
        };

        let right = match &self.status {
            Some((StatusLevel::Success, msg)) => {
                Span::styled(msg, Style::default().fg(Color::Green))
            }
            Some((StatusLevel::Warning, msg)) => {
                Span::styled(msg, Style::default().fg(Color::Yellow))
            }
            Some((StatusLevel::Error, msg)) => Span::styled(msg, Style::default().fg(Color::Red)),
            Some((StatusLevel::Info, msg)) => Span::styled(msg, Style::default().fg(Color::Cyan)),
            None => Span::raw(""),
        };

        let bar = Paragraph::new(Line::from(vec![
            Span::styled(format!(" {}", left), Style::default().fg(Color::DarkGray)),
            Span::raw("  "),
            right,
        ]));
        f.render_widget(bar, area);
    }

    // ---- Help overlay ----

    fn render_help(&self, f: &mut ratatui::Frame) {
        let help_text = vec![
            Line::from(""),
            Line::from(Span::styled(
                "  awzars TUI — Help",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Navigation:",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from("    Tab / 1 / 2    Switch tabs"),
            Line::from("    ↑/k  ↓/j        Navigate list"),
            Line::from("    q / Esc         Quit"),
            Line::from(""),
            Line::from(Span::styled(
                "  Tab 1 — awzars Profiles:",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from("    a / c / e / d   Add / Clone / Edit / Delete"),
            Line::from("    Ctrl+S          Save form"),
            Line::from("    Esc             Cancel"),
            Line::from(""),
            Line::from(Span::styled(
                "  Tab 2 — AWS Config:",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from("    a / e           Add / Edit profile"),
            Line::from("    d               Delete (awzars-linked only)"),
            Line::from("    l               Link to awzars profile"),
            Line::from("    Ctrl+S          Save form"),
            Line::from(""),
            Line::from(Span::styled(
                "  Field editing:",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from("    ←/→  Home/End   Move cursor"),
            Line::from("    Backspace/Del   Delete character"),
            Line::from("    Ctrl+D          Clear field (navigation mode)"),
            Line::from("    Ctrl+U          Clear field (editing mode)"),
            Line::from("    Enter           Confirm edit"),
            Line::from("    Esc             Cancel edit"),
            Line::from(""),
            Line::from(Span::styled(
                "  Press any key to close",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let area = centered_rect(55, 75, f.area());
        let help = Paragraph::new(help_text).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Help ")
                .style(Style::default().bg(Color::Black)),
        );
        f.render_widget(help, area);
    }
}

// ---- Helpers ----

fn format_lock(locked: bool, ttl_hours: Option<u64>) -> String {
    if !locked {
        return "no".to_string();
    }
    let h = ttl_hours.unwrap_or(crate::auth::lock::DEFAULT_TTL_HOURS);
    format!("yes (TTL {}h)", h)
}

fn field_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("  {:>14}: ", label),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(value.to_string(), Style::default().fg(Color::White)),
    ])
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
