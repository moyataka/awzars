use super::AwsProfileEntry;
use std::collections::{BTreeMap, HashMap};

enum Line<'a> {
    Header {
        raw: &'a str,
        name: &'a str,
    },
    Property {
        raw: &'a str,
        name: &'a str,
        value: &'a str,
    },
    Continuation {
        raw: &'a str,
        value: &'a str,
    },
    Other(&'a str),
}

impl<'a> Line<'a> {
    fn parse(raw: &'a str, property_indentation: &mut Option<usize>) -> Self {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';']) {
            return Self::Other(raw);
        }
        let indentation = raw.len() - raw.trim_start().len();
        if property_indentation.is_some_and(|previous| indentation > previous) {
            return Self::Continuation {
                raw,
                value: trimmed,
            };
        }
        if let Some((name, _)) = trimmed
            .strip_prefix('[')
            .and_then(|tail| tail.split_once(']'))
        {
            if !name.is_empty() {
                *property_indentation = None;
                return Self::Header { raw, name };
            }
        }
        if let Some((name, value)) = trimmed.split_once(['=', ':']) {
            *property_indentation = Some(indentation);
            return Self::Property {
                raw,
                name: name.trim_end(),
                value: value.trim(),
            };
        }
        Self::Other(raw)
    }

    fn raw(&self) -> &'a str {
        match self {
            Self::Header { raw, .. }
            | Self::Property { raw, .. }
            | Self::Continuation { raw, .. }
            | Self::Other(raw) => raw,
        }
    }
}

enum SectionName<'a> {
    Profile(&'a str),
    Other,
}

impl<'a> SectionName<'a> {
    fn parse(header: &'a str) -> Self {
        if header == "default" {
            return Self::Profile(header);
        }
        let Some(name) = header.strip_prefix("profile ").map(str::trim) else {
            return Self::Other;
        };
        let name = name
            .strip_prefix('"')
            .and_then(|name| name.strip_suffix('"'))
            .or_else(|| {
                name.strip_prefix('\'')
                    .and_then(|name| name.strip_suffix('\''))
            })
            .unwrap_or(name);
        if name.is_empty() {
            Self::Other
        } else {
            Self::Profile(name)
        }
    }
}

struct Section<'a> {
    name: SectionName<'a>,
    header: &'a str,
    lines: Vec<Line<'a>>,
}

impl Section<'_> {
    fn properties(&self) -> BTreeMap<String, String> {
        let mut properties = BTreeMap::<String, String>::new();
        let mut current_name = None;
        for line in &self.lines {
            match line {
                Line::Property { name, value, .. } => {
                    let name = name.to_ascii_lowercase();
                    properties.insert(name.clone(), (*value).to_string());
                    current_name = Some(name);
                }
                Line::Continuation { value, .. } => {
                    if let Some(previous) = current_name
                        .as_ref()
                        .and_then(|name| properties.get_mut(name))
                    {
                        previous.push('\n');
                        previous.push_str(value);
                    }
                }
                _ => {}
            }
        }
        properties
    }

    fn write_original(&self, output: &mut String) {
        output.push_str(self.header);
        self.lines
            .iter()
            .for_each(|line| output.push_str(line.raw()));
    }

    fn write_profile(&self, entry: &AwsProfileEntry, newline: &str, output: &mut String) {
        if matches!(self.name, SectionName::Profile(name) if name == entry.name) {
            output.push_str(self.header);
        } else {
            let opening = self.header.find('[').expect("parsed section header");
            let closing = self.header.find(']').expect("parsed section header");
            output.push_str(&self.header[..opening]);
            output.push_str(&profile_header(&entry.name));
            output.push_str(&self.header[closing + 1..]);
        }

        let original = self.properties();
        let desired = entry.properties();
        let mut preserve_continuations = true;
        for line in &self.lines {
            match line {
                Line::Property { raw, name, .. } => {
                    let name = name.to_ascii_lowercase();
                    preserve_continuations = desired.get(&name) == original.get(&name);
                    if preserve_continuations {
                        output.push_str(raw);
                    } else if let Some(value) = desired.get(&name) {
                        write_changed_property(raw, value, newline, output);
                    }
                }
                Line::Continuation { raw, .. } => {
                    if preserve_continuations {
                        output.push_str(raw);
                    }
                }
                _ => output.push_str(line.raw()),
            }
        }
        for (name, value) in desired
            .iter()
            .filter(|(name, _)| !original.contains_key(*name))
        {
            ensure_newline(output, newline);
            write_new_property(name, value, newline, output);
        }
    }
}

pub(super) struct Document<'a> {
    preamble: String,
    sections: Vec<Section<'a>>,
    newline: &'static str,
}

impl<'a> Document<'a> {
    pub(super) fn parse(contents: &'a str) -> Self {
        let mut document = Self {
            preamble: String::new(),
            sections: Vec::new(),
            newline: if contents.contains("\r\n") {
                "\r\n"
            } else {
                "\n"
            },
        };
        let mut property_indentation = None;
        for raw in contents.split_inclusive('\n') {
            let line = Line::parse(raw, &mut property_indentation);
            if let Line::Header { raw, name } = line {
                document.sections.push(Section {
                    name: SectionName::parse(name),
                    header: raw,
                    lines: Vec::new(),
                });
            } else if let Some(section) = document.sections.last_mut() {
                section.lines.push(line);
            } else {
                document.preamble.push_str(raw);
            }
        }
        document
    }

    pub(super) fn profiles(&self) -> impl Iterator<Item = (&str, BTreeMap<String, String>)> {
        self.sections
            .iter()
            .filter_map(|section| match section.name {
                SectionName::Profile(name) => Some((name, section.properties())),
                SectionName::Other => None,
            })
    }

    pub(super) fn update(&self, profiles: &[AwsProfileEntry]) -> String {
        let mut remaining: HashMap<_, _> = profiles
            .iter()
            .map(|entry| (entry.source_name(), entry))
            .collect();
        let mut output = self.preamble.clone();
        for section in &self.sections {
            match section.name {
                SectionName::Profile(name) => {
                    if let Some(entry) = remaining.remove(name) {
                        section.write_profile(entry, self.newline, &mut output);
                    }
                }
                SectionName::Other => section.write_original(&mut output),
            }
        }
        for entry in profiles
            .iter()
            .filter(|entry| remaining.contains_key(entry.source_name()))
        {
            ensure_newline(&mut output, self.newline);
            if !output.is_empty() {
                output.push_str(self.newline);
            }
            output.push_str(&profile_header(&entry.name));
            output.push_str(self.newline);
            for (name, value) in entry.properties() {
                write_new_property(&name, &value, self.newline, &mut output);
            }
        }
        output
    }
}

fn profile_header(name: &str) -> String {
    if name == "default" {
        "[default]".to_string()
    } else {
        format!("[profile {}]", name)
    }
}

fn ensure_newline(output: &mut String, newline: &str) {
    if !output.is_empty() && !output.ends_with('\n') {
        output.push_str(newline);
    }
}

fn write_new_property(name: &str, value: &str, newline: &str, output: &mut String) {
    let value = value.replace('\n', &format!("{}    ", newline));
    output.push_str(&format!("{} = {}{}", name, value, newline));
}

fn write_changed_property(raw: &str, value: &str, newline: &str, output: &mut String) {
    let ending = if raw.ends_with("\r\n") {
        "\r\n"
    } else if raw.ends_with('\n') {
        "\n"
    } else {
        ""
    };
    let body = &raw[..raw.len() - ending.len()];
    let separator = body.find(['=', ':']).expect("parsed property") + 1;
    let original_value = &body[separator..];
    let value_start = separator + original_value.len() - original_value.trim_start().len();
    let suffix = if original_value.trim().is_empty() {
        ""
    } else {
        &body[body.trim_end().len()..]
    };
    let indentation = &raw[..raw.len() - raw.trim_start().len()];
    let value = value.replace('\n', &format!("{}{}    ", newline, indentation));
    output.push_str(&body[..value_start]);
    output.push_str(&value);
    output.push_str(suffix);
    output.push_str(ending);
}
