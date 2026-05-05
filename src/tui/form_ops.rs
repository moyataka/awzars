//! Pure operations on a `FormField`.
//!
//! Text-editing logic is described as data (`FieldOp`) and applied via a
//! single dispatch. Two benefits over the previous one-method-per-edit
//! shape:
//!
//! 1. The mapping from keystroke to edit lives in one place
//!    (`key_to_field_op`) so both form handlers share it.
//! 2. Ops are first-class values — testable without a TUI, and easy to
//!    extend (undo, replay, programmatic edit) later if needed.

use super::form::FormField;
use crossterm::event::{KeyCode, KeyModifiers};

/// A single editing operation on a [`FormField`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldOp {
    InsertChar(char),
    DeleteBack,
    DeleteForward,
    MoveLeft,
    MoveRight,
    MoveHome,
    MoveEnd,
    Clear,
}

/// Move `current` by `delta` within `[0, len)`, clamping at the bounds.
///
/// Used by every autocomplete-suggestion list in the TUI (region,
/// credential_process, source_profile) — they all share the
/// "move-with-clamp" navigation pattern.
pub fn move_index(current: usize, delta: i32, len: usize) -> usize {
    if len == 0 {
        return current;
    }
    if delta > 0 {
        (current + delta as usize).min(len - 1)
    } else {
        current.saturating_sub((-delta) as usize)
    }
}

/// Map a (modifiers, keycode) pair to the corresponding edit op, or
/// `None` if the keystroke is not a text edit.
///
/// Bindings:
/// - char → InsertChar
/// - Backspace → DeleteBack
/// - Delete → DeleteForward
/// - Left/Right/Home/End → cursor movement
/// - Ctrl-U → Clear
pub fn key_to_field_op(mods: KeyModifiers, code: KeyCode) -> Option<FieldOp> {
    match (mods, code) {
        (_, KeyCode::Backspace) => Some(FieldOp::DeleteBack),
        (_, KeyCode::Delete) => Some(FieldOp::DeleteForward),
        (_, KeyCode::Left) => Some(FieldOp::MoveLeft),
        (_, KeyCode::Right) => Some(FieldOp::MoveRight),
        (_, KeyCode::Home) => Some(FieldOp::MoveHome),
        (_, KeyCode::End) => Some(FieldOp::MoveEnd),
        (KeyModifiers::CONTROL, KeyCode::Char('u')) => Some(FieldOp::Clear),
        (_, KeyCode::Char(c)) => Some(FieldOp::InsertChar(c)),
        _ => None,
    }
}

impl FormField {
    /// Apply an edit op to this field.
    ///
    /// Mutating in place rather than by-value is purely an efficiency
    /// choice — the `(field, op) -> field'` semantics are unchanged, and
    /// no other state is touched.
    pub fn apply(&mut self, op: FieldOp) {
        match op {
            FieldOp::InsertChar(c) => {
                self.value.insert(self.cursor_pos, c);
                self.cursor_pos += c.len_utf8();
            }
            FieldOp::DeleteBack => {
                if self.cursor_pos > 0 {
                    self.cursor_pos -= 1;
                    self.value.remove(self.cursor_pos);
                }
            }
            FieldOp::DeleteForward => {
                if self.cursor_pos < self.value.len() {
                    self.value.remove(self.cursor_pos);
                }
            }
            FieldOp::MoveLeft => {
                if self.cursor_pos > 0 {
                    self.cursor_pos -= 1;
                }
            }
            FieldOp::MoveRight => {
                if self.cursor_pos < self.value.len() {
                    self.cursor_pos += 1;
                }
            }
            FieldOp::MoveHome => {
                self.cursor_pos = 0;
            }
            FieldOp::MoveEnd => {
                self.cursor_pos = self.value.len();
            }
            FieldOp::Clear => {
                self.value.clear();
                self.cursor_pos = 0;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(value: &str, cursor: usize) -> FormField {
        let mut f = FormField::new("test", value.to_string(), false);
        f.cursor_pos = cursor;
        f
    }

    #[test]
    fn insert_char_at_cursor() {
        let mut f = field("ac", 1);
        f.apply(FieldOp::InsertChar('b'));
        assert_eq!(f.value, "abc");
        assert_eq!(f.cursor_pos, 2);
    }

    #[test]
    fn insert_multibyte_char_advances_by_utf8_len() {
        let mut f = field("", 0);
        f.apply(FieldOp::InsertChar('é'));
        assert_eq!(f.value, "é");
        assert_eq!(f.cursor_pos, 'é'.len_utf8());
    }

    #[test]
    fn delete_back_at_start_is_noop() {
        let mut f = field("abc", 0);
        f.apply(FieldOp::DeleteBack);
        assert_eq!(f.value, "abc");
        assert_eq!(f.cursor_pos, 0);
    }

    #[test]
    fn delete_back_removes_previous_char() {
        let mut f = field("abc", 2);
        f.apply(FieldOp::DeleteBack);
        assert_eq!(f.value, "ac");
        assert_eq!(f.cursor_pos, 1);
    }

    #[test]
    fn delete_forward_at_end_is_noop() {
        let mut f = field("abc", 3);
        f.apply(FieldOp::DeleteForward);
        assert_eq!(f.value, "abc");
        assert_eq!(f.cursor_pos, 3);
    }

    #[test]
    fn delete_forward_removes_current_char() {
        let mut f = field("abc", 1);
        f.apply(FieldOp::DeleteForward);
        assert_eq!(f.value, "ac");
        assert_eq!(f.cursor_pos, 1);
    }

    #[test]
    fn cursor_movement_clamps_to_bounds() {
        let mut f = field("abc", 0);
        f.apply(FieldOp::MoveLeft);
        assert_eq!(f.cursor_pos, 0);

        let mut f = field("abc", 3);
        f.apply(FieldOp::MoveRight);
        assert_eq!(f.cursor_pos, 3);
    }

    #[test]
    fn home_and_end_jump() {
        let mut f = field("hello", 2);
        f.apply(FieldOp::MoveEnd);
        assert_eq!(f.cursor_pos, 5);
        f.apply(FieldOp::MoveHome);
        assert_eq!(f.cursor_pos, 0);
    }

    #[test]
    fn clear_resets_value_and_cursor() {
        let mut f = field("hello", 3);
        f.apply(FieldOp::Clear);
        assert_eq!(f.value, "");
        assert_eq!(f.cursor_pos, 0);
    }

    #[test]
    fn key_mapping_covers_text_edits() {
        assert_eq!(
            key_to_field_op(KeyModifiers::NONE, KeyCode::Char('x')),
            Some(FieldOp::InsertChar('x'))
        );
        assert_eq!(
            key_to_field_op(KeyModifiers::NONE, KeyCode::Backspace),
            Some(FieldOp::DeleteBack)
        );
        assert_eq!(
            key_to_field_op(KeyModifiers::CONTROL, KeyCode::Char('u')),
            Some(FieldOp::Clear)
        );
    }

    #[test]
    fn key_mapping_returns_none_for_navigation_keys() {
        assert_eq!(key_to_field_op(KeyModifiers::NONE, KeyCode::Esc), None);
        assert_eq!(key_to_field_op(KeyModifiers::NONE, KeyCode::Enter), None);
        assert_eq!(key_to_field_op(KeyModifiers::NONE, KeyCode::Tab), None);
    }

    #[test]
    fn move_index_clamps_at_bounds() {
        // forward past end clamps to len - 1
        assert_eq!(move_index(2, 5, 4), 3);
        // backward past start clamps to 0
        assert_eq!(move_index(1, -5, 4), 0);
        // empty list returns current unchanged
        assert_eq!(move_index(7, 1, 0), 7);
        // delta 0 is identity
        assert_eq!(move_index(2, 0, 4), 2);
    }
}
