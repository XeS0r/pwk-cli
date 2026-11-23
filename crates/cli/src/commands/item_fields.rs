//! Turning the field options and `field=value` assignments of `item create` and
//! `item edit` into changes. Pure logic, no I/O.

use anyhow::bail;
use pwk_api::{CustomField, CustomKind, SecretString};
use zeroize::Zeroizing;

use crate::cli::{Assignment, FieldKind, ItemFieldArgs, StandardField};

/// The changes requested on the command line; `None` leaves a field unchanged.
#[derive(Default)]
pub struct FieldChanges {
    /// New name.
    pub name: Option<String>,
    /// New login (empty clears it).
    pub login: Option<String>,
    /// `Some(Some(p))` sets, `Some(None)` clears the password.
    pub password: Option<Option<SecretString>>,
    /// New main URL.
    pub url: Option<String>,
    /// New complete URL list (only with two or more `--url`; `None` keeps the list).
    pub urls: Option<Vec<String>>,
    /// New description.
    pub description: Option<String>,
    /// New tags.
    pub tags: Option<Vec<String>>,
    /// New color.
    pub color: Option<i64>,
    /// The complete new list of custom fields, if any custom field changed.
    pub customs: Option<Vec<CustomField>>,
}

impl std::fmt::Debug for FieldChanges {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldChanges")
            .field("name", &self.name)
            .field("login", &self.login)
            .field("password", &self.password.as_ref().map(Option::is_some))
            .field("customs", &self.customs)
            .finish_non_exhaustive()
    }
}

impl FieldChanges {
    /// True when nothing would change.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.name.is_none()
            && self.login.is_none()
            && self.password.is_none()
            && self.url.is_none()
            && self.urls.is_none()
            && self.description.is_none()
            && self.tags.is_none()
            && self.color.is_none()
            && self.customs.is_none()
    }
}

/// The custom field type of a `[kind]`.
#[must_use]
pub fn custom_kind(kind: FieldKind) -> CustomKind {
    match kind {
        FieldKind::Text => CustomKind::Text,
        FieldKind::Password => CustomKind::Password,
        FieldKind::Totp => CustomKind::Totp,
    }
}

/// Builds the changes from the options, the assignments and an already read or
/// generated password (`--password-stdin` / `--generate-password`). `existing` are the
/// item's current custom fields (empty on create). `editing` allows `field=` removals.
pub fn plan_changes(
    args: &ItemFieldArgs,
    password_input: Option<SecretString>,
    existing: &[CustomField],
    editing: bool,
) -> anyhow::Result<FieldChanges> {
    let mut changes = FieldChanges {
        login: args.login.clone(),
        description: args.description.clone(),
        color: args.color.map(i64::from),
        ..FieldChanges::default()
    };
    // One --url sets only the main URL (the other URLs stay); several set the main URL
    // to the first and replace the whole list. Never an empty list: that would wipe it.
    if let Some(first) = args.urls.first() {
        changes.url = Some(first.clone());
        if args.urls.len() >= 2 {
            changes.urls = Some(args.urls.clone());
        }
    }
    if !args.tags.is_empty() {
        changes.tags = Some(args.tags.clone());
    }
    let from_input = password_input.is_some();
    changes.password = password_input.map(Some);

    let mut custom_assignments = Vec::new();
    for assignment in &args.assignments {
        match assignment.standard() {
            Some(field) => apply_standard(&mut changes, field, assignment, from_input, editing)?,
            None => custom_assignments.push(assignment),
        }
    }
    if !custom_assignments.is_empty() {
        changes.customs = Some(merge_customs(existing, &custom_assignments, editing)?);
    }
    Ok(changes)
}

fn apply_standard(
    changes: &mut FieldChanges,
    field: StandardField,
    assignment: &Assignment,
    password_from_input: bool,
    editing: bool,
) -> anyhow::Result<()> {
    let value = assignment.value.clone();
    if value.is_none() && !editing {
        bail!(
            "`{}=` clears a field; use it with `item edit`",
            assignment.name
        );
    }
    let text = value.clone().unwrap_or_default();
    match field {
        StandardField::Password => {
            if password_from_input {
                bail!("password given twice (assignment and --password-stdin/--generate-password)");
            }
            changes.password = Some(value.map(Zeroizing::new));
        }
        StandardField::Login => changes.login = Some(text),
        StandardField::Name => {
            if value.is_none() {
                bail!("an item needs a name; `name=` cannot clear it");
            }
            changes.name = Some(text);
        }
        StandardField::Url => changes.url = Some(text),
        StandardField::Description => changes.description = Some(text),
    }
    Ok(())
}

fn find_custom(customs: &[CustomField], name: &str) -> Option<usize> {
    let lower = name.to_lowercase();
    customs
        .iter()
        .position(|c| c.name == name)
        .or_else(|| customs.iter().position(|c| c.name.to_lowercase() == lower))
}

/// Applies custom field assignments to `existing`: a known name (exact, then
/// case-insensitive) is replaced in place (keeping its type unless `[kind]` is given),
/// a new name is appended (type text unless given), `name=` removes the field.
pub fn merge_customs(
    existing: &[CustomField],
    assignments: &[&Assignment],
    editing: bool,
) -> anyhow::Result<Vec<CustomField>> {
    let mut customs = existing.to_vec();
    for assignment in assignments {
        let position = find_custom(&customs, &assignment.name);
        match (&assignment.value, position) {
            (None, _) if !editing => {
                bail!(
                    "`{}=` removes a field; use it with `item edit`",
                    assignment.name
                );
            }
            (None, None) => bail!("the item has no custom field `{}`", assignment.name),
            (None, Some(i)) => {
                customs.remove(i);
            }
            (Some(value), Some(i)) => {
                let field = &mut customs[i];
                field.value = Zeroizing::new(value.clone());
                if let Some(kind) = assignment.kind {
                    field.kind = custom_kind(kind);
                }
            }
            (Some(value), None) => customs.push(CustomField::new(
                assignment.name.clone(),
                value.clone(),
                assignment.kind.map_or(CustomKind::Text, custom_kind),
            )),
        }
    }
    Ok(customs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assignments(args: &[&str]) -> Vec<Assignment> {
        args.iter().map(|a| a.parse().unwrap()).collect()
    }

    fn existing() -> Vec<CustomField> {
        vec![
            CustomField::new("PIN", "1234", CustomKind::Password),
            CustomField::new("note", "hello", CustomKind::Text),
            CustomField::new("otp", "JBSW", CustomKind::Totp),
        ]
    }

    fn summary(customs: &[CustomField]) -> Vec<(String, String, String)> {
        customs
            .iter()
            .map(|c| (c.name.clone(), c.value.to_string(), c.kind.to_string()))
            .collect()
    }

    #[test]
    fn merge_replaces_appends_removes() {
        let list = assignments(&[
            "pin=9999",
            "note[password]=secret",
            "new=x",
            "otp=",
            "t[totp]=AB",
        ]);
        let refs: Vec<&Assignment> = list.iter().collect();
        let merged = merge_customs(&existing(), &refs, true).unwrap();
        assert_eq!(
            summary(&merged),
            vec![
                ("PIN".into(), "9999".into(), "password".into()),
                ("note".into(), "secret".into(), "password".into()),
                ("new".into(), "x".into(), "text".into()),
                ("t".into(), "AB".into(), "totp".into()),
            ]
        );
    }

    #[test]
    fn merge_errors() {
        let list = assignments(&["missing="]);
        let refs: Vec<&Assignment> = list.iter().collect();
        assert!(
            merge_customs(&existing(), &refs, true)
                .unwrap_err()
                .to_string()
                .contains("no custom field `missing`")
        );
        let list = assignments(&["note="]);
        let refs: Vec<&Assignment> = list.iter().collect();
        assert!(merge_customs(&existing(), &refs, false).is_err());
    }

    #[test]
    fn exact_name_wins_over_case_insensitive() {
        let customs = vec![
            CustomField::new("Key", "a", CustomKind::Text),
            CustomField::new("key", "b", CustomKind::Text),
        ];
        let list = assignments(&["key=c"]);
        let refs: Vec<&Assignment> = list.iter().collect();
        let merged = merge_customs(&customs, &refs, true).unwrap();
        assert_eq!(merged[0].value.as_str(), "a");
        assert_eq!(merged[1].value.as_str(), "c");
    }

    fn field_args(assign: &[&str]) -> ItemFieldArgs {
        ItemFieldArgs {
            assignments: assignments(assign),
            ..ItemFieldArgs::default()
        }
    }

    #[test]
    fn standard_fields() {
        let mut args = field_args(&["login=bob", "password=pw", "url=https://u", "name=N"]);
        args.urls = vec!["https://a".into(), "https://b".into()];
        args.tags = vec!["t".into()];
        args.color = Some(3);
        let changes = plan_changes(&args, None, &[], false).unwrap();
        assert_eq!(changes.login.as_deref(), Some("bob"));
        assert_eq!(
            changes
                .password
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .as_str(),
            "pw"
        );
        // The assignment comes after --url and wins for the main URL.
        assert_eq!(changes.url.as_deref(), Some("https://u"));
        assert_eq!(
            changes.urls,
            Some(vec!["https://a".to_owned(), "https://b".to_owned()])
        );
        assert_eq!(changes.tags, Some(vec!["t".to_owned()]));
        assert_eq!(changes.color, Some(3));
        assert_eq!(changes.name.as_deref(), Some("N"));
        assert!(changes.customs.is_none());
        assert!(!changes.is_empty());
    }

    #[test]
    fn single_url_keeps_the_url_list() {
        let mut args = field_args(&[]);
        args.urls = vec!["https://only".into()];
        for editing in [true, false] {
            let changes = plan_changes(&args, None, &[], editing).unwrap();
            assert_eq!(changes.url.as_deref(), Some("https://only"));
            assert_eq!(changes.urls, None, "one --url must not replace the list");
        }
        let changes = plan_changes(&field_args(&["url=https://u"]), None, &[], true).unwrap();
        assert_eq!(changes.url.as_deref(), Some("https://u"));
        assert_eq!(changes.urls, None);
    }

    #[test]
    fn clearing_and_conflicts() {
        let changes = plan_changes(&field_args(&["password=", "login="]), None, &[], true).unwrap();
        assert!(matches!(changes.password, Some(None)));
        assert_eq!(changes.login.as_deref(), Some(""));
        assert!(plan_changes(&field_args(&["login="]), None, &[], false).is_err());
        assert!(plan_changes(&field_args(&["name="]), None, &[], true).is_err());
        let input = Some(Zeroizing::new("gen".to_owned()));
        assert!(plan_changes(&field_args(&["password=x"]), input.clone(), &[], false).is_err());
        let changes = plan_changes(&field_args(&[]), input, &[], false).unwrap();
        assert_eq!(changes.password.unwrap().unwrap().as_str(), "gen");
        assert!(
            plan_changes(&field_args(&[]), None, &[], true)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn customs_on_create() {
        let changes = plan_changes(
            &field_args(&["pin[password]=1", "note=x"]),
            None,
            &[],
            false,
        )
        .unwrap();
        let customs = changes.customs.unwrap();
        assert_eq!(customs.len(), 2);
        assert_eq!(customs[0].kind, CustomKind::Password);
        assert_eq!(customs[1].kind, CustomKind::Text);
    }
}
