/// Normalizes a UUID string to the standard hyphenated format.
/// Accepts either "f9526c60fe324e43a915294b5f97cabe" (32 chars)
/// or "f9526c60-fe32-4e43-a915-294b5f97cabe" (36 chars).
/// Returns None if the input is not a valid UUID format.
pub fn normalize_uuid(input: &str) -> Option<String> {
    let input = input.trim();

    match input.len() {
        36 if input.chars().enumerate().all(|(i, c)| {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        }) =>
        {
            Some(input.to_lowercase())
        }
        32 if input.chars().all(|c| c.is_ascii_hexdigit()) => Some(
            format!(
                "{}-{}-{}-{}-{}",
                &input[0..8],
                &input[8..12],
                &input[12..16],
                &input[16..20],
                &input[20..32]
            )
            .to_lowercase(),
        ),

        _ => None,
    }
}
