use std::cmp::Ordering;

/// A package version ordered with the same rules as winget.
#[derive(Debug, Clone)]
pub struct Version {
    parts: Vec<Part>,
}

#[derive(Debug, Clone, Default)]
struct Part {
    number: u64,
    other: String,
}

impl Version {
    pub fn parse(text: &str) -> Self {
        let mut parts: Vec<Part> = text.trim().split('.').map(Part::parse).collect();
        while parts.last().is_some_and(|p| p.number == 0 && p.other.is_empty()) {
            parts.pop();
        }
        Self { parts }
    }
}

impl Part {
    fn parse(text: &str) -> Self {
        let text = text.trim();
        let digits = text.bytes().take_while(u8::is_ascii_digit).count();
        Self {
            number: text[..digits].parse().unwrap_or(if digits == 0 { 0 } else { u64::MAX }),
            other: text[digits..].to_lowercase(),
        }
    }
}

impl Ord for Part {
    fn cmp(&self, other: &Self) -> Ordering {
        self.number.cmp(&other.number).then_with(|| {
            // A part with a suffix sorts before the same number without one, so "1-beta" < "1"
            match (self.other.is_empty(), other.other.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.other.cmp(&other.other),
            }
        })
    }
}

impl PartialOrd for Part {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Part {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Part {}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let empty = Part::default();
        let len = self.parts.len().max(other.parts.len());
        (0..len)
            .map(|i| {
                let a = self.parts.get(i).unwrap_or(&empty);
                let b = other.parts.get(i).unwrap_or(&empty);
                a.cmp(b)
            })
            .find(|o| o.is_ne())
            .unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

#[cfg(test)]
mod tests {
    use super::Version;

    fn v(text: &str) -> Version {
        Version::parse(text)
    }

    #[test]
    fn numeric_parts() {
        assert!(v("1.10") > v("1.9"));
        assert!(v("2") > v("1.99.99"));
        assert!(v("10.0.19041") > v("10.0.1904"));
    }

    #[test]
    fn trailing_zeros_are_equal() {
        assert_eq!(v("1.0.0"), v("1"));
        assert_eq!(v("1.0"), v("1.0.0.0"));
    }

    #[test]
    fn suffixes() {
        assert!(v("1.0-beta") < v("1.0"));
        assert!(v("1.0-beta") < v("1.0-rc"));
        assert!(v("1.0-Beta") == v("1.0-beta"));
        assert!(v("1.1-beta") > v("1.0"));
    }

    #[test]
    fn large_numbers() {
        assert!(v("20240101123456") > v("20231231000000"));
        assert!(v("99999999999999999999999") > v("1"));
    }
}
