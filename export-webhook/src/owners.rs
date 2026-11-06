// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::ops::Deref;
use zeroize::Zeroize;

/// The URL parser owns a serialization separate from the operator's setting. Consume it through
/// [`Deref`]: when it drops, that serialization is taken out and wiped, so no parsed copy of a
/// credential-bearing url outlives its use.
pub(crate) struct ParsedUrl(Option<url::Url>);

impl ParsedUrl {
    pub(crate) fn parse(text: &str) -> Result<Self, url::ParseError> {
        url::Url::parse(text).map(|url| Self(Some(url)))
    }
}

impl Deref for ParsedUrl {
    type Target = url::Url;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().expect("owned parsed URL")
    }
}
impl Drop for ParsedUrl {
    fn drop(&mut self) {
        if let Some(url) = self.0.take() {
            let mut text = String::from(url);
            text.zeroize();
        }
    }
}
