// Licensed under the Apache-2.0 license

use anyhow::Result;

pub(crate) fn precheckin() -> Result<()> {
    mcu_builder::runtime_build_with_apps(&[], None)
}
