// This code is translated from the Xilinx I3C C driver:
// https://github.com/Xilinx/embeddedsw/tree/master/XilinxProcessorIPLib/drivers/i3c/src
// Which is:
// Copyright (C) 2024 Advanced Micro Devices, Inc. All Rights Reserved
// SPDX-License-Identifier: MIT

mod xi3c;
mod xi3c_master;

#[allow(unused)]
pub use xi3c::{Ccc, Command, Config, Controller, XI3c};
