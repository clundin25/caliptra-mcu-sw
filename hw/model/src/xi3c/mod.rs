// This code is translated from the Xilinx I3C C driver:
// https://github.com/Xilinx/embeddedsw/tree/master/XilinxProcessorIPLib/drivers/i3c/src
// Which is:
// Copyright (C) 2024 Advanced Micro Devices, Inc. All Rights Reserved
// SPDX-License-Identifier: MIT

mod xi3c;
mod xi3c_master;

pub use xi3c::{Config, Controller};
