use caliptra_api::mailbox::MailboxResp;
use caliptra_api::mailbox::{CommandId, MailboxReq, MailboxReqHeader, ReportHekMetadataReq};
use romtime::CaliptraSoC;
use romtime::McuError;

use zerocopy::FromBytes;

// TODO(clundin): Push into config or compile flag?
const TOTAL_HEK_SEED_SLOTS: u16 = 8;

#[derive(Debug)]
pub enum HekSeedState {
    Empty,
    Zeroized,
    Corrupted,
    Programmed,
    Unerasable,
}

impl From<HekSeedState> for u16 {
    fn from(value: HekSeedState) -> Self {
        match value {
            HekSeedState::Empty => 0x0,
            HekSeedState::Zeroized => 0x1,
            HekSeedState::Corrupted => 0x2,
            HekSeedState::Programmed => 0x3,
            HekSeedState::Unerasable => 0x4,
        }
    }
}

pub fn report_hek_state(soc: &mut CaliptraSoC) -> Result<(), McuError> {
    romtime::println!("Reporting HEK metadata");
    let seed_state = HekSeedState::Programmed;
    let mut cmd = MailboxReq::ReportHekMetadata(ReportHekMetadataReq {
        hdr: MailboxReqHeader { chksum: 0 },
        total_slots: TOTAL_HEK_SEED_SLOTS,
        active_slots: 1,
        seed_state: seed_state.into(),
        ..Default::default()
    });
    cmd.populate_chksum().map_err(|_| McuError::FusesError)?;
    // let cmd = cmd.as_bytes().map_err(|_| McuError::FusesError)?;

    // let cmd = <[u32]>::ref_from_bytes(cmd).map_err(|_| McuError::FusesError)?;

    return Ok(());
    // romtime::println!("starting HEK metadata");
    // soc.start_mailbox_req(
    //     CommandId::REPORT_HEK_METADATA.into(),
    //     cmd.len(),
    //     cmd.iter().copied(),
    // )
    // .map_err(|_| McuError::FusesError)?;
    //
    // romtime::println!("finished HEK metadata");
    // soc.finish_mailbox_resp(
    //     core::mem::size_of::<MailboxResp>(),
    //     core::mem::size_of::<MailboxResp>(),
    // )
    // .map_err(|_| McuError::FusesError)?;

    Ok(())
}
