use thiserror::Error;

#[derive(Error, Debug)]
pub enum PcaptureError {
    /* OS DETECT ERROR */
    #[error("calculation of diff vec failed, the input vec length is not enough")]
    CalcDiffFailed,
}
