#[cfg(feature = "libpcap")]
mod libpcap1;
#[cfg(feature = "libpnet")]
mod libpnet1;
#[cfg(feature = "libpnet")]
mod libpnet2;
#[cfg(feature = "libpnet")]
mod libpnet3;
#[cfg(feature = "libpnet")]
mod libpnet4;

fn main() {
    #[cfg(feature = "libpcap")]
    libpcap1::test1();
    #[cfg(feature = "libpnet")]
    libpnet1::test1();
    #[cfg(feature = "libpnet")]
    libpnet2::test2();
    #[cfg(feature = "libpnet")]
    libpnet3::test3();
    #[cfg(feature = "libpnet")]
    libpnet4::test4();
}
