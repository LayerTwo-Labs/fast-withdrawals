//! Generated protobuf and Connect code, wired into `fastwithdraw::*` modules.

#[allow(
    non_camel_case_types,
    dead_code,
    unused_imports,
    unused_qualifications,
    clippy::all
)]
pub mod generated {
    pub mod buffa {
        pub mod fastwithdraw {
            pub mod v1 {
                include!("generated/buffa/fastwithdraw.v1.rs");
            }
            pub mod internal {
                pub mod v1 {
                    include!("generated/buffa/fastwithdraw.internal.v1.rs");
                }
            }
            pub mod wallet {
                pub mod v1 {
                    include!("generated/buffa/fastwithdraw.wallet.v1.rs");
                }
            }
        }
    }

    pub mod connect {
        pub mod fastwithdraw {
            pub mod v1 {
                include!("generated/connect/fastwithdraw.v1.rs");
            }
            pub mod internal {
                pub mod v1 {
                    include!("generated/connect/fastwithdraw.internal.v1.rs");
                }
            }
            pub mod wallet {
                pub mod v1 {
                    include!("generated/connect/fastwithdraw.wallet.v1.rs");
                }
            }
        }
    }
}

/// Public API messages.
pub mod v1 {
    pub use crate::generated::buffa::fastwithdraw::v1::*;
}

/// Public API service traits and client.
pub mod v1_connect {
    pub use crate::generated::connect::fastwithdraw::v1::*;
}

/// Internal api messages, for Cloud Scheduler.
pub mod internal {
    pub use crate::generated::buffa::fastwithdraw::internal::v1::*;
}

/// Internal api service traits and client.
pub mod internal_connect {
    pub use crate::generated::connect::fastwithdraw::internal::v1::*;
}

/// Internal wallet messages.
pub mod wallet {
    pub use crate::generated::buffa::fastwithdraw::wallet::v1::*;
}

/// Internal wallet service traits and client.
pub mod wallet_connect {
    pub use crate::generated::connect::fastwithdraw::wallet::v1::*;
}
