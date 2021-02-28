use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct AuditLog {
    pub time: String,
    #[serde(rename = "type")]
    pub log_type: String,
    pub request: Request,
}

#[derive(Deserialize, Debug)]
pub struct Request {
    pub operation: String,
    pub mount_type: String,
    pub path: String,
}

#[derive(Serialize, Debug)]
pub struct CreateAuditDeviceRequest {
    #[serde(rename = "type")]
    pub audit_device_type: String,
    pub options: AuditDeviceOptions,
}

#[derive(Serialize, Debug)]
pub struct AuditDeviceOptions {
    pub address: String,
    pub socket_type: String,
}
