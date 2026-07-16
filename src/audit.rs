use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct AuditLog {
    #[allow(dead_code)]
    pub time: String,
    #[serde(rename = "type")]
    pub log_type: String,
    pub request: Request,
}

#[derive(Deserialize, Debug)]
pub struct Request {
    pub operation: String,
    pub mount_type: Option<String>,
    pub path: String,
}
