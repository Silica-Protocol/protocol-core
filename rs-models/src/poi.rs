use super::boinc::BoincWork;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationState {
    Pending,
    Validated,
    Invalid,
    InProgress,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoIProof {
    pub work_hash: String,
    pub contributor_address: String,
    pub boinc_work: BoincWork,
    pub proof_timestamp: DateTime<Utc>,
    pub difficulty_score: f64,
    pub reward_points: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HardwareType {
    CpuOnly,
    GpuOnly,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectInfo {
    pub name: String,
    pub description: String,
    pub cpu_supported: bool,
    pub gpu_supported: bool,
    pub estimated_runtime: Duration,
    pub priority: u32,
    pub reward_multiplier: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoIServiceConfig {
    pub name: String,
    pub api_endpoint: String,
    pub reward_multiplier: f64,
    pub min_work_interval: Duration,
    pub max_daily_submissions: u32,
    pub requires_auth: bool,
}
