use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoincWork {
    pub project_name: String,
    pub user_id: String,
    pub task_id: String,
    pub cpu_time: f64,
    pub credit_granted: f64,
    pub completion_time: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_state: Option<crate::poi::ValidationState>,
}
