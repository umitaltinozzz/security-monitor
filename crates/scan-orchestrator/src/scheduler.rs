use std::time::Duration;

use thiserror::Error;
use tokio::{sync::mpsc, time::Instant};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulePlan {
    pub inventory_check_interval: Duration,
    pub advisory_refresh_interval: Duration,
    pub full_scan_interval: Duration,
}

impl Default for SchedulePlan {
    fn default() -> Self {
        Self {
            inventory_check_interval: Duration::from_secs(15 * 60),
            advisory_refresh_interval: Duration::from_secs(10 * 60),
            full_scan_interval: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScheduleAction {
    CheckProjects,
    RefreshAdvisories,
    FullScanProjects,
}

#[derive(Debug, Error)]
pub enum ScheduleError {
    #[error("schedule intervals must be positive")]
    InvalidInterval,
    #[error("schedule event receiver closed")]
    ReceiverClosed,
}

pub struct Scheduler {
    plan: SchedulePlan,
    next_inventory_check: Instant,
    next_advisory_refresh: Instant,
    next_full_scan: Instant,
}

impl Scheduler {
    pub fn new(plan: SchedulePlan, now: Instant) -> Result<Self, ScheduleError> {
        if plan.inventory_check_interval.is_zero()
            || plan.advisory_refresh_interval.is_zero()
            || plan.full_scan_interval.is_zero()
        {
            return Err(ScheduleError::InvalidInterval);
        }
        Ok(Self {
            plan,
            next_inventory_check: now + plan.inventory_check_interval,
            next_advisory_refresh: now + plan.advisory_refresh_interval,
            next_full_scan: now + plan.full_scan_interval,
        })
    }

    pub fn due_actions(&mut self, now: Instant) -> Vec<ScheduleAction> {
        let mut actions = Vec::new();
        if now >= self.next_inventory_check {
            actions.push(ScheduleAction::CheckProjects);
            self.next_inventory_check = now + self.plan.inventory_check_interval;
        }
        if now >= self.next_advisory_refresh {
            actions.push(ScheduleAction::RefreshAdvisories);
            self.next_advisory_refresh = now + self.plan.advisory_refresh_interval;
        }
        if now >= self.next_full_scan {
            actions.push(ScheduleAction::FullScanProjects);
            self.next_full_scan = now + self.plan.full_scan_interval;
        }
        actions
    }

    pub async fn run(
        mut self,
        sender: mpsc::Sender<ScheduleAction>,
        cancellation: CancellationToken,
    ) -> Result<(), ScheduleError> {
        let interval = self
            .plan
            .inventory_check_interval
            .min(self.plan.advisory_refresh_interval)
            .min(self.plan.full_scan_interval);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = cancellation.cancelled() => return Ok(()),
                _ = ticker.tick() => {
                    for action in self.due_actions(Instant::now()) {
                        sender.send(action).await.map_err(|_| ScheduleError::ReceiverClosed)?;
                    }
                }
            }
        }
    }
}
