use std::{error::Error, fmt};

use crate::{
    AcerHwmonDevice, AdmittedPolicyAuthority, BoundedIdentityBoundFileAccess, Clock,
    CompletedControlCycle, ControllerOwnership, EmergencyContainmentReport, FanArmingError,
    FirmwareAutoRestorationError, FreshSampleGate, HealthyControl, HealthyControlCycleError,
    IdentityBoundReadAccess, OwnershipSampleReadiness, RequiredInput, RuntimeFault,
    RuntimeLockAccess, RuntimeState, RuntimeTransition, SampleSetError, SampleSourceError,
    SampleSources, ShutdownRequest, ValidatedConfig, arm_both_fans_safely,
    diagnostics::sample_fault, emit_fault, emit_state_transition,
    ownership::FirmwareAutoSafingOutcome, run_healthy_control_cycle,
};

/// Creates replacement CPU/GPU source bindings while Firmware Auto owns both fans.
///
/// Each successful call must perform fresh discovery. The returned source value becomes the only
/// one retained by [`TransientSensorControl`]; the source from the failed epoch is dropped only
/// after Firmware Auto restoration succeeds. Filesystem access is read-only by construction.
pub trait SensorSourceDiscovery {
    type Sources: SampleSources;

    fn rediscover(
        &mut self,
        files: &mut dyn IdentityBoundReadAccess,
    ) -> Result<Self::Sources, SampleSourceError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SensorControlState {
    CustomControl,
    FirmwareAutoRecovery,
    Faulted,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SensorControlStep {
    Completed(CompletedControlCycle),
    FirmwareAutoRestored { fault: SampleSetError },
    AwaitingRediscovery(SampleSourceError),
    AwaitingSecondSample,
    Rearmed,
}

#[derive(Debug)]
pub enum TransientSensorControlError {
    Faulted,
    ShutdownRequested,
    ControlLatched {
        fault: HealthyControlCycleError,
    },
    ControlLatchContained {
        fault: HealthyControlCycleError,
        restoration: Box<FirmwareAutoRestorationError>,
        containment: Box<EmergencyContainmentReport>,
    },
    ControlLatchCritical {
        fault: HealthyControlCycleError,
        restoration: Box<FirmwareAutoRestorationError>,
        containment: Box<EmergencyContainmentReport>,
    },
    RecoveryLatched {
        fault: SampleSetError,
    },
    RecoveryLatchContained {
        fault: SampleSetError,
        restoration: Box<FirmwareAutoRestorationError>,
        containment: Box<EmergencyContainmentReport>,
    },
    RecoveryLatchCritical {
        fault: SampleSetError,
        restoration: FirmwareAutoRestorationError,
        containment: Box<EmergencyContainmentReport>,
    },
    Rearming(FanArmingError),
}

impl fmt::Display for TransientSensorControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Faulted => formatter.write_str("sensor recovery control is faulted"),
            Self::ShutdownRequested => {
                formatter.write_str("graceful shutdown permanently cancelled sensor control")
            }
            Self::ControlLatched { fault } => {
                write!(
                    formatter,
                    "normal control fault latched after restoring Firmware Auto: {fault}"
                )
            }
            Self::ControlLatchContained {
                fault,
                restoration,
                containment,
            } => write!(
                formatter,
                "normal control fault latched after emergency containment ({fault}); Firmware Auto restoration failed: {restoration}; containment: {containment:?}"
            ),
            Self::ControlLatchCritical {
                fault,
                restoration,
                containment,
            } => write!(
                formatter,
                "critical normal control fault latched with Firmware Auto unconfirmed ({fault}); restoration failed: {restoration}; containment: {containment:?}"
            ),
            Self::RecoveryLatched { fault } => write!(
                formatter,
                "recovery fault latched after restoring Firmware Auto: {fault}"
            ),
            Self::RecoveryLatchContained {
                fault,
                restoration,
                containment,
            } => write!(
                formatter,
                "sensor fault latched after emergency containment ({fault}); Firmware Auto restoration failed: {restoration}; containment: {containment:?}"
            ),
            Self::RecoveryLatchCritical {
                fault,
                restoration,
                containment,
            } => write!(
                formatter,
                "critical sensor fault latched with Firmware Auto unconfirmed ({fault}); restoration failed: {restoration}; containment: {containment:?}"
            ),
            Self::Rearming(error) => write!(formatter, "sensor recovery rearming failed: {error}"),
        }
    }
}

impl Error for TransientSensorControlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Faulted | Self::ShutdownRequested => None,
            Self::ControlLatched { fault }
            | Self::ControlLatchContained { fault, .. }
            | Self::ControlLatchCritical { fault, .. } => Some(fault),
            Self::RecoveryLatched { fault } | Self::RecoveryLatchContained { fault, .. } => {
                Some(fault)
            }
            Self::RecoveryLatchCritical { restoration, .. } => Some(restoration),
            Self::Rearming(error) => Some(error),
        }
    }
}

#[derive(Debug)]
enum ControlState<S> {
    Custom {
        control: Box<HealthyControl>,
        sources: S,
    },
    Recovering(Box<RecoveryState<S>>),
    Faulted {
        retained_sources: Option<S>,
    },
}

#[derive(Debug)]
struct RecoveryState<S> {
    config: ValidatedConfig,
    device: AcerHwmonDevice,
    gate: FreshSampleGate,
    sources: Option<S>,
}

/// Owns normal control and the sole permitted automatic recovery path.
///
/// A CPU/GPU input failure, stale observation, future observation, or late observation restores
/// Firmware Auto in the same call. Recovery then requires replacement source bindings, two new
/// consecutive complete sample sets, and the full two-fan arming handover.
#[derive(Debug)]
pub struct TransientSensorControl<D>
where
    D: SensorSourceDiscovery,
{
    authority: AdmittedPolicyAuthority,
    discovery: D,
    shutdown: ShutdownRequest,
    state: Option<ControlState<D::Sources>>,
}

impl<D> TransientSensorControl<D>
where
    D: SensorSourceDiscovery,
{
    pub fn from_armed(
        armed: crate::ArmedFanControl,
        authority: AdmittedPolicyAuthority,
        shutdown: ShutdownRequest,
        discovery: D,
        sources: D::Sources,
    ) -> Self {
        Self {
            authority,
            discovery,
            shutdown: shutdown.clone(),
            state: Some(ControlState::Custom {
                control: Box::new(HealthyControl::from_armed(armed, shutdown)),
                sources,
            }),
        }
    }

    pub fn state(&self) -> SensorControlState {
        match self
            .state
            .as_ref()
            .expect("control state is always installed")
        {
            ControlState::Custom { .. } => SensorControlState::CustomControl,
            ControlState::Recovering(_) => SensorControlState::FirmwareAutoRecovery,
            ControlState::Faulted { .. } => SensorControlState::Faulted,
        }
    }

    pub fn step<P>(
        &mut self,
        ownership: &mut ControllerOwnership<'_, P>,
    ) -> Result<SensorControlStep, TransientSensorControlError>
    where
        P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
    {
        let state = self
            .state
            .take()
            .expect("control state is always installed");
        match state {
            ControlState::Custom {
                mut control,
                mut sources,
            } => match run_healthy_control_cycle(ownership, &mut control, &mut sources) {
                Ok(completed) => {
                    self.state = Some(ControlState::Custom { control, sources });
                    Ok(SensorControlStep::Completed(completed))
                }
                Err(HealthyControlCycleError::ShutdownRequested) => {
                    emit_state_transition(
                        RuntimeState::CustomControl,
                        RuntimeState::FaultLatched,
                        RuntimeTransition::Shutdown,
                    );
                    self.state = Some(ControlState::Faulted {
                        retained_sources: Some(sources),
                    });
                    Err(TransientSensorControlError::ShutdownRequested)
                }
                Err(error) => {
                    let Some(fault) = recoverable_sensor_cycle_fault(&error).cloned() else {
                        let (_, device) = (*control).into_recovery_parts();
                        emit_state_transition(
                            RuntimeState::CustomControl,
                            RuntimeState::Restoring,
                            RuntimeTransition::ControlFault,
                        );
                        return self.latch_control_fault(ownership, device, error, sources);
                    };
                    let (config, device) = (*control).into_recovery_parts();
                    emit_state_transition(
                        RuntimeState::CustomControl,
                        RuntimeState::Restoring,
                        RuntimeTransition::SensorFault,
                    );
                    self.restore_for_recovery(ownership, config, device, fault, sources)
                }
            },
            ControlState::Recovering(recovery) => {
                let RecoveryState {
                    config,
                    device,
                    mut gate,
                    mut sources,
                } = *recovery;
                if self.shutdown.is_requested() {
                    emit_fault(RuntimeFault::ShutdownRequested, None);
                    emit_state_transition(
                        RuntimeState::FirmwareAuto,
                        RuntimeState::FaultLatched,
                        RuntimeTransition::Shutdown,
                    );
                    self.state = Some(ControlState::Faulted {
                        retained_sources: sources,
                    });
                    return Err(TransientSensorControlError::ShutdownRequested);
                }
                if sources.is_none() && !ownership.refresh_firmware_auto_confirmation(&device) {
                    emit_fault(RuntimeFault::FirmwareAutoUnconfirmed, None);
                    emit_state_transition(
                        RuntimeState::FirmwareAuto,
                        RuntimeState::Restoring,
                        RuntimeTransition::ControlFault,
                    );
                    return self.latch_recovery_fault(
                        ownership,
                        device,
                        SampleSetError::FirmwareAutoUnconfirmed,
                        None,
                    );
                }
                if sources.is_none() {
                    match self.discovery.rediscover(ownership.platform_mut()) {
                        Ok(rediscovered) => {
                            gate.reset();
                            sources = Some(rediscovered);
                        }
                        Err(source) => {
                            emit_fault(RuntimeFault::SensorUnavailable, None);
                            self.state = Some(ControlState::Recovering(Box::new(RecoveryState {
                                config,
                                device,
                                gate,
                                sources: None,
                            })));
                            return Ok(SensorControlStep::AwaitingRediscovery(source));
                        }
                    }
                }

                let readiness = ownership.collect_fresh_sample(
                    &device,
                    &mut gate,
                    sources
                        .as_mut()
                        .expect("successful rediscovery installs sources"),
                );
                match readiness {
                    Ok(OwnershipSampleReadiness::AwaitingSecondSample) => {
                        self.state = Some(ControlState::Recovering(Box::new(RecoveryState {
                            config,
                            device,
                            gate,
                            sources,
                        })));
                        Ok(SensorControlStep::AwaitingSecondSample)
                    }
                    Ok(OwnershipSampleReadiness::Ready(sample)) => {
                        if self.shutdown.is_requested() {
                            emit_fault(RuntimeFault::ShutdownRequested, None);
                            emit_state_transition(
                                RuntimeState::FirmwareAuto,
                                RuntimeState::FaultLatched,
                                RuntimeTransition::Shutdown,
                            );
                            self.state = Some(ControlState::Faulted {
                                retained_sources: sources,
                            });
                            return Err(TransientSensorControlError::ShutdownRequested);
                        }
                        match arm_both_fans_safely(
                            ownership,
                            &device,
                            &self.authority,
                            &config,
                            sample,
                        ) {
                            Ok(armed) => {
                                self.state = Some(ControlState::Custom {
                                    control: Box::new(HealthyControl::from_armed(
                                        armed,
                                        self.shutdown.clone(),
                                    )),
                                    sources: sources
                                        .expect("ready sample was captured from installed sources"),
                                });
                                Ok(SensorControlStep::Rearmed)
                            }
                            Err(error) => {
                                if !matches!(&error, FanArmingError::RestorationFailed { .. }) {
                                    emit_state_transition(
                                        RuntimeState::FirmwareAuto,
                                        RuntimeState::FaultLatched,
                                        RuntimeTransition::ControlFault,
                                    );
                                }
                                let retained_sources =
                                    if matches!(&error, FanArmingError::RestorationFailed { .. }) {
                                        sources
                                    } else {
                                        drop(sources);
                                        None
                                    };
                                self.state = Some(ControlState::Faulted { retained_sources });
                                Err(TransientSensorControlError::Rearming(error))
                            }
                        }
                    }
                    Err(fault) if recoverable_sensor_sample_fault(&fault) => {
                        let (fault_id, endpoint) = sample_fault(&fault);
                        emit_fault(fault_id, endpoint);
                        emit_state_transition(
                            RuntimeState::FirmwareAuto,
                            RuntimeState::Restoring,
                            RuntimeTransition::SensorFault,
                        );
                        self.restore_for_recovery(
                            ownership,
                            config,
                            device,
                            fault,
                            sources.expect("sample failure requires installed sources"),
                        )
                    }
                    Err(fault) => {
                        let (fault_id, endpoint) = sample_fault(&fault);
                        emit_fault(fault_id, endpoint);
                        emit_state_transition(
                            RuntimeState::FirmwareAuto,
                            RuntimeState::Restoring,
                            RuntimeTransition::ControlFault,
                        );
                        self.latch_recovery_fault(ownership, device, fault, sources)
                    }
                }
            }
            ControlState::Faulted { retained_sources } => {
                self.state = Some(ControlState::Faulted { retained_sources });
                Err(TransientSensorControlError::Faulted)
            }
        }
    }

    fn restore_for_recovery<P>(
        &mut self,
        ownership: &mut ControllerOwnership<'_, P>,
        config: ValidatedConfig,
        device: AcerHwmonDevice,
        fault: SampleSetError,
        sources: D::Sources,
    ) -> Result<SensorControlStep, TransientSensorControlError>
    where
        P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
    {
        let outcome = ownership.restore_or_contain_firmware_auto(&device);
        emit_safing_outcome_diagnostics(&outcome);
        match outcome {
            FirmwareAutoSafingOutcome::Restored => {
                self.state = Some(ControlState::Recovering(Box::new(RecoveryState {
                    config,
                    device,
                    gate: FreshSampleGate::new(),
                    sources: None,
                })));
                drop(sources);
                Ok(SensorControlStep::FirmwareAutoRestored { fault })
            }
            FirmwareAutoSafingOutcome::Contained {
                restoration,
                containment,
            } => {
                emit_state_transition(
                    RuntimeState::FirmwareAuto,
                    RuntimeState::FaultLatched,
                    RuntimeTransition::RestorationFailed,
                );
                drop(sources);
                self.state = Some(ControlState::Faulted {
                    retained_sources: None,
                });
                Err(TransientSensorControlError::RecoveryLatchContained {
                    fault,
                    restoration: Box::new(restoration),
                    containment: Box::new(containment),
                })
            }
            FirmwareAutoSafingOutcome::Critical {
                restoration,
                containment,
            } => {
                self.state = Some(ControlState::Faulted {
                    retained_sources: Some(sources),
                });
                Err(TransientSensorControlError::RecoveryLatchCritical {
                    fault,
                    restoration,
                    containment: Box::new(containment),
                })
            }
        }
    }

    fn latch_control_fault<P>(
        &mut self,
        ownership: &mut ControllerOwnership<'_, P>,
        device: AcerHwmonDevice,
        fault: HealthyControlCycleError,
        sources: D::Sources,
    ) -> Result<SensorControlStep, TransientSensorControlError>
    where
        P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
    {
        let outcome = ownership.restore_or_contain_firmware_auto(&device);
        emit_safing_outcome_diagnostics(&outcome);
        match outcome {
            FirmwareAutoSafingOutcome::Restored => {
                emit_state_transition(
                    RuntimeState::FirmwareAuto,
                    RuntimeState::FaultLatched,
                    RuntimeTransition::ControlFault,
                );
                drop(sources);
                self.state = Some(ControlState::Faulted {
                    retained_sources: None,
                });
                Err(TransientSensorControlError::ControlLatched { fault })
            }
            FirmwareAutoSafingOutcome::Contained {
                restoration,
                containment,
            } => {
                emit_state_transition(
                    RuntimeState::FirmwareAuto,
                    RuntimeState::FaultLatched,
                    RuntimeTransition::ControlFault,
                );
                drop(sources);
                self.state = Some(ControlState::Faulted {
                    retained_sources: None,
                });
                Err(TransientSensorControlError::ControlLatchContained {
                    fault,
                    restoration: Box::new(restoration),
                    containment: Box::new(containment),
                })
            }
            FirmwareAutoSafingOutcome::Critical {
                restoration,
                containment,
            } => {
                self.state = Some(ControlState::Faulted {
                    retained_sources: Some(sources),
                });
                Err(TransientSensorControlError::ControlLatchCritical {
                    fault,
                    restoration: Box::new(restoration),
                    containment: Box::new(containment),
                })
            }
        }
    }

    fn latch_recovery_fault<P>(
        &mut self,
        ownership: &mut ControllerOwnership<'_, P>,
        device: AcerHwmonDevice,
        fault: SampleSetError,
        sources: Option<D::Sources>,
    ) -> Result<SensorControlStep, TransientSensorControlError>
    where
        P: BoundedIdentityBoundFileAccess + Clock + RuntimeLockAccess,
    {
        let outcome = ownership.restore_or_contain_firmware_auto(&device);
        emit_safing_outcome_diagnostics(&outcome);
        match outcome {
            FirmwareAutoSafingOutcome::Restored => {
                emit_state_transition(
                    RuntimeState::FirmwareAuto,
                    RuntimeState::FaultLatched,
                    RuntimeTransition::ControlFault,
                );
                drop(sources);
                self.state = Some(ControlState::Faulted {
                    retained_sources: None,
                });
                Err(TransientSensorControlError::RecoveryLatched { fault })
            }
            FirmwareAutoSafingOutcome::Contained {
                restoration,
                containment,
            } => {
                emit_state_transition(
                    RuntimeState::FirmwareAuto,
                    RuntimeState::FaultLatched,
                    RuntimeTransition::ControlFault,
                );
                drop(sources);
                self.state = Some(ControlState::Faulted {
                    retained_sources: None,
                });
                Err(TransientSensorControlError::RecoveryLatchContained {
                    fault,
                    restoration: Box::new(restoration),
                    containment: Box::new(containment),
                })
            }
            FirmwareAutoSafingOutcome::Critical {
                restoration,
                containment,
            } => {
                self.state = Some(ControlState::Faulted {
                    retained_sources: sources,
                });
                Err(TransientSensorControlError::RecoveryLatchCritical {
                    fault,
                    restoration,
                    containment: Box::new(containment),
                })
            }
        }
    }
}

fn emit_safing_outcome_diagnostics(outcome: &FirmwareAutoSafingOutcome) {
    match outcome {
        FirmwareAutoSafingOutcome::Restored | FirmwareAutoSafingOutcome::Contained { .. } => {
            emit_state_transition(
                RuntimeState::Restoring,
                RuntimeState::FirmwareAuto,
                RuntimeTransition::RestorationConfirmed,
            );
        }
        FirmwareAutoSafingOutcome::Critical { .. } => {
            emit_fault(RuntimeFault::ContainmentUnconfirmed, None);
            emit_state_transition(
                RuntimeState::Restoring,
                RuntimeState::FaultLatched,
                RuntimeTransition::RestorationFailed,
            );
        }
    }
}

fn recoverable_sensor_cycle_fault(error: &HealthyControlCycleError) -> Option<&SampleSetError> {
    let HealthyControlCycleError::Sample(fault) = error else {
        return None;
    };
    recoverable_sensor_sample_fault(fault).then_some(fault)
}

fn recoverable_sensor_sample_fault(fault: &SampleSetError) -> bool {
    match fault {
        SampleSetError::Input { input, .. }
        | SampleSetError::Stale { input }
        | SampleSetError::Future { input }
        | SampleSetError::Late { input } => {
            matches!(input, RequiredInput::Cpu | RequiredInput::Gpu)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::recoverable_sensor_sample_fault;
    use crate::{RequiredInput, SampleSetError, SampleSourceError};

    #[test]
    fn only_cpu_and_gpu_input_freshness_faults_are_automatically_recoverable() {
        let source = || SampleSourceError::new("unavailable");
        for input in [RequiredInput::Cpu, RequiredInput::Gpu] {
            assert!(recoverable_sensor_sample_fault(&SampleSetError::Input {
                input,
                source: source(),
            }));
            assert!(recoverable_sensor_sample_fault(&SampleSetError::Stale {
                input
            }));
            assert!(recoverable_sensor_sample_fault(&SampleSetError::Future {
                input
            }));
            assert!(recoverable_sensor_sample_fault(&SampleSetError::Late {
                input
            }));
        }

        assert!(!recoverable_sensor_sample_fault(&SampleSetError::Input {
            input: RequiredInput::Power,
            source: source(),
        }));
        assert!(!recoverable_sensor_sample_fault(
            &SampleSetError::FirmwareAutoUnconfirmed
        ));
        assert!(!recoverable_sensor_sample_fault(
            &SampleSetError::ClockWentBackwards
        ));
        assert!(!recoverable_sensor_sample_fault(
            &SampleSetError::DeadlineOverflow
        ));
        assert!(!recoverable_sensor_sample_fault(
            &SampleSetError::CaptureCycleOverflow
        ));
        assert!(!recoverable_sensor_sample_fault(
            &SampleSetError::CadenceMissed {
                expected_at: Duration::ZERO,
                observed_at: Duration::from_secs(3),
            }
        ));
    }
}
