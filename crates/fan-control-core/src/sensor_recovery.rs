use std::{error::Error, fmt};

use crate::{
    AcerHwmonDevice, AdmittedPolicyAuthority, BoundedIdentityBoundFileAccess, Clock,
    CompletedControlCycle, ControllerOwnership, EmergencyContainmentReport, FanArmingError,
    FirmwareAutoRestorationError, FreshSampleGate, HealthyControl, HealthyControlCycleError,
    IdentityBoundReadAccess, OwnershipSampleReadiness, RequiredInput, RuntimeLockAccess,
    SampleSetError, SampleSourceError, SampleSources, ValidatedConfig, arm_both_fans_safely,
    run_healthy_control_cycle,
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
    RecoverySample(SampleSetError),
    RestorationFailed {
        fault: SampleSetError,
        source: FirmwareAutoRestorationError,
    },
    Rearming(FanArmingError),
}

impl fmt::Display for TransientSensorControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Faulted => formatter.write_str("sensor recovery control is faulted"),
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
            Self::RecoverySample(error) => {
                write!(
                    formatter,
                    "non-recoverable recovery sample failure: {error}"
                )
            }
            Self::RestorationFailed { fault, source } => write!(
                formatter,
                "sensor fault ({fault}) could not restore Firmware Auto: {source}"
            ),
            Self::Rearming(error) => write!(formatter, "sensor recovery rearming failed: {error}"),
        }
    }
}

impl Error for TransientSensorControlError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Faulted => None,
            Self::ControlLatched { fault }
            | Self::ControlLatchContained { fault, .. }
            | Self::ControlLatchCritical { fault, .. } => Some(fault),
            Self::RecoverySample(error) => Some(error),
            Self::RestorationFailed { source, .. } => Some(source),
            Self::Rearming(error) => Some(error),
        }
    }
}

#[derive(Debug)]
enum ControlState<S> {
    Custom {
        control: HealthyControl,
        sources: S,
    },
    Recovering {
        config: ValidatedConfig,
        device: AcerHwmonDevice,
        gate: FreshSampleGate,
        sources: Option<S>,
    },
    Faulted {
        retained_sources: Option<S>,
    },
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
    state: Option<ControlState<D::Sources>>,
}

impl<D> TransientSensorControl<D>
where
    D: SensorSourceDiscovery,
{
    pub fn from_armed(
        armed: crate::ArmedFanControl,
        authority: AdmittedPolicyAuthority,
        discovery: D,
        sources: D::Sources,
    ) -> Self {
        Self {
            authority,
            discovery,
            state: Some(ControlState::Custom {
                control: HealthyControl::from_armed(armed),
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
            ControlState::Recovering { .. } => SensorControlState::FirmwareAutoRecovery,
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
                Err(error) => {
                    let Some(fault) = recoverable_sensor_cycle_fault(&error).cloned() else {
                        let (_, device) = control.into_recovery_parts();
                        return self.latch_control_fault(ownership, device, error, sources);
                    };
                    let (config, device) = control.into_recovery_parts();
                    self.restore_for_recovery(ownership, config, device, fault, sources)
                }
            },
            ControlState::Recovering {
                config,
                device,
                mut gate,
                mut sources,
            } => {
                if sources.is_none() {
                    if !ownership.refresh_firmware_auto_confirmation(&device)
                        && let Err(source) = ownership.restore_firmware_auto(&device)
                    {
                        self.state = Some(ControlState::Faulted {
                            retained_sources: None,
                        });
                        return Err(TransientSensorControlError::RestorationFailed {
                            fault: SampleSetError::FirmwareAutoUnconfirmed,
                            source,
                        });
                    }
                    match self.discovery.rediscover(ownership.platform_mut()) {
                        Ok(rediscovered) => {
                            gate.reset();
                            sources = Some(rediscovered);
                        }
                        Err(source) => {
                            self.state = Some(ControlState::Recovering {
                                config,
                                device,
                                gate,
                                sources: None,
                            });
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
                        self.state = Some(ControlState::Recovering {
                            config,
                            device,
                            gate,
                            sources,
                        });
                        Ok(SensorControlStep::AwaitingSecondSample)
                    }
                    Ok(OwnershipSampleReadiness::Ready(sample)) => {
                        match arm_both_fans_safely(
                            ownership,
                            &device,
                            &self.authority,
                            &config,
                            sample,
                        ) {
                            Ok(armed) => {
                                self.state = Some(ControlState::Custom {
                                    control: HealthyControl::from_armed(armed),
                                    sources: sources
                                        .expect("ready sample was captured from installed sources"),
                                });
                                Ok(SensorControlStep::Rearmed)
                            }
                            Err(error) => {
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
                    Err(fault) if recoverable_sensor_sample_fault(&fault) => self
                        .restore_for_recovery(
                            ownership,
                            config,
                            device,
                            fault,
                            sources.expect("sample failure requires installed sources"),
                        ),
                    Err(fault) => {
                        let retained_sources =
                            if matches!(&fault, SampleSetError::FirmwareAutoUnconfirmed) {
                                sources
                            } else {
                                drop(sources);
                                None
                            };
                        self.state = Some(ControlState::Faulted { retained_sources });
                        Err(TransientSensorControlError::RecoverySample(fault))
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
        match ownership.restore_firmware_auto(&device) {
            Ok(()) => {
                self.state = Some(ControlState::Recovering {
                    config,
                    device,
                    gate: FreshSampleGate::new(),
                    sources: None,
                });
                drop(sources);
                Ok(SensorControlStep::FirmwareAutoRestored { fault })
            }
            Err(source) => {
                self.state = Some(ControlState::Faulted {
                    retained_sources: Some(sources),
                });
                Err(TransientSensorControlError::RestorationFailed { fault, source })
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
        match ownership.restore_firmware_auto(&device) {
            Ok(()) => {
                drop(sources);
                self.state = Some(ControlState::Faulted {
                    retained_sources: None,
                });
                Err(TransientSensorControlError::ControlLatched { fault })
            }
            Err(restoration) => {
                let containment = ownership.contain_custom_fans_at_maximum(&device);
                if containment.restoration_confirmed() {
                    drop(sources);
                    self.state = Some(ControlState::Faulted {
                        retained_sources: None,
                    });
                    Err(TransientSensorControlError::ControlLatchContained {
                        fault,
                        restoration: Box::new(restoration),
                        containment: Box::new(containment),
                    })
                } else {
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
