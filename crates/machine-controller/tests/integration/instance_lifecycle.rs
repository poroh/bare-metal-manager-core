/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::time::Duration;

use carbide_redfish::libredfish::test_support::RedfishSimAction;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::{
    FixtureDefault as _, ManagedHostConfigExt as _,
};
use carbide_test_harness::test_support::network_segment::FIXTURE_TENANT_ORG_ID;
use carbide_uuid::vpc::VpcId;
use futures::future::join_all;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::instance::config::network::{DeviceLocator, InstanceNetworkConfig};
use model::machine::{InstanceState, ManagedHostState};
use model::test_support::ManagedHostConfig;
use rpc::forge::{InstanceAllocationRequest, InstanceReleaseRequest, VpcCreationRequest};
use tonic::{IntoRequest, Request};

use crate::env::Env;
use crate::instance_common::*;

#[sqlx_test]
async fn test_allocate_and_release_instance_one_dpu(pool: PgPool) {
    test_allocate_and_release_instance_impl(pool, 1, 1).await
}

#[sqlx_test]
async fn test_allocate_and_release_instance_one_of_two_dpus(pool: PgPool) {
    test_allocate_and_release_instance_impl(pool, 2, 1).await
}

#[sqlx_test]
async fn test_allocate_and_release_instance_two_of_two_dpus(pool: PgPool) {
    test_allocate_and_release_instance_impl(pool, 2, 2).await
}

#[sqlx_test]
async fn test_allocate_and_release_instance_two_of_three_dpus(pool: PgPool) {
    test_allocate_and_release_instance_impl(pool, 3, 2).await
}

async fn test_allocate_and_release_instance_impl(
    pool: PgPool,
    dpu_count: usize,
    instance_interface_count: usize,
) {
    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .build()
        .await;
    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();

    let segment_ids = create_tenant_segments(
        harness,
        &network_controller,
        &boot.domain,
        default_vpc_config(),
        dpu_count,
    )
    .await;

    let vpc_ids: Vec<VpcId> = join_all(segment_ids.iter().map(|id| {
        let pool = harness.api().database_connection.clone();
        async move {
            db::vpc::find_by_segment(&pool, *id)
                .await
                .map(|vpc| vpc.expect("missing VPC for created segment").id)
        }
    }))
    .await
    .into_iter()
    .collect::<Result<_, _>>()
    .unwrap();

    let mh = create_ready_host(
        harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default().with_dpu_count(dpu_count),
    )
    .await;

    let dpu_ids = mh.dpu_ids();
    let (used_dpu_ids, _unused_dpu_ids) = dpu_ids.split_at(instance_interface_count);

    let mut txn = harness.db_txn().await;
    for segment_id in &segment_ids {
        assert_eq!(
            db::instance_address::count_by_segment_id(&mut txn, segment_id)
                .await
                .unwrap(),
            0
        );
    }
    let host_machine = mh.host.db_machine(&mut txn).await;

    let mut device_locators = Vec::default();
    for dpu_machine_id in used_dpu_ids {
        device_locators.push(
            host_machine
                .get_device_locator_for_dpu_id(dpu_machine_id)
                .unwrap(),
        );
    }

    assert!(matches!(
        host_machine.current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

    let tinstance = mh
        .instance_builder(harness)
        .network(interface_network_config_with_devices(
            &segment_ids,
            &device_locators,
        ))
        .build()
        .await;
    Box::pin(advance_instance_to_ready(
        &env,
        &network_controller,
        &mh,
        &tinstance,
    ))
    .await;

    let instance = tinstance.rpc_instance().await;

    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .tenant
            .as_ref()
            .unwrap()
            .state(),
        rpc::forge::TenantState::Ready
    );

    let tenant_config = instance.config.as_ref().unwrap().tenant.as_ref().unwrap();
    let expected_os = default_os_config();
    let os = instance.config.as_ref().unwrap().os.as_ref().unwrap();
    assert_eq!(os, &expected_os);

    let expected_tenant_config = default_tenant_config();
    assert_eq!(tenant_config, &expected_tenant_config);

    let mut txn = harness.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;

    let fetched_instance = snapshot.instance.unwrap();
    assert_eq!(&fetched_instance.machine_id, &mh.host.id);
    for (segment_index, segment_id) in segment_ids.iter().enumerate() {
        let expected_count = if segment_index < instance_interface_count {
            1
        } else {
            0
        };
        assert_eq!(
            db::instance_address::count_by_segment_id(&mut txn, segment_id)
                .await
                .unwrap(),
            expected_count
        );
    }
    let network_config = fetched_instance.config.network.clone();
    assert_eq!(fetched_instance.network_config_version.version_nr(), 1);
    let mut network_config_no_addresses = network_config.clone();
    for iface in network_config_no_addresses.interfaces.iter_mut() {
        assert_eq!(iface.ip_addrs.len(), 1);
        assert_eq!(iface.interface_prefixes.len(), 1);
        iface.ip_addrs.clear();
        iface.interface_prefixes.clear();
        iface.network_segment_gateways.clear();
        iface.internal_uuid = uuid::Uuid::nil();
    }
    assert_eq!(
        network_config_no_addresses,
        InstanceNetworkConfig::for_segment_ids(&segment_ids, &device_locators, &vpc_ids)
    );

    assert!(!fetched_instance.observations.network.is_empty());
    assert!(fetched_instance.use_custom_pxe_on_boot);

    let _ = db::instance::use_custom_ipxe_on_next_boot(&mh.host.id, false, &mut txn).await;
    let snapshot = mh.snapshot(&mut txn).await;
    let fetched_instance = snapshot.instance.unwrap();
    txn.commit().await.unwrap();

    let mut txn = harness.db_txn().await;
    // TODO: The MAC here doesn't matter. It's not used for lookup
    let records = db::instance_address::find_all_by_instance_id_and_segment_id(
        &mut txn,
        &fetched_instance.id,
        segment_ids.first().unwrap(),
    )
    .await
    .unwrap();
    let [record] = records.as_slice() else {
        panic!("expected one address on the first segment")
    };

    // This should the first IP. Algo does not look into machine_interface_addresses
    // table for used addresses for instance.
    assert_eq!(record.address.to_string(), "192.0.4.3");
    assert_eq!(
        &record.address,
        network_config.interfaces[0]
            .ip_addrs
            .iter()
            .next()
            .unwrap()
            .1
    );

    assert_eq!(
        format!("{}/32", record.address),
        network_config.interfaces[0]
            .interface_prefixes
            .iter()
            .next()
            .unwrap()
            .1
            .to_string()
    );

    assert!(matches!(
        mh.host.db_machine(&mut txn).await.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.commit().await.unwrap();

    delete_instance(&env, &network_controller, &mh, tinstance.id).await;

    // Address is freed during delete
    let mut txn = harness.db_txn().await;
    assert!(matches!(
        mh.host.db_machine(&mut txn).await.current_state(),
        ManagedHostState::Ready
    ));
    for segment_id in &segment_ids {
        assert_eq!(
            db::instance_address::count_by_segment_id(&mut txn, segment_id)
                .await
                .unwrap(),
            0
        );
    }
    txn.commit().await.unwrap();
}

#[sqlx_test]
async fn test_instance_deletion_before_provisioning_finishes(pool: PgPool) {
    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .build()
        .await;
    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();

    let segment_id = create_tenant_segments(
        harness,
        &network_controller,
        &boot.domain,
        default_vpc_config(),
        1,
    )
    .await[0];
    let mh = create_ready_host(harness, &site_explorer, &boot, ManagedHostConfig::default()).await;

    // Create an instance in non-ready state
    let config = rpc::InstanceConfig {
        network: Some(single_interface_network_config(segment_id)),
        ..default_instance_config()
    };

    let instance = harness
        .api()
        .allocate_instance(
            InstanceAllocationRequest::builder(false)
                .machine_id(host_id(&mh))
                .config(config)
                .metadata(rpc::Metadata {
                    name: "test_instance".to_string(),
                    description: "tests/instance".to_string(),
                    labels: Vec::new(),
                })
                .tonic_request(),
        )
        .await
        .expect("Create instance failed.")
        .into_inner();
    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .tenant
            .as_ref()
            .unwrap()
            .state(),
        rpc::TenantState::Provisioning
    );

    let instance_id = instance.id.expect("Missing instance ID");

    // Stop provisioning at the point that normally requires a DPU network-status
    // observation. Releasing here must not wait for that observation.
    network_controller.run_single_iteration().await;
    until(
        &env,
        &mh.host.id,
        10,
        ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForNetworkConfig,
        },
    )
    .await;

    harness
        .api()
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id),
            issue: None,
            is_repair_tenant: None,
            delete_attribution: None,
        }))
        .await
        .expect("Delete instance failed.");

    let instance = find_instance(harness, instance_id).await;
    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .tenant
            .as_ref()
            .unwrap()
            .state(),
        rpc::TenantState::Terminating
    );

    until(
        &env,
        &mh.host.id,
        1,
        ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForRebootToReady,
        },
    )
    .await;

    // Now go through regular deletion
    delete_instance(&env, &network_controller, &mh, instance_id).await;
}

#[sqlx_test]
async fn test_instance_waits_for_primary_dpu_bgp_before_pxe_reboot(pool: PgPool) {
    const PRIMARY_DPU_BGP_WAIT_REASON: &str =
        "Waiting for the primary DPU p0 BGP session to be established";
    const HOST_HEALTH_WAIT_REASON: &str =
        "Waiting for lifecycle-blocking host health alerts to clear before PXE reboot";

    fn dpu_health_alert(
        id: &str,
        target: Option<&str>,
        classifications: Vec<health_report::HealthAlertClassification>,
    ) -> rpc::health::HealthReport {
        rpc::health::HealthReport {
            source: "forge-dpu-agent".to_string(),
            triggered_by: None,
            observed_at: None,
            successes: vec![],
            alerts: vec![rpc::health::HealthProbeAlert {
                id: id.to_string(),
                target: target.map(str::to_string),
                in_alert_since: None,
                message: "test lifecycle gate".to_string(),
                tenant_message: None,
                classifications: classifications
                    .into_iter()
                    .map(|classification| classification.to_string())
                    .collect(),
            }],
        }
    }

    fn post_config_wait_health() -> rpc::health::HealthReport {
        dpu_health_alert(
            health_report::HealthProbeId::post_config_check_wait().as_str(),
            None,
            vec![
                health_report::HealthAlertClassification::prevent_allocations(),
                health_report::HealthAlertClassification::prevent_host_state_changes(),
            ],
        )
    }

    fn bgp_tor_health(target: &str, prevent_allocations: bool) -> rpc::health::HealthReport {
        let classifications = prevent_allocations
            .then(health_report::HealthAlertClassification::prevent_allocations)
            .into_iter()
            .collect();
        dpu_health_alert(
            health_report::HealthProbeId::bgp_peering_tor().as_str(),
            Some(target),
            classifications,
        )
    }

    fn pxe_blocking_bgp_merge(source: &str) -> health_report::HealthReport {
        health_report::HealthReport {
            source: source.to_string(),
            triggered_by: None,
            observed_at: None,
            successes: vec![],
            alerts: vec![health_report::HealthProbeAlert {
                id: health_report::HealthProbeId::bgp_peering_tor(),
                target: Some("p0_if".to_string()),
                in_alert_since: None,
                message: "test additive PXE gate".to_string(),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_allocations(),
                ],
            }],
        }
    }

    async fn assert_instance_state(env: &Env, mh: &TestManagedHost, expected: InstanceState) {
        let harness = &env.test_harness;
        let mut txn = harness.db_txn().await;
        assert_eq!(
            mh.host.db_machine(&mut txn).await.current_state(),
            &ManagedHostState::Assigned {
                instance_state: expected,
            }
        );
        txn.commit().await.unwrap();
    }

    async fn assert_pxe_reboot_wait_outcome(
        env: &Env,
        mh: &TestManagedHost,
        expected_reason: &str,
    ) {
        let harness = &env.test_harness;
        let mut txn = harness.db_txn().await;
        let host_machine = mh.host.db_machine(&mut txn).await;
        let Some(PersistentStateHandlerOutcome::Wait {
            reason,
            source_ref: Some(source_ref),
        }) = &host_machine.controller_state_outcome
        else {
            panic!("The PXE reboot gate should persist a Wait outcome with a source reference");
        };
        assert_eq!(reason, expected_reason);
        assert!(source_ref.file.ends_with("/handler.rs"));
        txn.commit().await.unwrap();
    }

    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .build()
        .await;
    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();

    let segment_id = create_tenant_segments(
        harness,
        &network_controller,
        &boot.domain,
        default_vpc_config(),
        1,
    )
    .await[0];
    let mh = create_ready_host(harness, &site_explorer, &boot, ManagedHostConfig::default()).await;
    let dpu_id = mh.dpu_ids()[0];

    let config = rpc::InstanceConfig {
        network: Some(single_interface_network_config(segment_id)),
        ..default_instance_config()
    };
    harness
        .api()
        .allocate_instance(
            InstanceAllocationRequest::builder(false)
                .machine_id(host_id(&mh))
                .config(config)
                .metadata(rpc::Metadata {
                    name: "test_instance".to_string(),
                    description: "tests/instance".to_string(),
                    labels: Vec::new(),
                })
                .tonic_request(),
        )
        .await
        .expect("Create instance failed.");

    network_controller.run_single_iteration().await;
    until(
        &env,
        &mh.host.id,
        10,
        ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForNetworkConfig,
        },
    )
    .await;

    // Both the configuration settle period and a failed p0 session hold the
    // initial network configuration gate.
    {
        let status = mh
            .dpus
            .iter()
            .find(|dpu| dpu.id == dpu_id)
            .unwrap()
            .network_status()
            .dpu_agent_version("test")
            .dpu_health(post_config_wait_health())
            .build()
            .await;
        harness
            .api()
            .record_dpu_network_status(status.into_request())
            .await
            .unwrap();
    }
    env.run_single_iteration_ext(true).await;
    assert_instance_state(&env, &mh, InstanceState::WaitingForNetworkConfig).await;

    {
        let status = mh
            .dpus
            .iter()
            .find(|dpu| dpu.id == dpu_id)
            .unwrap()
            .network_status()
            .dpu_agent_version("test")
            .dpu_health(bgp_tor_health("p0_if", true))
            .build()
            .await;
        harness
            .api()
            .record_dpu_network_status(status.into_request())
            .await
            .unwrap();
    }
    env.run_single_iteration_ext(true).await;
    assert_instance_state(&env, &mh, InstanceState::WaitingForNetworkConfig).await;

    // An empty DPU Replace report masks the agent Merge report and allows
    // provisioning to advance to the reboot gate.
    send_health_report_entry(
        harness,
        &dpu_id,
        (
            health_report::HealthReport::empty("test-pxe-bgp-override".to_string()),
            health_report::HealthReportApplyMode::Replace,
        ),
    )
    .await;
    until(
        &env,
        &mh.host.id,
        1,
        ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForRebootToReady,
        },
    )
    .await;

    // Removing the Replace report exposes the agent p0 alert again, so the
    // reboot gate must recheck it before restarting the host.
    remove_health_report_entry(harness, &dpu_id, "test-pxe-bgp-override".to_string()).await;
    env.run_single_iteration_ext(true).await;
    assert_instance_state(&env, &mh, InstanceState::WaitingForRebootToReady).await;
    assert_pxe_reboot_wait_outcome(&env, &mh, PRIMARY_DPU_BGP_WAIT_REASON).await;

    // The reboot gate also rechecks health alerts that block host state
    // changes and persists a diagnosable wait reason.
    {
        let status = mh
            .dpus
            .iter()
            .find(|dpu| dpu.id == dpu_id)
            .unwrap()
            .network_status()
            .dpu_agent_version("test")
            .dpu_health(post_config_wait_health())
            .build()
            .await;
        harness
            .api()
            .record_dpu_network_status(status.into_request())
            .await
            .unwrap();
    }
    env.run_single_iteration_ext(true).await;
    assert_instance_state(&env, &mh, InstanceState::WaitingForRebootToReady).await;
    assert_pxe_reboot_wait_outcome(&env, &mh, HOST_HEALTH_WAIT_REASON).await;

    // A visible p1 alert permits reboot, but an additional primary DPU Merge
    // report that carries the p0 classification still blocks it.
    {
        let status = mh
            .dpus
            .iter()
            .find(|dpu| dpu.id == dpu_id)
            .unwrap()
            .network_status()
            .dpu_agent_version("test")
            .dpu_health(bgp_tor_health("p1_if", false))
            .build()
            .await;
        harness
            .api()
            .record_dpu_network_status(status.into_request())
            .await
            .unwrap();
    }
    send_health_report_entry(
        harness,
        &dpu_id,
        (
            pxe_blocking_bgp_merge("test-pxe-bgp-merge"),
            health_report::HealthReportApplyMode::Merge,
        ),
    )
    .await;
    env.run_single_iteration_ext(true).await;
    assert_instance_state(&env, &mh, InstanceState::WaitingForRebootToReady).await;

    // Clearing the last PXE blocking Merge report lets provisioning reach Ready.
    remove_health_report_entry(harness, &dpu_id, "test-pxe-bgp-merge".to_string()).await;
    until(
        &env,
        &mh.host.id,
        1,
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready,
        },
    )
    .await;
}

#[sqlx_test]
async fn test_instance_release_waits_for_primary_dpu_network_health_before_discovery_reboot(
    pool: PgPool,
) {
    const DPU_NETWORK_READY_WAIT_REASON: &str =
        "Waiting for the primary DPU network to become ready before PXE reboot";

    fn agent_health(alert_id: Option<health_report::HealthProbeId>) -> rpc::health::HealthReport {
        rpc::health::HealthReport {
            source: "forge-dpu-agent".to_string(),
            triggered_by: None,
            observed_at: None,
            successes: vec![],
            alerts: alert_id
                .map(|id| rpc::health::HealthProbeAlert {
                    id: id.to_string(),
                    target: None,
                    in_alert_since: None,
                    message: "test primary DPU network health".to_string(),
                    tenant_message: None,
                    classifications: vec![
                        health_report::HealthAlertClassification::prevent_allocations().to_string(),
                        health_report::HealthAlertClassification::prevent_host_state_changes()
                            .to_string(),
                    ],
                })
                .into_iter()
                .collect(),
        }
    }

    async fn assert_release_is_waiting(env: &Env, mh: &TestManagedHost, scenario: &str) {
        let harness = &env.test_harness;
        let mut txn = harness.db_txn().await;
        let host = mh.host.db_machine(&mut txn).await;
        assert_eq!(
            host.current_state(),
            &ManagedHostState::Assigned {
                instance_state: InstanceState::WaitingForDpusToUp,
            },
            "{scenario}",
        );
        let Some(PersistentStateHandlerOutcome::Wait { reason, .. }) =
            &host.controller_state_outcome
        else {
            panic!("{scenario}: release gate should persist a Wait outcome");
        };
        assert_eq!(reason, DPU_NETWORK_READY_WAIT_REASON, "{scenario}");
        txn.commit().await.unwrap();
    }

    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .build()
        .await;
    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();

    let segment_id = create_tenant_segments(
        harness,
        &network_controller,
        &boot.domain,
        default_vpc_config(),
        1,
    )
    .await[0];
    let mh = create_ready_host(harness, &site_explorer, &boot, ManagedHostConfig::default()).await;
    let instance = mh
        .instance_builder(harness)
        .single_interface_network_config(segment_id)
        .build()
        .await;
    Box::pin(advance_instance_to_ready(
        &env,
        &network_controller,
        &mh,
        &instance,
    ))
    .await;

    harness
        .api()
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance.id),
            issue: None,
            is_repair_tenant: None,
            delete_attribution: None,
        }))
        .await
        .expect("Delete instance failed.");

    let mut txn = harness.db_txn().await;
    db::machine::update_state(
        &mut txn,
        &mh.host.id,
        &ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForDpusToUp,
        },
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    let redfish_checkpoint = env.redfish_sim.timepoint();
    {
        let status = mh
            .dpus
            .iter()
            .find(|dpu| dpu.id == mh.dpu_ids()[0])
            .unwrap()
            .network_status()
            .dpu_agent_version("test")
            .dpu_health(agent_health(Some(
                health_report::HealthProbeId::nvue_api_running(),
            )))
            .build()
            .await;
        harness
            .api()
            .record_dpu_network_status(status.into_request())
            .await
            .unwrap();
    }
    env.run_single_iteration_ext(true).await;
    assert_release_is_waiting(&env, &mh, "NVUE API is unavailable").await;

    let power_actions = env
        .redfish_sim
        .actions_since(&redfish_checkpoint)
        .all_hosts()
        .into_iter()
        .filter(|action| matches!(action, RedfishSimAction::Power(_)))
        .collect::<Vec<_>>();
    assert!(
        power_actions.is_empty(),
        "release must not reboot the host before primary DPU network health is ready: {power_actions:?}",
    );

    {
        let status = mh
            .dpus
            .iter()
            .find(|dpu| dpu.id == mh.dpu_ids()[0])
            .unwrap()
            .network_status()
            .dpu_agent_version("test")
            .dpu_health(agent_health(None))
            .build()
            .await;
        harness
            .api()
            .record_dpu_network_status(status.into_request())
            .await
            .unwrap();
    }
    env.run_single_iteration_ext(true).await;

    let mut txn = harness.db_txn().await;
    assert_eq!(
        mh.host.db_machine(&mut txn).await.current_state(),
        &ManagedHostState::Assigned {
            instance_state: InstanceState::BootingWithDiscoveryImage {
                retry: model::machine::RetryInfo { count: 0 },
            },
        }
    );
    txn.commit().await.unwrap();

    let power_actions = env
        .redfish_sim
        .actions_since(&redfish_checkpoint)
        .all_hosts()
        .into_iter()
        .filter(|action| matches!(action, RedfishSimAction::Power(_)))
        .collect::<Vec<_>>();
    assert_eq!(
        power_actions,
        vec![RedfishSimAction::Power(
            libredfish::SystemPowerControl::ForceRestart,
        )],
    );
}

#[sqlx_test]
async fn test_bootingwithdiscoveryimage_delay(pool: PgPool) {
    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .build()
        .await;
    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();

    let segment_id = create_tenant_segments(
        harness,
        &network_controller,
        &boot.domain,
        default_vpc_config(),
        1,
    )
    .await[0];
    let mh = create_ready_host(harness, &site_explorer, &boot, ManagedHostConfig::default()).await;

    let tinstance = mh
        .instance_builder(harness)
        .single_interface_network_config(segment_id)
        .build()
        .await;
    Box::pin(advance_instance_to_ready(
        &env,
        &network_controller,
        &mh,
        &tinstance,
    ))
    .await;

    harness
        .api()
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(tinstance.id),
            issue: None,
            is_repair_tenant: None,
            delete_attribution: None,
        }))
        .await
        .expect("Delete instance failed.");

    until(
        &env,
        &mh.host.id,
        8,
        ManagedHostState::Assigned {
            instance_state: model::machine::InstanceState::HostPlatformConfiguration {
                platform_config_state:
                    model::machine::HostPlatformConfigurationState::CheckHostConfig,
            },
        },
    )
    .await;

    report_network(&mh).await;

    until(
        &env,
        &mh.host.id,
        2,
        ManagedHostState::Assigned {
            instance_state: model::machine::InstanceState::WaitingForDpusToUp,
        },
    )
    .await;

    report_network(&mh).await;

    until(
        &env,
        &mh.host.id,
        1,
        ManagedHostState::Assigned {
            instance_state: model::machine::InstanceState::BootingWithDiscoveryImage {
                retry: model::machine::RetryInfo { count: 0 },
            },
        },
    )
    .await;

    assert!(
        harness
            .test_meter
            .formatted_metric("carbide_reboot_attempts_in_booting_with_discovery_image_count")
            .is_none(),
        "State is not changed. The reboot counter should only increased once state changed"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;

    let mut txn = harness.db_txn().await;
    let host = mh.host.db_machine(&mut txn).await;
    txn.commit().await.unwrap();

    update_time_params(&harness.api().database_connection, &host, 1, None).await;
    until(
        &env,
        &mh.host.id,
        1,
        ManagedHostState::Assigned {
            instance_state: model::machine::InstanceState::BootingWithDiscoveryImage {
                retry: model::machine::RetryInfo { count: 1 },
            },
        },
    )
    .await;

    assert!(
        harness
            .test_meter
            .formatted_metric("carbide_reboot_attempts_in_booting_with_discovery_image_count")
            .is_none(),
        "State is not changed. The reboot counter should only increased once state changed"
    );

    finish_cleanup(&env, &mh).await;

    assert_eq!(
        harness
            .test_meter
            .formatted_metric("carbide_reboot_attempts_in_booting_with_discovery_image_sum")
            .unwrap(),
        "2"
    );
    assert_eq!(
        harness
            .test_meter
            .formatted_metric("carbide_reboot_attempts_in_booting_with_discovery_image_count")
            .unwrap(),
        "1"
    );
}

#[sqlx_test]
async fn initial_network_wait_keeps_admin_until_tenant_configuration_is_ready(pool: PgPool) {
    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .configure_runtime(|config| {
            config.dpu_config.restart_ovs_on_use_admin_network_change = true;
            config.fnn = Some(fnn_config());
        })
        .build()
        .await;

    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();
    create_fixture_tenant(harness, FIXTURE_TENANT_ORG_ID)
        .await
        .unwrap();
    let vpc_id = harness
        .api()
        .create_vpc(
            VpcCreationRequest::builder(FIXTURE_TENANT_ORG_ID)
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner()
        .id
        .unwrap();
    let prefix_id = create_tenant_overlay_prefix(harness, vpc_id).await;

    struct Case {
        scenario: &'static str,
        predecessor_selected_tenant: bool,
    }
    for Case {
        scenario,
        predecessor_selected_tenant,
    } in [
        Case {
            scenario: "new allocation",
            predecessor_selected_tenant: false,
        },
        Case {
            scenario: "predecessor selected tenant before network readiness",
            predecessor_selected_tenant: true,
        },
    ] {
        let mh = create_ready_host(
            harness,
            &site_explorer,
            &boot,
            ManagedHostConfig::default().with_dpu_count(2),
        )
        .await;
        harness
            .api()
            .allocate_instance(
                InstanceAllocationRequest::builder(false)
                    .machine_id(host_id(&mh))
                    .config(rpc::InstanceConfig {
                        network: Some(single_interface_network_config_with_vpc_prefix(prefix_id)),
                        ..default_instance_config()
                    })
                    .tonic_request(),
            )
            .await
            .unwrap();
        let waiting = ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForNetworkSegmentToBeReady,
        };
        // Observe each transition once: requeueing can skip this intermediate wait.
        for _ in 0..10 {
            env.run_single_iteration_ext(false).await;
            let mut txn = harness.db_txn().await;
            let state = mh.snapshot(&mut txn).await.managed_state;
            txn.commit().await.unwrap();
            if state == waiting {
                break;
            }
        }

        let mut txn = harness.db_txn().await;
        let snapshot = mh.snapshot(&mut txn).await;
        assert_eq!(
            snapshot.host_snapshot.network_config.use_admin_network,
            Some(true),
            "{scenario}"
        );
        assert_eq!(snapshot.managed_state, waiting, "{scenario}");
        assert!(
            snapshot
                .dpu_snapshots
                .iter()
                .all(|dpu| dpu.network_config.use_admin_network_changed != Some(true)),
            "{scenario}"
        );
        let primary_dpu_id = snapshot
            .host_snapshot
            .status
            .interfaces
            .iter()
            .find(|interface| interface.primary_interface)
            .and_then(|interface| interface.attached_dpu_machine_id)
            .unwrap();
        txn.commit().await.unwrap();
        if predecessor_selected_tenant {
            // The predecessor persisted tenant mode and its restart before entering this wait.
            let mut txn = harness.db_txn().await;
            let snapshot = mh.snapshot(&mut txn).await;
            let mut network = snapshot.host_snapshot.network_config.value.clone();
            network.use_admin_network = Some(false);
            assert_eq!(
                db::machine::try_update_network_config(
                    &mut txn,
                    &mh.host.id.into(),
                    snapshot.host_snapshot.network_config.version,
                    &network,
                )
                .await
                .unwrap(),
                db::ConditionalWrite::Applied(()),
                "{scenario}"
            );
            db::machine::set_use_admin_network_changed(&mut txn, &primary_dpu_id, true)
                .await
                .unwrap();
            txn.commit().await.unwrap();
        }

        let mut admin_responses = Vec::new();
        for dpu_id in &mh.dpu_ids() {
            let response = harness
                .api()
                .get_managed_host_network_config(Request::new(
                    rpc::forge::ManagedHostNetworkConfigRequest {
                        dpu_machine_id: Some(*dpu_id),
                    },
                ))
                .await
                .unwrap()
                .into_inner();
            assert!(response.use_admin_network, "{scenario}");
            assert!(response.admin_interface.is_some(), "{scenario}");
            assert!(response.tenant_interfaces.is_empty(), "{scenario}");
            assert!(
                response.instance_network_config_version.is_empty(),
                "{scenario}"
            );
            assert!(response.vni_device.is_empty(), "{scenario}");
            admin_responses.push((*dpu_id, response));
        }
        // This also consumes the predecessor's early restart acknowledgement.
        report_network(&mh).await;

        env.run_single_iteration_ext(true).await;
        let tenant_wait = ManagedHostState::Assigned {
            instance_state: InstanceState::WaitingForNetworkConfig,
        };
        let mut txn = harness.db_txn().await;
        let snapshot = mh.snapshot(&mut txn).await;
        assert_eq!(snapshot.managed_state, tenant_wait, "{scenario}");
        assert_eq!(
            snapshot.host_snapshot.network_config.use_admin_network,
            Some(false),
            "{scenario}"
        );
        let tenant_version = snapshot.host_snapshot.network_config.version;
        let (_, previous_admin_response) = &admin_responses[0];
        assert_ne!(
            tenant_version.version_string(),
            previous_admin_response.managed_host_config_version,
            "{scenario}"
        );
        for dpu in &snapshot.dpu_snapshots {
            assert_eq!(dpu.network_config.version, tenant_version, "{scenario}");
            assert_eq!(
                dpu.network_config.use_admin_network_changed == Some(true),
                dpu.id == primary_dpu_id,
                "{scenario}"
            );
        }
        txn.commit().await.unwrap();

        for (dpu_id, admin_response) in admin_responses {
            let response = harness
                .api()
                .get_managed_host_network_config(Request::new(
                    rpc::forge::ManagedHostNetworkConfigRequest {
                        dpu_machine_id: Some(dpu_id),
                    },
                ))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                response.use_admin_network,
                dpu_id != primary_dpu_id,
                "{scenario}"
            );
            assert_eq!(
                response.tenant_interfaces.len(),
                usize::from(dpu_id == primary_dpu_id),
                "{scenario}"
            );
            assert_eq!(
                response.instance_network_config_version.is_empty(),
                dpu_id != primary_dpu_id,
                "{scenario}"
            );
            harness
                .api()
                .record_dpu_network_status(Request::new(rpc::forge::DpuNetworkStatus {
                    dpu_machine_id: Some(dpu_id),
                    network_config_version: Some(admin_response.managed_host_config_version),
                    dpu_health: Some(
                        health_report::HealthReport::empty("forge-dpu-agent".to_string()).into(),
                    ),
                    ..Default::default()
                }))
                .await
                .unwrap();
        }
        env.run_single_iteration_ext(true).await;
        let mut txn = harness.db_txn().await;
        let snapshot = mh.snapshot(&mut txn).await;
        assert_eq!(snapshot.managed_state, tenant_wait, "{scenario}");
        assert!(
            matches!(
                &snapshot.host_snapshot.controller_state_outcome,
                Some(PersistentStateHandlerOutcome::Wait { reason, .. })
                    if reason.contains("Waiting for DPU agent(s) to apply network config")
            ),
            "{scenario}"
        );
        assert!(
            snapshot
                .instance
                .as_ref()
                .unwrap()
                .observations
                .network
                .is_empty(),
            "{scenario}"
        );
        assert_eq!(
            snapshot
                .dpu_snapshots
                .iter()
                .find(|dpu| dpu.id == primary_dpu_id)
                .unwrap()
                .network_config
                .use_admin_network_changed,
            Some(true),
            "{scenario}"
        );
        txn.commit().await.unwrap();

        report_network(&mh).await;
        let mut txn = harness.db_txn().await;
        let snapshot = mh.snapshot(&mut txn).await;
        assert!(
            snapshot.managed_host_network_config_version_synced(),
            "{scenario}"
        );
        let instance = snapshot.instance.as_ref().unwrap();
        assert_eq!(
            instance.observations.network[&primary_dpu_id].config_version,
            instance.network_config_version,
            "{scenario}"
        );
        txn.commit().await.unwrap();
        // Keep the immediate successor visible even while another host is queued.
        env.run_single_iteration_ext(false).await;
        let mut txn = harness.db_txn().await;
        let snapshot = mh.snapshot(&mut txn).await;
        assert_eq!(
            snapshot.managed_state,
            ManagedHostState::Assigned {
                instance_state: InstanceState::WaitingForRebootToReady,
            },
            "{scenario}"
        );
        txn.commit().await.unwrap();
    }
}

/// Allocate instance with non-existent OS image ID.
/// Expect: FailedPrecondition error indicating image does not exist.
/// With the site flag on, tenant release drives the host through the full
/// `FactoryResetBmc` sub-flow before the existing power-cycle path: it suppresses
/// site-explorer, waits for the acknowledgement, factory-resets and re-probes the
/// BMC, verifies the factory credentials, restores the device to its previous
/// per-device Vault credential (read-only), removes the suppression, and hands
/// off to `PowerCycle`. Asserts the suppression is cleaned up, the per-device
/// Vault secret is preserved (never written), and the BMC ends on the restored
/// per-device password.
#[sqlx_test]
async fn test_factory_reset_bmc_on_release_sanitizes_host_bmc(pool: PgPool) {
    use carbide_secrets::credentials::{
        BmcCredentialType, CredentialKey, CredentialReader, CredentialWriter, Credentials,
    };
    use model::bmc_suppression::{BmcSuppressionSource, BmcSuppressionSubsystem};
    use model::machine::HostPlatformConfigurationState;

    const FACTORY_USER: &str = "root";
    const FACTORY_PW: &str = "factory-default";
    const PER_DEVICE_PW: &str = "prev-per-device";

    // Opt the site in to the deletion-only BMC factory-reset sub-flow.
    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .configure_runtime(|config| config.bmc_factory_reset_on_instance_termination_enabled = true)
        .build()
        .await;

    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();
    let segment_ids = create_tenant_segments(
        harness,
        &network_controller,
        &boot.domain,
        default_vpc_config(),
        1,
    )
    .await;
    let mh = create_ready_host(
        harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default().with_dpu_count(1),
    )
    .await;

    let mut txn = harness.db_txn().await;
    let host_machine = mh.host.db_machine(&mut txn).await;
    let device_locators: Vec<DeviceLocator> = mh
        .dpu_ids()
        .iter()
        .map(|dpu_id| {
            host_machine
                .get_device_locator_for_dpu_id(dpu_id)
                .expect("device locator for DPU")
        })
        .collect();
    let host_bmc_mac = host_machine
        .status
        .bmc_info
        .mac
        .expect("fixture host should have a BMC MAC");
    txn.commit().await.unwrap();

    // Allocate and drive the instance to Assigned/Ready.
    let tinstance = mh
        .instance_builder(harness)
        .network(interface_network_config_with_devices(
            &segment_ids,
            &device_locators,
        ))
        .build()
        .await;
    Box::pin(advance_instance_to_ready(
        &env,
        &network_controller,
        &mh,
        &tinstance,
    ))
    .await;

    // Seed the state the sub-flow depends on, after provisioning so nothing
    // overwrites it: non-empty factory credentials in expected_machines (the
    // recovery path for the factory password), the sim's factory `root` account,
    // and the device's previous per-device Vault credential (the restore target).
    let per_device_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: host_bmc_mac,
        },
    };
    let per_device_creds = Credentials::UsernamePassword {
        username: FACTORY_USER.to_string(),
        password: PER_DEVICE_PW.to_string(),
    };
    {
        let mut expected = db::expected_machine::find_by_bmc_mac_address(
            &harness.api().database_connection,
            host_bmc_mac,
        )
        .await
        .unwrap()
        .expect("expected_machines row for the fixture host");
        let mut txn = harness.api().database_connection.begin().await.unwrap();
        db::expected_machine::update_bmc_credentials(
            &mut expected,
            txn.as_mut(),
            FACTORY_USER.to_string(),
            FACTORY_PW.to_string(),
        )
        .await
        .unwrap();
        txn.commit().await.unwrap();
    }
    env.redfish_sim.seed_user(FACTORY_USER, FACTORY_PW);
    harness
        .api()
        .credential_manager()
        .set_credentials(&per_device_key, &per_device_creds)
        .await
        .expect("staging the per-device Vault credential should succeed");

    // Tenant release: mark the instance deleted.
    harness
        .api()
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(tinstance.id),
            issue: None,
            is_repair_tenant: None,
            delete_attribution: None,
        }))
        .await
        .expect("release_instance failed");

    // Drive the sub-flow one iteration at a time, acknowledging the suppression
    // once it appears (site-explorer does not run in this env), and stop as soon
    // as the machine advances past FactoryResetBmc.
    let mut acknowledged = false;
    let mut entered_factory_reset = false;
    let mut state_after_factory_reset = None;
    for _ in 0..60 {
        env.run_single_iteration_ext(true).await;

        if !acknowledged
            && let Some(suppression) = db::bmc_suppression::find(
                &harness.api().database_connection,
                host_bmc_mac,
                BmcSuppressionSubsystem::SiteExplorer,
                BmcSuppressionSource::FactoryResetBmc,
            )
            .await
            .unwrap()
            && suppression.acknowledged_at.is_none()
        {
            let mut txn = harness.api().database_connection.begin().await.unwrap();
            db::bmc_suppression::acknowledge(
                txn.as_mut(),
                host_bmc_mac,
                BmcSuppressionSubsystem::SiteExplorer,
            )
            .await
            .unwrap();
            txn.commit().await.unwrap();
            acknowledged = true;
        }

        let mut txn = harness.api().database_connection.begin().await.unwrap();
        let machine = mh.host.db_machine(&mut txn).await;
        let state = machine.current_state().clone();
        txn.commit().await.unwrap();

        // WaitForBmc holds a fixed 30s wall-clock settle window before its first
        // readiness probe. Backdate the state version timestamp (preserving the
        // version number so the next transition's optimistic check still passes)
        // so the settle elapses and the always-up sim BMC is probed without a
        // real 30s wait.
        if matches!(
            state,
            ManagedHostState::Assigned {
                instance_state: InstanceState::HostPlatformConfiguration {
                    platform_config_state: HostPlatformConfigurationState::FactoryResetBmc {
                        reset_state: model::machine::FactoryResetBmcState::WaitForBmc,
                    },
                },
            }
        ) {
            let aged_version = format!(
                "V{}-T{}",
                machine.current_version().version_nr(),
                (chrono::Utc::now() - chrono::Duration::seconds(120)).timestamp_micros()
            );
            let mut txn = harness.api().database_connection.begin().await.unwrap();
            sqlx::query("UPDATE machines SET controller_state_version=$1 WHERE id=$2")
                .bind(aged_version)
                .bind(machine.id.to_string())
                .execute(txn.as_mut())
                .await
                .unwrap();
            txn.commit().await.unwrap();
        }

        if matches!(
            state,
            ManagedHostState::Assigned {
                instance_state: InstanceState::HostPlatformConfiguration {
                    platform_config_state: HostPlatformConfigurationState::FactoryResetBmc { .. },
                },
            }
        ) {
            entered_factory_reset = true;
        } else if entered_factory_reset {
            state_after_factory_reset = Some(state);
            break;
        }
    }

    assert!(
        entered_factory_reset,
        "tenant release with the flag on must enter FactoryResetBmc"
    );
    assert!(
        acknowledged,
        "the sub-flow must upsert a site-explorer suppression to acknowledge"
    );
    let state_after_factory_reset =
        state_after_factory_reset.expect("machine must advance past FactoryResetBmc");
    assert!(
        matches!(
            state_after_factory_reset,
            ManagedHostState::Assigned {
                instance_state: InstanceState::HostPlatformConfiguration {
                    platform_config_state: HostPlatformConfigurationState::PowerCycle { .. },
                },
            }
        ),
        "FactoryResetBmc must hand off to PowerCycle, got {state_after_factory_reset:?}"
    );

    // RemoveSuppression deletes the row it created.
    assert!(
        !db::bmc_suppression::is_suppressed(
            &harness.api().database_connection,
            host_bmc_mac,
            BmcSuppressionSubsystem::SiteExplorer,
        )
        .await
        .unwrap(),
        "RemoveSuppression must delete the site-explorer suppression"
    );

    // The per-device Vault secret is preserved verbatim: this flow only reads it.
    let persisted = harness
        .api()
        .credential_manager()
        .get_credentials(&per_device_key)
        .await
        .expect("reading the per-device Vault credential should succeed")
        .expect("the per-device Vault credential must still be present");
    assert_eq!(
        persisted, per_device_creds,
        "the per-device Vault credential must be preserved (read-only restore target)"
    );

    // RestoreCredentials changed the BMC root password from the factory default
    // back to the device's previous per-device password.
    assert_eq!(
        env.redfish_sim.user_password(FACTORY_USER).as_deref(),
        Some(PER_DEVICE_PW),
        "the BMC root account must end on the restored per-device password"
    );
}
