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
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::{
    FixtureDefault as _, ManagedHostConfigExt as _,
};
use carbide_test_harness::test_support::network_segment::FIXTURE_TENANT_ORG_ID;
use carbide_uuid::vpc::VpcPrefixId;
use db::ObjectColumnFilter;
use db::network_segment::IdColumn;
use itertools::Itertools;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::machine::{InstanceState, ManagedHostState, NetworkConfigUpdateState};
use model::metadata::Metadata;
use model::network_segment::NetworkSegmentSearchConfig;
use model::test_support::ManagedHostConfig;
use rpc::forge::VpcCreationRequest;
use tonic::{IntoRequest, Request};

use crate::env::Env;
use crate::instance_common::*;

#[sqlx_test]
async fn test_allocate_and_update_network_config_instance_state_machine(pool: PgPool) {
    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .build()
        .await;
    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();

    let (segment_id, segment_id2) =
        create_dual_tenant_segments(harness, &network_controller, &boot.domain).await;
    let mh = create_ready_host(harness, &site_explorer, &boot, ManagedHostConfig::default()).await;

    let mut txn = harness.db_txn().await;
    assert_eq!(
        db::instance_address::count_by_segment_id(&mut txn, &segment_id)
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        mh.host.db_machine(&mut txn).await.current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

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

    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .network
            .as_ref()
            .unwrap()
            .configs_synced(),
        rpc::SyncState::Synced
    );

    let new_network_config = rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: Some(
                rpc::forge::instance_interface_config::NetworkDetails::SegmentId(segment_id2),
            ),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
            ip_address: None,
            ipv6_interface_config: None,
            routing_profile: None,
        }],
        #[allow(deprecated)]
        auto: false,
        auto_config: None,
    };

    // Now update to change network config.
    let _ = harness
        .api()
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                if_version_match: None,
                config: Some(rpc::InstanceConfig {
                    tenant: Some(default_tenant_config()),
                    os: Some(default_os_config()),
                    network: Some(new_network_config),
                    infiniband: None,
                    nvlink: None,
                    spxconfig: None,
                    network_security_group_id: None,
                    dpu_extension_services: None,
                    power_profile: None,
                }),
                instance_id: instance.id,
                metadata: Some(rpc::forge::Metadata {
                    name: "newinstance".to_string(),
                    description: "desc".to_string(),
                    labels: vec![],
                }),
            },
        ))
        .await
        .unwrap();

    // Instance should move to NetworkConfigUpdateState::WaitingForNetworkSegmentToBeReady
    env.run_single_iteration_ext(true).await;
    // Instance should move to NetworkConfigUpdateState::WaitingForConfigSynced
    env.run_single_iteration_ext(true).await;
    // and stay there only.
    env.run_single_iteration_ext(true).await;

    let mut txn = harness.db_txn().await;
    let current_state = mh.host.db_machine(&mut txn).await;
    let current_state = current_state.current_state();
    println!("Current State: {current_state}");
    assert!(matches!(
        current_state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::NetworkConfigUpdate {
                network_config_update_state: NetworkConfigUpdateState::WaitingForConfigSynced
            }
        }
    ));
    txn.rollback().await.unwrap();

    // - forge-dpu-agent gets an instance network to configure, reports it configured
    report_network(&mh).await;
    // Move to ReleaseOldResources state.
    env.run_single_iteration_ext(true).await;
    let mut txn = harness.db_txn().await;
    assert!(matches!(
        mh.host.db_machine(&mut txn).await.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::NetworkConfigUpdate {
                network_config_update_state: NetworkConfigUpdateState::ReleaseOldResources
            }
        }
    ));
    txn.rollback().await.unwrap();
    env.run_single_iteration_ext(true).await;
    let mut txn = harness.db_txn().await;
    assert!(matches!(
        mh.host.db_machine(&mut txn).await.current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.rollback().await.unwrap();
}

/// A removed DPU's failed Admin apply must retain its old network resources,
/// including after `ReleaseOldResources` is persisted.
#[sqlx_test]
async fn test_network_update_waits_for_removed_dpu_admin_ack(pool: PgPool) {
    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .configure_runtime(|config| config.fnn = Some(fnn_config()))
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
                .metadata(Metadata {
                    name: "auto-prefix-selection-vpc".into(),
                    ..Default::default()
                })
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
                .slaac_enabled(false)
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner()
        .id
        .unwrap();
    let first = create_tenant_overlay_prefix_with_prefix(
        harness,
        vpc_id,
        "auto-prefix-candidate-one",
        "10.218.0.0/30".parse().unwrap(),
    )
    .await;
    let second = create_tenant_overlay_prefix_with_prefix(
        harness,
        vpc_id,
        "auto-prefix-candidate-two",
        "10.218.0.4/30".parse().unwrap(),
    )
    .await;
    let (lower_ipv4_prefix_id, higher_ipv4_prefix_id) = if first < second {
        (first, second)
    } else {
        (second, first)
    };
    let mh = create_ready_host(
        harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default().with_dpu_count(2),
    )
    .await;
    let mut network =
        dual_physical_network_config_with_vpc_prefixes(lower_ipv4_prefix_id, higher_ipv4_prefix_id);
    let mut txn = harness.db_txn().await;
    let host = mh.host.db_machine(&mut txn).await;
    for (interface, dpu_id) in network.interfaces.iter_mut().zip(&mh.dpu_ids()) {
        let locator = host.get_device_locator_for_dpu_id(dpu_id).unwrap();
        interface.device = Some(locator.device);
        interface.device_instance = locator.device_instance as u32;
    }
    txn.commit().await.unwrap();
    let tinstance = mh
        .instance_builder(harness)
        .tenant_org(FIXTURE_TENANT_ORG_ID)
        .network(network)
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
    let mut config = instance.config.clone().unwrap();
    let interfaces = &mut config.network.as_mut().unwrap().interfaces;
    let removed_segment_id = interfaces.pop().unwrap().network_segment_id.unwrap();
    let retained_segment_id = interfaces[0].network_segment_id.unwrap();
    harness
        .api()
        .update_instance_config(Request::new(rpc::forge::InstanceConfigUpdateRequest {
            instance_id: Some(tinstance.id),
            config: Some(config),
            metadata: Some(instance.metadata.as_ref().unwrap().clone()),
            if_version_match: None,
        }))
        .await
        .unwrap();
    let waiting = ManagedHostState::Assigned {
        instance_state: InstanceState::NetworkConfigUpdate {
            network_config_update_state: NetworkConfigUpdateState::WaitingForConfigSynced,
        },
    };
    until(&env, &mh.host.id, 10, waiting).await;

    // Find the removed DPU through the config the API actually serves it.
    let mut removed_dpu_id = None;
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
        if response.use_admin_network {
            assert!(
                removed_dpu_id.is_none(),
                "only one DPU should lose its interfaces"
            );
            removed_dpu_id = Some(*dpu_id);
            assert!(response.tenant_interfaces.is_empty());
            assert!(response.instance_network_config_version.is_empty());
        } else {
            assert_eq!(response.tenant_interfaces.len(), 1);
            {
                let status = mh
                    .dpus
                    .iter()
                    .find(|dpu| dpu.id == *dpu_id)
                    .unwrap()
                    .network_status()
                    .dpu_agent_version("test")
                    .build()
                    .await;
                harness
                    .api()
                    .record_dpu_network_status(status.into_request())
                    .await
                    .unwrap();
            }
        }
    }
    let removed_dpu_id = removed_dpu_id.expect("removed DPU must receive Admin config");
    let mut txn = harness.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    let pending = snapshot.instance.as_ref().unwrap();
    assert_eq!(pending.observations.network.len(), 2);
    let update_request = pending.update_network_config_request.clone().unwrap();
    let old_addresses = db::instance_address::find_all_by_instance_id_and_segment_id(
        txn.as_mut(),
        &tinstance.id,
        &removed_segment_id,
    )
    .await
    .unwrap()
    .into_iter()
    .map(|allocation| allocation.address)
    .collect_vec();
    assert_eq!(old_addresses.len(), 1);
    txn.commit().await.unwrap();

    for phase in [
        NetworkConfigUpdateState::WaitingForConfigSynced,
        NetworkConfigUpdateState::ReleaseOldResources,
    ] {
        if phase == NetworkConfigUpdateState::ReleaseOldResources {
            // Establish the normal transition, then lose the acknowledgement
            // before the next iteration handles the persisted release phase.
            {
                let status = mh
                    .dpus
                    .iter()
                    .find(|dpu| dpu.id == removed_dpu_id)
                    .unwrap()
                    .network_status()
                    .dpu_agent_version("test")
                    .build()
                    .await;
                harness
                    .api()
                    .record_dpu_network_status(status.into_request())
                    .await
                    .unwrap();
            }
            env.run_single_iteration_ext(true).await;
        }
        let expected_state = ManagedHostState::Assigned {
            instance_state: InstanceState::NetworkConfigUpdate {
                network_config_update_state: phase,
            },
        };
        let mut txn = harness.db_txn().await;
        assert_eq!(mh.snapshot(&mut txn).await.managed_state, expected_state);
        txn.commit().await.unwrap();

        // Inject the report emitted after a failed Admin apply: both version
        // stamps are absent, although NVUE/uplink health can still be clear.
        harness
            .api()
            .record_dpu_network_status(Request::new(rpc::forge::DpuNetworkStatus {
                dpu_machine_id: Some(removed_dpu_id),
                network_config_version: None,
                instance_network_config_version: None,
                network_config_error: Some(
                    "network update failed: injected Admin apply failure".to_string(),
                ),
                dpu_health: Some(
                    health_report::HealthReport::empty("forge-dpu-agent".to_string()).into(),
                ),
                ..Default::default()
            }))
            .await
            .unwrap();
        env.run_single_iteration_ext(true).await;

        let mut txn = harness.db_txn().await;
        let snapshot = mh.snapshot(&mut txn).await;
        assert_eq!(snapshot.managed_state, expected_state);
        assert!(
            matches!(
                &snapshot.host_snapshot.controller_state_outcome,
                Some(PersistentStateHandlerOutcome::Wait { reason, .. })
                    if reason == "Waiting for DPU agent(s) to apply network config and report healthy network"
            ),
            "expected the managed-host version wait, got {:?}",
            snapshot.host_snapshot.controller_state_outcome
        );
        assert!(!snapshot.managed_host_network_config_version_synced());
        let pending = snapshot.instance.as_ref().unwrap();
        // The remaining Instance receipts are current; the missing Admin
        // receipt, not Instance-version mismatch or health, must block cleanup.
        assert_eq!(pending.observations.network.len(), 1);
        assert!(!pending.observations.network.contains_key(&removed_dpu_id));
        assert!(
            pending.observations.network.values().all(|observation| {
                observation.config_version == pending.network_config_version
            })
        );
        assert_eq!(pending.config.network, update_request.new_config);
        assert_eq!(
            pending.update_network_config_request.as_ref(),
            Some(&update_request)
        );
        let addresses = db::instance_address::find_all_by_instance_id_and_segment_id(
            txn.as_mut(),
            &tinstance.id,
            &removed_segment_id,
        )
        .await
        .unwrap()
        .into_iter()
        .map(|allocation| allocation.address)
        .collect_vec();
        assert_eq!(addresses, old_addresses);
        let segments = db::network_segment::find_by(
            txn.as_mut(),
            ObjectColumnFilter::One(IdColumn, &removed_segment_id),
            NetworkSegmentSearchConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(segments.len(), 1);
        assert!(!segments[0].is_marked_as_deleted());
        txn.commit().await.unwrap();
    }

    // A lifecycle-blocking alert can arrive after the healthy transition to
    // `ReleaseOldResources`. Current receipts alone must not bypass that alert.
    let mut blocking_health = health_report::HealthReport::empty("forge-dpu-agent".to_string());
    blocking_health
        .alerts
        .push(health_report::HealthProbeAlert {
            id: health_report::HealthProbeId::post_config_check_wait(),
            target: None,
            in_alert_since: None,
            message: "injected health change before resource release".to_string(),
            tenant_message: None,
            classifications: vec![
                health_report::HealthAlertClassification::prevent_host_state_changes(),
            ],
        });
    {
        let status = mh
            .dpus
            .iter()
            .find(|dpu| dpu.id == removed_dpu_id)
            .unwrap()
            .network_status()
            .dpu_agent_version("test")
            .dpu_health(blocking_health.into())
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
    let snapshot = mh.snapshot(&mut txn).await;
    assert!(snapshot.managed_host_network_config_version_synced());
    assert_eq!(
        snapshot.managed_state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::NetworkConfigUpdate {
                network_config_update_state: NetworkConfigUpdateState::ReleaseOldResources,
            },
        }
    );
    assert!(
        matches!(
            &snapshot.host_snapshot.controller_state_outcome,
            Some(PersistentStateHandlerOutcome::Error { err, .. })
                if err.contains("health")
        ),
        "expected the existing health error, got {:?}",
        snapshot.host_snapshot.controller_state_outcome
    );
    assert!(
        snapshot
            .instance
            .as_ref()
            .unwrap()
            .update_network_config_request
            .is_some()
    );
    assert_eq!(
        db::instance_address::count_by_segment_id(&mut txn, &removed_segment_id)
            .await
            .unwrap(),
        1
    );
    txn.commit().await.unwrap();

    {
        let status = mh
            .dpus
            .iter()
            .find(|dpu| dpu.id == removed_dpu_id)
            .unwrap()
            .network_status()
            .dpu_agent_version("test")
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
    let snapshot = mh.snapshot(&mut txn).await;
    assert_eq!(
        snapshot.managed_state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    );
    assert!(snapshot.managed_host_network_config_version_synced());
    assert!(
        snapshot
            .instance
            .as_ref()
            .unwrap()
            .update_network_config_request
            .is_none()
    );
    assert_eq!(
        db::instance_address::count_by_segment_id(&mut txn, &removed_segment_id)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        db::instance_address::count_by_segment_id(&mut txn, &retained_segment_id)
            .await
            .unwrap(),
        1
    );
    let segments = db::network_segment::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(IdColumn, &removed_segment_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .unwrap();
    assert_eq!(segments.len(), 1);
    assert!(segments[0].is_marked_as_deleted());
    txn.commit().await.unwrap();
}

/// Builds a two-interface physical network config backed by VPC prefixes.
fn dual_physical_network_config_with_vpc_prefixes(
    first_prefix_id: VpcPrefixId,
    second_prefix_id: VpcPrefixId,
) -> rpc::InstanceNetworkConfig {
    // Put each PF on a distinct BlueField device instance so validation treats
    // them as separate physical interfaces.
    let interfaces = [first_prefix_id, second_prefix_id]
        .into_iter()
        .enumerate()
        .map(
            |(device_instance, vpc_prefix_id)| rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(
                        vpc_prefix_id,
                    ),
                ),
                device: Some("BlueField SoC".to_string()),
                device_instance: device_instance as u32,
                virtual_function_id: None,
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
            },
        )
        .collect();

    rpc::InstanceNetworkConfig {
        interfaces,
        #[allow(deprecated)]
        auto: false,
        auto_config: None,
    }
}
