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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use carbide_dpf::DpuDeploymentType;
use carbide_machine_controller::dpf::{DpfOperations, MockDpfOperations};
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::{
    FixtureDefault as _, ManagedHostConfigExt as _,
};
use carbide_test_harness::test_support::network_segment::{
    FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS, FIXTURE_TENANT_ORG_ID,
};
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::DpuMachineId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use itertools::Itertools;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::expected_machine::ExpectedMachineData;
use model::instance::config::network::{DeviceLocator, InstanceServiceInterfaceConfig};
use model::machine::{InstanceState, ManagedHostState, NetworkConfigUpdateState};
use model::metadata::Metadata;
use model::resource_pool::{OwnerType, ResourcePoolEntryState};
use model::test_support::ManagedHostConfig;
use rpc::forge::{DpuExtensionService, VpcCreationRequest};
use tonic::Request;

use crate::env::Env;
use crate::instance_common::*;

/// Verifies host-network promotion releases per-VPC loopbacks only when no
/// remaining host or service membership needs them. This prevents a live
/// loopback from returning to the pool for conflicting reuse.
#[sqlx_test]
#[allow(deprecated)]
async fn test_fnn_vrf_loopback_release_uses_remaining_host_and_service_membership(
    pool: sqlx::PgPool,
) {
    // Enable both per-VPC FNN loopbacks and the DPF service definition used by
    // the retained-membership half of the test.
    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .configure_runtime(|config| {
            config.dpf.enabled = true;
            // Configure one service slot so retained endpoints can appear in DPU network responses.
            config.dpu_config.service_vpc_slot_count = 1;
            config.fnn = Some(carbide_api_core::cfg::file::FnnConfig {
                use_vpc_vrf_loopback: true,
                ..fnn_config()
            });
        })
        .with_dpf_sdk(service_vpc_placement_mock())
        .build()
        .await;

    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();

    // Create FNN tenants matching the existing peer-VPC fixture organizations.
    for (organization_id, name) in [
        (FIXTURE_TENANT_ORG_ID, "fnn vf loopback tenant 1"),
        (
            "e65a9d69-39d2-4872-a53e-e5cb87c84e75",
            "fnn vf loopback tenant 2",
        ),
    ] {
        harness
            .api()
            .create_tenant(Request::new(rpc::forge::CreateTenantRequest {
                organization_id: organization_id.to_string(),
                routing_profile_type: Some("INTERNAL".to_string()),
                metadata: Some(rpc::forge::Metadata {
                    name: name.to_string(),
                    ..Default::default()
                }),
            }))
            .await
            .unwrap();
    }

    // Create two FNN VPCs and allocate PF/VF interfaces on one DPU.
    let PeerVpcSegments {
        first_vpc,
        first_segment_id,
        second_vpc,
        second_segment_id,
    } = create_peer_tenant_segments(
        harness,
        &network_controller,
        &boot.domain,
        rpc::forge::VpcVirtualizationType::Fnn,
        rpc::forge::VpcVirtualizationType::Fnn,
    )
    .await;
    let first_vpc = first_vpc.expect("first VPC should be present");
    let second_vpc = second_vpc.expect("second VPC should be present");
    let mh = create_ready_host(
        harness,
        &site_explorer,
        &boot,
        service_vpc_test_host_config(),
    )
    .await;
    let dpu_id = mh.dpu_ids()[0];
    let instance = mh
        .instance_builder(harness)
        .network(single_interface_network_config_with_vfs(vec![
            first_segment_id,
            second_segment_id,
        ]))
        .build()
        .await;
    Box::pin(advance_instance_to_ready(
        &env,
        &network_controller,
        &mh,
        &instance,
    ))
    .await;

    // Fetch the single DPU config and verify both PF and VF receive loopbacks.
    let network_config = harness
        .api()
        .get_managed_host_network_config(Request::new(
            rpc::forge::ManagedHostNetworkConfigRequest {
                dpu_machine_id: Some(dpu_id),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(network_config.tenant_interfaces.len(), 2);
    assert_eq!(
        network_config.tenant_interfaces[0].function_type,
        rpc::InterfaceFunctionType::Physical as i32
    );
    assert_eq!(
        network_config.tenant_interfaces[1].function_type,
        rpc::InterfaceFunctionType::Virtual as i32
    );
    let first_loopback = network_config.tenant_interfaces[0]
        .tenant_vrf_loopback_ip
        .clone()
        .expect("PF VPC loopback should be present");
    let second_loopback = network_config.tenant_interfaces[1]
        .tenant_vrf_loopback_ip
        .clone()
        .expect("VF VPC loopback should be present");
    assert_ne!(first_loopback, second_loopback);

    // Update the instance to keep only the PF-backed VPC interface.
    // The network field drives loopback release; the remaining config and
    // metadata fields make this a valid full replacement request.
    harness
        .api()
        .update_instance_config(Request::new(rpc::forge::InstanceConfigUpdateRequest {
            if_version_match: None,
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(first_segment_id)),
                infiniband: None,
                nvlink: None,
                spxconfig: None,
                network_security_group_id: None,
                dpu_extension_services: None,
                power_profile: None,
            }),
            instance_id: Some(instance.id),
            metadata: Some(rpc::Metadata {
                name: "single-fnn-vpc".to_string(),
                description: "tests/instance".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();

    // Move the instance to ready state after the network config update.
    network_update_to_ready(&env, &network_controller, &mh, false).await;

    // Verify the retained PF VPC loopback remains and the removed VF VPC loopback is gone.
    let mut txn = harness.db_txn().await;
    let retained_loopback = db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_id, &first_vpc)
        .await
        .unwrap()
        .expect("retained PF VPC loopback should remain");
    assert_eq!(retained_loopback.loopback_ip.to_string(), first_loopback);
    let retained_entry = db::resource_pool::find_value(&mut *txn, &first_loopback)
        .await
        .expect("find retained PF loopback allocation")
        .into_iter()
        .find(|entry| {
            entry.pool_name
                == harness
                    .api()
                    .common_pools()
                    .ethernet
                    .pool_vpc_dpu_loopback_ip
                    .name()
        })
        .expect("retained PF loopback pool entry");
    assert_eq!(
        retained_entry.state.0,
        ResourcePoolEntryState::Allocated {
            owner: dpu_id.to_string(),
            owner_type: OwnerType::Machine.to_string(),
        }
    );
    let removed_entry = db::resource_pool::find_value(&mut *txn, &second_loopback)
        .await
        .expect("find removed VF loopback allocation")
        .into_iter()
        .find(|entry| {
            entry.pool_name
                == harness
                    .api()
                    .common_pools()
                    .ethernet
                    .pool_vpc_dpu_loopback_ip
                    .name()
        })
        .expect("removed VF loopback must remain in its pool");
    assert_eq!(removed_entry.state.0, ResourcePoolEntryState::Free);
    assert!(
        db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_id, &second_vpc)
            .await
            .unwrap()
            .is_none()
    );
    txn.rollback().await.unwrap();

    // A second host keeps the removed host VPC through a service endpoint on
    // its exact DPU, so that DPU/VPC allocation must remain assigned.
    let service_host = create_ready_host(
        harness,
        &site_explorer,
        &boot,
        service_vpc_test_host_config(),
    )
    .await;
    db::machine::mark_machine_ingestion_done_with_dpf(
        &mut harness.api().database_connection.acquire().await.unwrap(),
        &service_host.host.id,
    )
    .await
    .unwrap();
    let service_dpu_id = service_host.dpu_ids()[0];
    let service_instance = service_host
        .instance_builder(harness)
        .network(
            // Both VPCs need host loopbacks before the second becomes service-only.
            single_interface_network_config_with_vfs(vec![first_segment_id, second_segment_id]),
        )
        .build()
        .await;
    Box::pin(advance_instance_to_ready(
        &env,
        &network_controller,
        &service_host,
        &service_instance,
    ))
    .await;
    let service_network_config = harness
        .api()
        .get_managed_host_network_config(Request::new(
            rpc::forge::ManagedHostNetworkConfigRequest {
                dpu_machine_id: Some(service_dpu_id),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let service_loopback = service_network_config.tenant_interfaces[1]
        .tenant_vrf_loopback_ip
        .clone()
        .expect("service VPC loopback should be present");

    // Register the service tenant required by the DPF definition.
    create_fixture_tenant(harness, "best_org").await.unwrap();
    let service = create_networked_dpf_service(
        harness,
        "loopback-retention-service",
        rpc::forge::DpuExtensionServiceDpuTarget::All,
    )
    .await
    .unwrap();
    let service_version = service
        .latest_version_info
        .as_ref()
        .expect("created service has a version")
        .version
        .clone();
    // Retain `service_endpoint.network_segment_id` so the post-update assertion reads the service-owned
    // segment rather than the removed tenant segment.
    let service_endpoint = seed_networked_attachment(
        harness,
        service_instance.id,
        service_dpu_id,
        &service,
        second_vpc,
    )
    .await
    .unwrap();

    // Remove the tenant interface while preserving the existing service-VPC
    // selection through the caller-visible attachment configuration.
    harness
        .api()
        .update_instance_config(Request::new(rpc::forge::InstanceConfigUpdateRequest {
            if_version_match: None,
            config: Some(rpc::InstanceConfig {
                tenant: Some(default_tenant_config()),
                os: Some(default_os_config()),
                network: Some(single_interface_network_config(first_segment_id)),
                dpu_extension_services: Some(rpc::forge::InstanceDpuExtensionServicesConfig {
                    service_configs: vec![rpc::forge::InstanceDpuExtensionServiceConfig {
                        service_id: service.service_id,
                        version: service_version,
                        // This exact service membership retains only the removed VF's loopback.
                        service_vpc_ids: vec![second_vpc],
                    }],
                }),
                ..Default::default()
            }),
            instance_id: Some(service_instance.id),
            metadata: Some(rpc::Metadata {
                name: "service-retained-fnn-vpc".to_string(),
                description: "tests/instance".to_string(),
                labels: vec![],
            }),
        }))
        .await
        .unwrap();
    network_update_to_ready(&env, &network_controller, &service_host, false).await;

    // The service address and exact DPU/VPC loopback remain allocated, while
    // the unrelated first VPC allocation also remains intact.
    let mut txn = harness.db_txn().await;
    assert!(
        db::vpc_dpu_loopback::find(txn.as_mut(), &service_dpu_id, &first_vpc)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        db::vpc_dpu_loopback::find(txn.as_mut(), &service_dpu_id, &second_vpc)
            .await
            .unwrap()
            .expect("service VPC loopback should remain")
            .loopback_ip
            .to_string(),
        service_loopback,
    );
    let service_entry = db::resource_pool::find_value(&mut *txn, &service_loopback)
        .await
        .expect("find retained service loopback allocation")
        .into_iter()
        .find(|entry| {
            entry.pool_name
                == harness
                    .api()
                    .common_pools()
                    .ethernet
                    .pool_vpc_dpu_loopback_ip
                    .name()
        })
        .expect("retained service loopback pool entry");
    assert_eq!(
        service_entry.state.0,
        ResourcePoolEntryState::Allocated {
            owner: service_dpu_id.to_string(),
            owner_type: OwnerType::Machine.to_string(),
        }
    );
    let expected_service_address =
        db::instance_address::service_address_for_prefix(service_endpoint.link_prefix)
            .expect("seeded link prefix has a service address");
    let retained_addresses = db::instance_address::find_all_by_instance_id_and_segment_id(
        txn.as_mut(),
        &service_instance.id,
        &service_endpoint.network_segment_id,
    )
    .await
    .unwrap();
    assert_eq!(
        retained_addresses
            .iter()
            .map(|address| (address.address, address.prefix, address.vpc_id))
            .collect_vec(),
        vec![(
            expected_service_address,
            service_endpoint.link_prefix,
            second_vpc,
        )],
    );
}

/// Verifies a late loopback-pool release failure rolls back every earlier
/// cleanup write and leaves `ReleaseOldResources` retryable. This prevents a
/// cleared pending request or deleted loopback row from surviving a failed release.
#[sqlx_test]
async fn test_fnn_vrf_loopback_pool_release_failure_rolls_back_and_retries(pool: sqlx::PgPool) {
    // Enable per-VPC loopbacks and create both tenant identities used by the
    // two-VPC fixture.
    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .configure_runtime(|config| {
            config.fnn = Some(carbide_api_core::cfg::file::FnnConfig {
                use_vpc_vrf_loopback: true,
                ..fnn_config()
            });
        })
        .build()
        .await;

    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();

    for organization_id in [
        // The primary tenant owns the retained VPC.
        FIXTURE_TENANT_ORG_ID,
        // The peer tenant owns the VPC whose loopback release will fail.
        "e65a9d69-39d2-4872-a53e-e5cb87c84e75",
    ] {
        create_fixture_tenant(harness, organization_id)
            .await
            .unwrap();
    }

    // The retained PF keeps the post-update network valid while the removed VF
    // supplies the exact DPU/VPC loopback whose release will fail.
    let PeerVpcSegments {
        first_segment_id,
        second_vpc,
        second_segment_id,
        ..
    } = create_peer_tenant_segments(
        harness,
        &network_controller,
        &boot.domain,
        rpc::forge::VpcVirtualizationType::Fnn,
        rpc::forge::VpcVirtualizationType::Fnn,
    )
    .await;
    let second_vpc = second_vpc.expect("second VPC should be present");
    let mh = create_ready_host(harness, &site_explorer, &boot, ManagedHostConfig::default()).await;
    let dpu_id = mh.dpu_ids()[0];
    let tinstance = mh
        .instance_builder(harness)
        .tenant_org(FIXTURE_TENANT_ORG_ID)
        .network(single_interface_network_config_with_vfs(vec![
            first_segment_id,
            second_segment_id,
        ]))
        .build()
        .await;
    Box::pin(advance_instance_to_ready(
        &env,
        &network_controller,
        &mh,
        &tinstance,
    ))
    .await;

    // Stage removal of only the second VPC and stop at the persisted cleanup
    // state before any old resource has been released.
    let instance = tinstance.rpc_instance().await;
    let mut requested_config = instance.config.clone().unwrap();
    requested_config.network = Some(single_interface_network_config(first_segment_id));
    harness
        .api()
        .update_instance_config(Request::new(rpc::forge::InstanceConfigUpdateRequest {
            instance_id: Some(tinstance.id),
            config: Some(requested_config),
            metadata: Some(instance.metadata.as_ref().unwrap().clone()),
            if_version_match: None,
        }))
        .await
        .unwrap();
    until(
        &env,
        &mh.host.id,
        10,
        ManagedHostState::Assigned {
            instance_state: InstanceState::NetworkConfigUpdate {
                network_config_update_state: NetworkConfigUpdateState::WaitingForConfigSynced,
            },
        },
    )
    .await;
    report_network(&mh).await;
    let release_state = ManagedHostState::Assigned {
        instance_state: InstanceState::NetworkConfigUpdate {
            network_config_update_state: NetworkConfigUpdateState::ReleaseOldResources,
        },
    };
    until(&env, &mh.host.id, 10, release_state.clone()).await;

    // Capture the exact pending request and loopback before injecting the
    // failure so rollback is checked against persisted state.
    let loopback_pool_name = harness
        .api()
        .common_pools()
        .ethernet
        .pool_vpc_dpu_loopback_ip
        .name()
        .to_string();
    let mut txn = harness.db_txn().await;
    let pending_request = tinstance
        .db_instance(&mut txn)
        .await
        .update_network_config_request
        .expect("network update should remain pending before cleanup");
    let loopback_ip = db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_id, &second_vpc)
        .await
        .unwrap()
        .expect("removed VPC should have a loopback before cleanup")
        .loopback_ip;
    let loopback_value = loopback_ip.to_string();
    txn.rollback().await.unwrap();

    // Reject only the target loopback's transition to an unallocated pool row.
    // The loopback-row deletion has already run when this constraint fires.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE resource_pool ADD CONSTRAINT reject_vpc_loopback_release
         CHECK (name <> '{loopback_pool_name}' OR value <> '{loopback_value}' OR allocated IS NOT NULL)"
    )))
    .execute(&harness.api().database_connection)
    .await
    .expect("inject target loopback pool-release failure");
    env.run_single_iteration_ext(true).await;

    // The failed iteration must retain its state and roll back every earlier
    // write, preserving the pending request, address, and loopback row.
    let mut txn = harness.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    assert_eq!(snapshot.managed_state, release_state);
    assert!(
        matches!(
            &snapshot.host_snapshot.controller_state_outcome,
            Some(PersistentStateHandlerOutcome::Error { err, .. })
                if err.contains("reject_vpc_loopback_release")
        ),
        "expected the injected pool-release error, got {:?}",
        snapshot.host_snapshot.controller_state_outcome,
    );
    let persisted = tinstance.db_instance(&mut txn).await;
    assert_eq!(
        persisted.update_network_config_request.as_ref(),
        Some(&pending_request),
    );
    assert_eq!(
        db::instance_address::count_by_segment_id(&mut txn, &second_segment_id)
            .await
            .unwrap(),
        1,
    );
    assert_eq!(
        db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_id, &second_vpc)
            .await
            .unwrap()
            .expect("failed release should retain the loopback row")
            .loopback_ip,
        loopback_ip,
    );
    let retained_entry = db::resource_pool::find_value(&mut *txn, &loopback_value)
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.pool_name == loopback_pool_name)
        .expect("failed release should retain the pool row");
    assert_eq!(
        retained_entry.state.0,
        ResourcePoolEntryState::Allocated {
            owner: dpu_id.to_string(),
            owner_type: OwnerType::Machine.to_string(),
        }
    );
    txn.rollback().await.unwrap();

    // Remove the transient failure and let a later controller iteration retry
    // the same persisted cleanup state.
    sqlx::query("ALTER TABLE resource_pool DROP CONSTRAINT reject_vpc_loopback_release")
        .execute(&harness.api().database_connection)
        .await
        .expect("remove injected loopback pool-release failure");
    let ready_state = ManagedHostState::Assigned {
        instance_state: InstanceState::Ready,
    };
    until(&env, &mh.host.id, 10, ready_state.clone()).await;

    // The retry must successfully complete each previously rolled-back mutation.
    let mut txn = harness.db_txn().await;
    let snapshot = mh.snapshot(&mut txn).await;
    assert_eq!(snapshot.managed_state, ready_state);
    assert!(
        tinstance
            .db_instance(&mut txn)
            .await
            .update_network_config_request
            .is_none()
    );
    assert_eq!(
        db::instance_address::count_by_segment_id(&mut txn, &second_segment_id)
            .await
            .unwrap(),
        0,
    );
    assert!(
        db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_id, &second_vpc)
            .await
            .unwrap()
            .is_none()
    );
    let released_entry = db::resource_pool::find_value(&mut *txn, &loopback_value)
        .await
        .unwrap()
        .into_iter()
        .find(|entry| entry.pool_name == loopback_pool_name)
        .expect("released loopback should remain represented in its pool");
    assert_eq!(released_entry.state.0, ResourcePoolEntryState::Free);
    txn.rollback().await.unwrap();
}

/// Verifies network updates independently retain and release exact DPU/VPC loopbacks, including
/// when a persisted retained locator no longer resolves. Another DPU's host membership or service
/// endpoint must not retain unrelated pairs, while ambiguous ownership must preserve its VPC on
/// every current DPU.
#[sqlx_test]
async fn test_fnn_vrf_loopback_release_is_exact_across_dpus_and_vpcs(pool: sqlx::PgPool) {
    // Enable per-VPC loopbacks and DPF service registration for the service-owned pair.
    let env = Env::builder(pool)
        .with_resource_pools(instance_resource_pools())
        .configure_runtime(|config| {
            config.dpf.enabled = true;
            // Configure one service slot so retained endpoints can appear in DPU network responses.
            config.dpu_config.service_vpc_slot_count = 1;
            config.fnn = Some(carbide_api_core::cfg::file::FnnConfig {
                use_vpc_vrf_loopback: true,
                ..fnn_config()
            });
        })
        .with_dpf_sdk(service_vpc_deployment_mock())
        .build()
        .await;

    let harness = &env.test_harness;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(harness, &network_controller).await;
    let site_explorer = harness.default_test_site_explorer();

    create_fixture_tenant(harness, FIXTURE_TENANT_ORG_ID)
        .await
        .unwrap();

    // Give each VPC one distinct segment per DPU so the initial host config
    // owns all four exact DPU/VPC memberships without duplicate segments.
    let first_vpc_segments = create_tenant_segments(
        harness,
        &network_controller,
        &boot.domain,
        VpcCreationRequest::builder(FIXTURE_TENANT_ORG_ID)
            .metadata(Metadata {
                name: "exact loopback vpc 1".to_string(),
                ..Default::default()
            })
            .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
            .rpc(),
        2,
    )
    .await;
    // Use the next two fixture prefixes for the second VPC so prefix validation
    // cannot obscure exact DPU/VPC ownership.
    let second_vpc = harness
        .api()
        .create_vpc(
            VpcCreationRequest::builder(FIXTURE_TENANT_ORG_ID)
                .metadata(Metadata {
                    name: "exact loopback vpc 2".to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner()
        .id
        .expect("second VPC has an ID");
    let second_vpc_segments = [
        create_tenant_network_segment(
            harness,
            &boot.domain,
            Some(second_vpc),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[2],
            "EXACT_LOOPBACK_VPC2_DPU0",
            true,
        )
        .await,
        create_tenant_network_segment(
            harness,
            &boot.domain,
            Some(second_vpc),
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[3],
            "EXACT_LOOPBACK_VPC2_DPU1",
            true,
        )
        .await,
    ];

    // Give the primary DPU an unrelated FNN host path so its active service endpoint remains
    // eligible while the original DPU/VPC pairs still exercise exact release behavior.
    let primary_dpu_host_vpc = create_fnn_vpc(harness, "exact loopback primary DPU host VPC").await;
    let primary_dpu_host_segment = create_tenant_network_segment(
        harness,
        &boot.domain,
        Some(primary_dpu_host_vpc),
        FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[4],
        "EXACT_LOOPBACK_PRIMARY_DPU_HOST",
        true,
    )
    .await;

    // Reconcile all queued segments before instance allocation so later loopback allocation uses
    // ready DPU/VPC segments.
    network_controller.run_single_iteration().await;
    network_controller.run_single_iteration().await;
    let first_vpc =
        db::vpc::find_by_segment(&harness.api().database_connection, first_vpc_segments[0])
            .await
            .unwrap()
            .expect("first segment belongs to a VPC")
            .id;
    // Make the multi-DPU host eligible for the later DPF attachment, then
    // resolve explicit locators so each host interface owns a known DPU/VPC pair.
    let managed_host = create_ready_host(
        harness,
        &site_explorer,
        &boot,
        service_vpc_test_host_config().with_dpu_count(2),
    )
    .await;
    let mut txn = harness.db_txn().await;
    db::machine::mark_machine_ingestion_done_with_dpf(&mut txn, &managed_host.host.id)
        .await
        .unwrap();
    let host = managed_host.host.db_machine(&mut txn).await;
    let dpu_locators = managed_host
        .dpu_ids()
        .iter()
        .map(|dpu_id| {
            host.get_device_locator_for_dpu_id(dpu_id)
                .expect("fixture DPU has a device locator")
        })
        .collect_vec();
    txn.commit().await.unwrap();

    // `device`, `device_instance`, `network_segment_id`, `function_type`, and
    // `virtual_function_id` drive exact DPU/VPC membership. The
    // remaining fields represent an otherwise empty caller-owned interface.
    let network_interface =
        |locator: &DeviceLocator,
         segment_id: NetworkSegmentId,
         function_type: rpc::InterfaceFunctionType,
         virtual_function_id: Option<u32>| rpc::InstanceInterfaceConfig {
            function_type: function_type as i32,
            network_segment_id: Some(segment_id),
            network_details: None,
            device: Some(locator.device.clone()),
            device_instance: locator.device_instance as u32,
            virtual_function_id,
            ip_address: None,
            ipv6_interface_config: None,
            routing_profile: None,
        };
    let initial_network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            // DPU 0/VPC 1 must later release despite DPU 1 retaining VPC 1.
            network_interface(
                &dpu_locators[0],
                first_vpc_segments[0],
                rpc::InterfaceFunctionType::Physical,
                None,
            ),
            // DPU 0/VPC 2 must later remain solely because of its service endpoint.
            network_interface(
                &dpu_locators[0],
                second_vpc_segments[0],
                rpc::InterfaceFunctionType::Virtual,
                Some(0),
            ),
            // DPU 1/VPC 1 remains a host membership after the update.
            network_interface(
                &dpu_locators[1],
                first_vpc_segments[1],
                rpc::InterfaceFunctionType::Physical,
                None,
            ),
            // DPU 1/VPC 2 must release despite the service endpoint on DPU 0.
            network_interface(
                &dpu_locators[1],
                second_vpc_segments[1],
                rpc::InterfaceFunctionType::Virtual,
                Some(0),
            ),
        ],
        #[allow(deprecated)]
        auto: false,
        auto_config: None,
    };
    let instance = managed_host
        .instance_builder(harness)
        .tenant_org(FIXTURE_TENANT_ORG_ID)
        .network(initial_network)
        .build()
        .await;
    Box::pin(advance_instance_to_ready(
        &env,
        &network_controller,
        &managed_host,
        &instance,
    ))
    .await;

    // Capture all four pool values before the update so retained and released
    // ownership can be verified independently after reconciliation.
    let initial_memberships = [
        // This pair loses host membership and has no service-interface membership.
        (managed_host.dpu_ids()[0], first_vpc),
        // This pair loses host membership but gains service-interface membership.
        (managed_host.dpu_ids()[0], second_vpc),
        // This pair keeps host membership.
        (managed_host.dpu_ids()[1], first_vpc),
        // This pair loses host membership and must not inherit the other DPU's service-interface membership.
        (managed_host.dpu_ids()[1], second_vpc),
    ];
    let mut initial_loopbacks = HashMap::new();
    let mut txn = harness.db_txn().await;
    for (dpu_id, vpc_id) in initial_memberships {
        let loopback = db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_id, &vpc_id)
            .await
            .unwrap()
            .expect("initial host membership has a loopback");
        initial_loopbacks.insert((dpu_id, vpc_id), loopback.loopback_ip.to_string());
    }
    assert_eq!(initial_loopbacks.values().collect::<HashSet<_>>().len(), 4);
    txn.rollback().await.unwrap();

    // Persist a DPF service registration and a service interface on DPU 0/VPC 2.
    create_fixture_tenant(harness, "best_org").await.unwrap();
    let service = create_networked_dpf_service(
        harness,
        "exact-loopback-retention-service",
        rpc::forge::DpuExtensionServiceDpuTarget::Primary,
    )
    .await
    .unwrap();
    let service_version = service
        .latest_version_info
        .as_ref()
        .expect("created service has a version")
        .version
        .clone();
    seed_networked_attachment(
        harness,
        instance.id,
        managed_host.dpu_ids()[0],
        &service,
        second_vpc,
    )
    .await
    .unwrap();

    // Keep DPU 1/VPC 1 as exact caller intent while an unrelated FNN path keeps the primary DPU
    // eligible and the service selection independently retains DPU 0/VPC 2.
    let requested_config = rpc::InstanceConfig {
        tenant: Some(rpc::TenantConfig {
            tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
            ..default_tenant_config()
        }),
        os: Some(default_os_config()),
        network: Some(rpc::InstanceNetworkConfig {
            interfaces: vec![
                // Keep this interface first so the unresolved-locator phase makes VPC 1 ambiguous.
                network_interface(
                    &dpu_locators[1],
                    first_vpc_segments[1],
                    rpc::InterfaceFunctionType::Physical,
                    None,
                ),
                // Keep the primary DPU on an unrelated FNN path without retaining DPU 0/VPC 1.
                network_interface(
                    &dpu_locators[0],
                    primary_dpu_host_segment,
                    rpc::InterfaceFunctionType::Physical,
                    None,
                ),
            ],
            #[allow(deprecated)]
            auto: false,
            auto_config: None,
        }),
        dpu_extension_services: Some(rpc::forge::InstanceDpuExtensionServicesConfig {
            service_configs: vec![rpc::forge::InstanceDpuExtensionServiceConfig {
                service_id: service.service_id,
                version: service_version,
                // Only DPU 0/VPC 2 has a service endpoint and may be retained by it.
                service_vpc_ids: vec![second_vpc],
            }],
        }),
        ..Default::default()
    };
    let requested_metadata = rpc::Metadata {
        name: "exact-loopback-membership".to_string(),
        description: "tests/instance".to_string(),
        labels: vec![],
    };

    // Stage the request through the public API before replacing only its pending locator to model
    // persisted pre-fix state that cleanup must tolerate.
    harness
        .api()
        .update_instance_config(Request::new(rpc::forge::InstanceConfigUpdateRequest {
            if_version_match: None,
            config: Some(requested_config.clone()),
            instance_id: Some(instance.id),
            metadata: Some(requested_metadata.clone()),
        }))
        .await
        .unwrap();

    // Make the retained locator unresolvable without changing its VPC or allocated resources.
    let mut txn = harness.db_txn().await;
    let mut pending_request = instance
        .db_instance(&mut txn)
        .await
        .update_network_config_request
        .expect("the valid network replacement must be pending");
    let unresolved_locator = DeviceLocator {
        // The absent device drives resolution failure while the index keeps the locator explicit.
        device: "removed-bluefield-device".to_string(),
        device_instance: 0,
    };
    pending_request
        .new_config
        .interfaces
        .first_mut()
        .expect("the replacement retains one host interface")
        .device_locator = Some(unresolved_locator);
    sqlx::query("UPDATE instances SET update_network_config_request = $1 WHERE id = $2")
        .bind(sqlx::types::Json(pending_request))
        .bind(instance.id)
        .execute(txn.as_mut())
        .await
        .expect("persist the unresolved pending locator");
    txn.commit().await.unwrap();

    network_update_to_ready(&env, &network_controller, &managed_host, false).await;

    // Reload after reconciliation to prove stale cleanup completed, retained the ambiguous VPC
    // on both current DPUs, and independently released DPU 1/VPC 2.
    let mut txn = harness.db_txn().await;
    assert_eq!(
        managed_host.snapshot(&mut txn).await.managed_state,
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready,
        }
    );
    assert!(
        instance
            .db_instance(&mut txn)
            .await
            .update_network_config_request
            .is_none()
    );
    assert_eq!(
        managed_host.dpu_ids().len(),
        2,
        "the fixture must prove ambiguous ownership across multiple DPUs"
    );
    for dpu_id in managed_host.dpu_ids().iter().copied() {
        let expected_loopback = &initial_loopbacks[&(dpu_id, first_vpc)];
        assert_eq!(
            db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_id, &first_vpc)
                .await
                .unwrap()
                .expect("ambiguous VPC ownership retains every current DPU loopback")
                .loopback_ip
                .to_string(),
            *expected_loopback,
        );
        let entry = db::resource_pool::find_value(&mut *txn, expected_loopback)
            .await
            .unwrap()
            .into_iter()
            .find(|entry| {
                entry.pool_name
                    == harness
                        .api()
                        .common_pools()
                        .ethernet
                        .pool_vpc_dpu_loopback_ip
                        .name()
            })
            .expect("ambiguously retained loopback remains in its pool");
        assert_eq!(
            entry.state.0,
            ResourcePoolEntryState::Allocated {
                owner: dpu_id.to_string(),
                owner_type: OwnerType::Machine.to_string(),
            }
        );
    }
    let released_loopback = &initial_loopbacks[&(managed_host.dpu_ids()[1], second_vpc)];
    assert!(
        db::vpc_dpu_loopback::find(txn.as_mut(), &managed_host.dpu_ids()[1], &second_vpc)
            .await
            .unwrap()
            .is_none()
    );
    let released_entry = db::resource_pool::find_value(&mut *txn, released_loopback)
        .await
        .unwrap()
        .into_iter()
        .find(|entry| {
            entry.pool_name
                == harness
                    .api()
                    .common_pools()
                    .ethernet
                    .pool_vpc_dpu_loopback_ip
                    .name()
        })
        .expect("exactly released loopback remains represented in its pool");
    assert_eq!(released_entry.state.0, ResourcePoolEntryState::Free);
    txn.rollback().await.unwrap();

    // Restore the valid DPU 1/VPC 1 locator through the public API so the original exact-release
    // contract remains covered after stale cleanup.
    harness
        .api()
        .update_instance_config(Request::new(rpc::forge::InstanceConfigUpdateRequest {
            if_version_match: None,
            config: Some(requested_config),
            instance_id: Some(instance.id),
            metadata: Some(requested_metadata),
        }))
        .await
        .unwrap();
    network_update_to_ready(&env, &network_controller, &managed_host, false).await;

    // Each retained pair from the original four-pair matrix keeps its row and exact pool owner.
    let retained_memberships = [
        // Host membership on DPU 1 retains VPC 1.
        (managed_host.dpu_ids()[1], first_vpc),
        // Service membership on DPU 0 retains VPC 2.
        (managed_host.dpu_ids()[0], second_vpc),
    ];
    let mut txn = harness.db_txn().await;
    for (dpu_id, vpc_id) in retained_memberships {
        let expected_loopback = &initial_loopbacks[&(dpu_id, vpc_id)];
        assert_eq!(
            db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_id, &vpc_id)
                .await
                .unwrap()
                .expect("retained membership keeps its loopback")
                .loopback_ip
                .to_string(),
            *expected_loopback,
        );
        let entry = db::resource_pool::find_value(&mut *txn, expected_loopback)
            .await
            .unwrap()
            .into_iter()
            .find(|entry| {
                entry.pool_name
                    == harness
                        .api()
                        .common_pools()
                        .ethernet
                        .pool_vpc_dpu_loopback_ip
                        .name()
            })
            .expect("retained loopback remains in its pool");
        assert_eq!(
            entry.state.0,
            ResourcePoolEntryState::Allocated {
                owner: dpu_id.to_string(),
                owner_type: OwnerType::Machine.to_string(),
            }
        );
    }

    // Each unrelated released pair loses its row and returns its pool value.
    let released_memberships = [
        // DPU 0/VPC 1 is not retained by DPU 1's host membership.
        (managed_host.dpu_ids()[0], first_vpc),
        // DPU 1/VPC 2 is not retained by DPU 0's service endpoint.
        (managed_host.dpu_ids()[1], second_vpc),
    ];
    for (dpu_id, vpc_id) in released_memberships {
        let released_loopback = &initial_loopbacks[&(dpu_id, vpc_id)];
        assert!(
            db::vpc_dpu_loopback::find(txn.as_mut(), &dpu_id, &vpc_id)
                .await
                .unwrap()
                .is_none()
        );
        let entry = db::resource_pool::find_value(&mut *txn, released_loopback)
            .await
            .unwrap()
            .into_iter()
            .find(|entry| {
                entry.pool_name
                    == harness
                        .api()
                        .common_pools()
                        .ethernet
                        .pool_vpc_dpu_loopback_ip
                        .name()
            })
            .expect("released loopback remains represented in its pool");
        assert_eq!(entry.state.0, ResourcePoolEntryState::Free);
    }
    txn.rollback().await.unwrap();
}

const TEST_DPF_HELM_SERVICE_DATA: &str = r#"{
    "repoURL": "oci://registry.example.com/charts",
    "chartName": "tenant-service",
    "chartVersion": "1.2.3",
    "serviceID": "tenant-service-v1",
    "deployInCluster": false,
    "security": {"privileged": false}
}"#;

/// Supplies the BF3 deployment lookup used when service-VPC tests revalidate endpoint placement
/// without exercising DPF resource provisioning.
fn service_vpc_deployment_mock() -> Arc<dyn DpfOperations> {
    let mut dpf_sdk = MockDpfOperations::new();
    dpf_sdk
        .expect_deployment_type_for_dpu()
        .returning(|_, _| Ok(DpuDeploymentType::Bf3));
    Arc::new(dpf_sdk)
}

/// Extends the deployment lookup with the placement-label calls the Assigned/Ready handler makes
/// for an attached DPF Helm service. A test controller pass keeps dispatching while another host's
/// task is in flight, so a host can reach that handler before the test's state checks run.
fn service_vpc_placement_mock() -> Arc<dyn DpfOperations> {
    let mut dpf_sdk = MockDpfOperations::new();
    dpf_sdk
        .expect_deployment_type_for_dpu()
        .returning(|_, _| Ok(DpuDeploymentType::Bf3));
    dpf_sdk
        .expect_merge_dpu_device_node_labels()
        .returning(|_, _| Ok(()));
    dpf_sdk
        .expect_get_dpu_device_node_labels()
        .returning(|_| Ok(Default::default()));
    Arc::new(dpf_sdk)
}

/// Keeps site-level DPF APIs enabled while routing fixture hosts through ordinary ingestion.
fn service_vpc_test_host_config() -> ManagedHostConfig {
    let mut host_config = ManagedHostConfig::default();
    host_config.expected_machine_data = Some(ExpectedMachineData {
        dpf_enabled: Some(false),
        ..Default::default()
    });
    host_config
}

/// Creates an FNN VPC without children so coordinator classification tests can delete it before
/// constructing caller selections.
async fn create_fnn_vpc(harness: &TestHarness, name: &str) -> VpcId {
    harness
        .api()
        .create_vpc(
            VpcCreationRequest::builder(FIXTURE_TENANT_ORG_ID)
                .metadata(Metadata {
                    name: name.to_string(),
                    ..Default::default()
                })
                .network_virtualization_type(rpc::forge::VpcVirtualizationType::Fnn as i32)
                .tonic_request(),
        )
        .await
        .expect("FNN VPC fixture must be created")
        .into_inner()
        .id
        .expect("created VPC has an ID")
}

/// Registers one DPF service with explicit placement and address family so admission tests can
/// vary those immutable contracts without duplicating unrelated registration fields.
async fn create_networked_dpf_service(
    harness: &TestHarness,
    service_name: &str,
    dpu_target: rpc::forge::DpuExtensionServiceDpuTarget,
) -> Result<DpuExtensionService, tonic::Status> {
    Ok(harness
        .api()
        .create_dpu_extension_service(Request::new(rpc::forge::CreateDpuExtensionServiceRequest {
            dpu_target: Some(dpu_target as i32),
            service_vpc_interfaces: vec![rpc::forge::ServiceVpcInterfaceRequirement {
                address_family: rpc::forge::ServiceVpcAddressFamily::Ipv4 as i32,
            }],
            service_id: None,
            service_name: service_name.to_string(),
            description: None,
            tenant_organization_id: "best_org".to_string(),
            service_type: rpc::forge::DpuExtensionServiceType::DpfHelmChart.into(),
            data: TEST_DPF_HELM_SERVICE_DATA.replace("tenant-service-v1", service_name),
            credential: None,
            observability: None,
            deployment_type: 0,
        }))
        .await?
        .into_inner())
}

async fn seed_networked_attachment(
    harness: &TestHarness,
    instance_id: InstanceId,
    dpu_id: DpuMachineId,
    service: &DpuExtensionService,
    vpc_id: VpcId,
) -> Result<InstanceServiceInterfaceConfig, Box<dyn std::error::Error>> {
    let parent_id = create_tenant_overlay_prefix_with_prefix(
        harness,
        vpc_id,
        "seeded service VPC IPv4 prefix",
        "10.219.0.0/30".parse()?,
    )
    .await;
    carbide_api_core::test_support::extension_service::seed_networked_attachment(
        harness.api(),
        instance_id,
        dpu_id,
        service,
        parent_id,
    )
    .await
}
