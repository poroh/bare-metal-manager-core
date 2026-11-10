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
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::SystemTime;

use carbide_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials};
use carbide_test_harness::TestNetworkSegment;
use carbide_test_harness::dns::TestDomain;
use carbide_test_harness::network::controller::TestNetworkController;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::network_segment::{
    FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS, FIXTURE_TENANT_ORG_ID,
};
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::{DpuMachineId, HostMachineId, StableHostMachineId};
use carbide_uuid::machine_validation::MachineValidationId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use db::ObjectColumnFilter;
use ipnetwork::{IpNetwork, Ipv4Network};
use model::expected_machine::ExpectedMachineData;
use model::instance::config::network::DeviceLocator;
use model::machine::health_override::HARDWARE_HEALTH_OVERRIDE_PREFIX;
use model::machine::{
    CleanupContext, CleanupState, InstanceState, MachineState, MachineValidatingState,
    ManagedHostState, NetworkConfigUpdateState, ValidationState,
};
use model::metadata::Metadata;
use model::resource_pool::{self, Range, ResourcePoolDef, ResourcePoolType};
use model::test_support::ManagedHostConfig;
use model::vpc_prefix::VpcPrefixConfig;
use rpc::Timestamp;
use rpc::forge::instance_interface_config::NetworkDetails;
use rpc::forge::{InstanceReleaseRequest, VpcCreationRequest};
use tonic::IntoRequest;

use crate::env::Env;

/// The domain and ready DHCP segments used to discover a test host.
/// Contains data only; the caller owns the API, explorer and controllers.
pub(super) struct BootNetworks {
    pub(super) domain: TestDomain,
    pub(super) admin: TestNetworkSegment,
    pub(super) underlay: TestNetworkSegment,
}

pub(super) async fn create_boot_networks(
    harness: &TestHarness,
    network_controller: &TestNetworkController,
) -> BootNetworks {
    let domain = harness.create_test_domain("dwrt1.com").await;
    let admin = network_controller.create_admin_segment(&domain).await;
    let underlay = network_controller.create_underlay_segment(&domain).await;
    BootNetworks {
        domain,
        admin,
        underlay,
    }
}

/// Matches legacy site-prefix capacity, including reserved VNIs and per-VPC DPU loopbacks.
pub(super) fn instance_resource_pools() -> HashMap<String, ResourcePoolDef> {
    let pool_size = u32::try_from(FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS.len() + 2).unwrap();
    let mut pools = ResourcePoolBuilder::default()
        .with_vlan_ids(1, pool_size)
        .with_vnis(10_001, 10_000 + pool_size)
        .with_integer_pool(resource_pool::common::DPA_VNI, 40_001, 40_000 + pool_size)
        .with_integer_pool(
            resource_pool::common::EXTERNAL_VPC_VNI,
            50_001,
            50_000 + pool_size,
        )
        .with_integer_pool(resource_pool::common::FNN_ASN, 30_001, 30_035)
        .build();
    // Match the legacy fixture's capacity, including the reserved VPC VNI range.
    pools.insert(
        resource_pool::common::VPC_VNI.to_string(),
        ResourcePoolDef {
            pool_type: ResourcePoolType::Integer,
            ranges: vec![
                Range {
                    start: "20001".into(),
                    end: (20_000 + pool_size).to_string(),
                    auto_assign: true,
                },
                Range {
                    start: "60001".into(),
                    end: (60_000 + pool_size).to_string(),
                    auto_assign: false,
                },
            ],
            prefix: None,
            delegate_prefix_len: None,
        },
    );
    pools.insert(
        resource_pool::common::VPC_DPU_LOOPBACK.to_string(),
        ResourcePoolDef {
            pool_type: ResourcePoolType::Ipv4,
            ranges: vec![Range {
                start: "10.255.255.0".into(),
                end: "10.255.255.127".into(),
                auto_assign: true,
            }],
            prefix: None,
            delegate_prefix_len: None,
        },
    );

    pools
}

pub(super) async fn until(
    env: &Env,
    id: &HostMachineId,
    max_iterations: u32,
    expected: ManagedHostState,
) {
    let harness = &env.test_harness;
    for _ in 0..max_iterations {
        env.run_single_iteration_ext(true).await;
        let mut txn = harness.db_txn().await;
        let machine = db::machine::find_one(txn.as_mut(), id, Default::default())
            .await
            .unwrap()
            .unwrap();
        txn.rollback().await.unwrap();
        let mut expected = expected.clone();
        // Validation IDs are allocated by the controller; retain all the caller's other fields.
        if let ManagedHostState::Validation {
            validation_state:
                ValidationState::MachineValidation {
                    machine_validation:
                        MachineValidatingState::MachineValidating { context, id, .. },
                },
        } = &mut expected
        {
            *id = if context == "Cleanup" {
                machine.cleanup_machine_validation_id
            } else if context == "OnDemand" {
                machine.on_demand_machine_validation_id
            } else {
                machine.discovery_machine_validation_id
            }
            .unwrap_or_default();
        }
        if machine.current_state() == &expected {
            return;
        }
    }
    let machine = harness
        .api()
        .find_machines_by_ids(
            rpc::forge::MachinesByIdsRequest {
                machine_ids: vec![(*id).into()],
                include_history: true,
            }
            .into_request(),
        )
        .await
        .unwrap()
        .into_inner();
    panic!(
        "Expected Machine state condition not hit after {max_iterations} iterations; state is {:?}",
        machine.machines
    );
}

/// Creates one Ready host through the supplied explorer and DHCP networks.
/// Records the reboot, hardware health, BIOS setup and credentials established by legacy ingestion.
/// Instance provisioning is driven separately by the caller.
pub(super) async fn create_ready_host(
    harness: &TestHarness,
    site_explorer: &TestSiteExplorer,
    boot: &BootNetworks,
    config: ManagedHostConfig,
) -> TestManagedHost {
    // Legacy ingestion always fills the serial, including when a test supplies DPF overrides.
    let config = ManagedHostConfig {
        expected_machine_data: Some(ExpectedMachineData {
            serial_number: config.serial.clone(),
            ..config.expected_machine_data.unwrap_or_default()
        }),
        ..config
    };
    // Box ingestion steps, as the legacy fixture does, to bound the worker stack.
    let mut mh = Box::pin(
        harness
            .managed_host_builder(site_explorer, boot.underlay)
            .with_config(config)
            .with_dpu_network_status_reported()
            .build(),
    )
    .await
    .0;
    Box::pin(mh.host.discover_primary_iface(boot.admin)).await;
    Box::pin(mh.host.reboot_completed()).await;
    Box::pin(
        harness.api().insert_machine_health_report(
            rpc::forge::InsertMachineHealthReportRequest {
                machine_id: Some(mh.host.id.into()),
                health_report_entry: Some(rpc::forge::HealthReportEntry {
                    report: Some(
                        health_report::HealthReport::empty(format!(
                            "{HARDWARE_HEALTH_OVERRIDE_PREFIX}health"
                        ))
                        .into(),
                    ),
                    ..Default::default()
                }),
            }
            .into_request(),
        ),
    )
    .await
    .unwrap();
    Box::pin(mh.advance_to_converged_ready()).await;
    // Completed ingestion records BIOS setup before a Ready host can share controller ticks.
    let mut txn = harness.db_txn().await;
    db::machine::update_bios_password_set_time(&mh.host.id, txn.as_mut())
        .await
        .unwrap();
    txn.commit().await.unwrap();
    for bmc_mac_address in
        std::iter::once(mh.host.bmc_mac).chain(mh.dpus.iter().map(|dpu| dpu.bmc_mac))
    {
        harness
            .api()
            .credential_manager()
            .set_credentials(
                &CredentialKey::BmcCredentials {
                    credential_type: BmcCredentialType::BmcRoot { bmc_mac_address },
                },
                &Credentials::UsernamePassword {
                    username: "root".into(),
                    password: "notforprod".into(),
                },
            )
            .await
            .unwrap();
    }
    Box::pin(report_network(&mh)).await;
    mh
}

pub(super) async fn report_network(mh: &TestManagedHost) {
    for dpu in &mh.dpus {
        let status = dpu.network_status().dpu_agent_version("test").build().await;
        mh.api
            .record_dpu_network_status(status.into_request())
            .await
            .unwrap();
    }
}

pub(super) async fn advance_instance_to_ready(
    env: &Env,
    network_controller: &TestNetworkController,
    mh: &TestManagedHost,
    instance: &TestInstance,
) {
    let harness = &env.test_harness;
    network_controller.run_single_iteration().await;
    until(
        env,
        &mh.host.id,
        10,
        assigned(InstanceState::WaitingForNetworkConfig),
    )
    .await;
    assert_eq!(
        history(mh, 4).await,
        vec![
            assigned(InstanceState::DpaProvisioning),
            assigned(InstanceState::WaitingForDpaToBeReady),
            assigned(InstanceState::WaitingForNetworkSegmentToBeReady),
            assigned(InstanceState::WaitingForNetworkConfig)
        ]
    );
    report_network(mh).await;
    env.run_single_iteration_ext(true).await;

    harness
        .api()
        .insert_machine_health_report(
            rpc::forge::InsertMachineHealthReportRequest {
                machine_id: Some(mh.host.id.into()),
                health_report_entry: Some(rpc::forge::HealthReportEntry {
                    report: Some(
                        health_report::HealthReport::empty(format!(
                            "{HARDWARE_HEALTH_OVERRIDE_PREFIX}health"
                        ))
                        .into(),
                    ),
                    ..Default::default()
                }),
            }
            .into_request(),
        )
        .await
        .unwrap();
    until(env, &mh.host.id, 20, assigned(InstanceState::Ready)).await;
    assert_eq!(
        history(mh, 2).await,
        vec![
            assigned(InstanceState::WaitingForRebootToReady),
            assigned(InstanceState::Ready)
        ]
    );
    instance.rpc_instance().await;
}

pub(super) async fn network_update_to_ready(
    env: &Env,
    network_controller: &TestNetworkController,
    mh: &TestManagedHost,
    interfaces_added: bool,
) {
    if interfaces_added {
        network_controller.run_single_iteration().await;
    }
    until(
        env,
        &mh.host.id,
        10,
        assigned(InstanceState::NetworkConfigUpdate {
            network_config_update_state: NetworkConfigUpdateState::WaitingForConfigSynced,
        }),
    )
    .await;
    report_network(mh).await;
    until(env, &mh.host.id, 10, assigned(InstanceState::Ready)).await;
}

pub(super) async fn find_instance(harness: &TestHarness, instance_id: InstanceId) -> rpc::Instance {
    let mut instances = find_instances(harness, vec![instance_id]).await.instances;
    assert_eq!(instances.len(), 1);
    instances.remove(0)
}

pub(super) async fn find_instances(
    harness: &TestHarness,
    instance_ids: Vec<InstanceId>,
) -> rpc::forge::InstanceList {
    harness
        .api()
        .find_instances_by_ids(rpc::forge::InstancesByIdsRequest { instance_ids }.into_request())
        .await
        .unwrap()
        .into_inner()
}

pub(super) async fn delete_instance(
    env: &Env,
    network_controller: &TestNetworkController,
    mh: &TestManagedHost,
    instance_id: InstanceId,
) {
    let harness = &env.test_harness;
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

    // The instance should show up immediatly as terminating - even if the state handler didn't yet run
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
        env,
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

    report_network(mh).await;

    until(
        env,
        &mh.host.id,
        2,
        ManagedHostState::Assigned {
            instance_state: model::machine::InstanceState::WaitingForDpusToUp,
        },
    )
    .await;

    report_network(mh).await;

    until(
        env,
        &mh.host.id,
        1,
        ManagedHostState::Assigned {
            instance_state: model::machine::InstanceState::BootingWithDiscoveryImage {
                retry: model::machine::RetryInfo { count: 0 },
            },
        },
    )
    .await;
    finish_cleanup(env, mh).await;

    assert!(
        find_instances(harness, vec![instance_id])
            .await
            .instances
            .is_empty()
    );

    // Run network state machine handler here.
    network_controller.run_single_iteration().await;
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    network_controller.run_single_iteration().await;
    network_controller.run_single_iteration().await;
}

pub(super) async fn finish_cleanup(env: &Env, mh: &TestManagedHost) {
    let harness = &env.test_harness;
    let mut txn = harness.api().database_connection.begin().await.unwrap();
    let machine = mh.host.db_machine(&mut txn).await;
    db::machine::update_reboot_time(&machine, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    // Run state machine twice.
    // First DeletingManagedResource updates use_admin_network, transitions to WaitingForNetworkReconfig
    // Second to discover we are now in WaitingForNetworkReconfig
    until(
        env,
        &mh.host.id,
        2,
        ManagedHostState::Assigned {
            instance_state: model::machine::InstanceState::WaitingForNetworkReconfig,
        },
    )
    .await;

    // Apply switching back to admin network
    report_network(mh).await;
    env.run_single_iteration_ext(true).await;

    until(
        env,
        &mh.host.id,
        3,
        ManagedHostState::WaitingForCleanup {
            cleanup_state: CleanupState::HostCleanup {
                boss_controller_id: None,
            },
            cleanup_context: CleanupContext::Deprovision,
        },
    )
    .await;

    let mut txn = harness.api().database_connection.begin().await.unwrap();
    let machine = mh.host.db_machine(&mut txn).await;
    db::machine::update_reboot_time(&machine, &mut txn)
        .await
        .unwrap();
    db::machine::update_cleanup_time(&machine, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    until(
        env,
        &mh.host.id,
        3,
        ManagedHostState::Validation {
            validation_state: ValidationState::MachineValidation {
                machine_validation: MachineValidatingState::MachineValidating {
                    context: "Cleanup".to_string(),
                    id: MachineValidationId::new(),
                    completed: 1,
                    total: 1,
                    is_enabled: true,
                },
            },
        },
    )
    .await;

    let mut machine_validation_result = rpc::forge::MachineValidationResult {
        validation_id: None,
        name: "instance".to_string(),
        description: "desc".to_string(),
        command: "echo".to_string(),
        args: "test".to_string(),
        std_out: "".to_string(),
        std_err: "".to_string(),
        context: "Cleanup".to_string(),
        exit_code: 0,
        start_time: Some(Timestamp::from(SystemTime::now())),
        end_time: Some(Timestamp::from(SystemTime::now())),
        test_id: Some("instance".to_string()),
    };

    mh.host.reboot_completed().await;
    let response = mh.host.forge_agent_control().await;
    let validation_id = &response.data.unwrap().pair[1].value;

    machine_validation_result.validation_id = Some(validation_id.parse().unwrap());
    harness
        .api()
        .persist_validation_result(
            rpc::forge::MachineValidationResultPostRequest {
                result: Some(machine_validation_result.clone()),
            }
            .into_request(),
        )
        .await
        .unwrap();

    let mut txn = harness.api().database_connection.begin().await.unwrap();
    db::machine::update_machine_validation_time(&mh.host.id, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    until(
        env,
        &mh.host.id,
        3,
        ManagedHostState::HostInit {
            machine_state: MachineState::Discovered {
                skip_reboot_wait: false,
            },
        },
    )
    .await;

    let mut txn = harness.api().database_connection.begin().await.unwrap();
    let machine = mh.host.db_machine(&mut txn).await;
    db::machine::update_reboot_time(&machine, &mut txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    until(env, &mh.host.id, 3, ManagedHostState::Ready).await;
}

pub(super) async fn create_tenant_segments(
    harness: &TestHarness,
    network_controller: &TestNetworkController,
    domain: &TestDomain,
    details: rpc::forge::VpcCreationRequest,
    count: usize,
) -> Vec<NetworkSegmentId> {
    let vpc = harness
        .api()
        .create_vpc(details.into_request())
        .await
        .unwrap()
        .into_inner()
        .id;
    let mut segments = Vec::new();
    for prefix in FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS.iter().take(count) {
        segments.push(
            create_tenant_network_segment(harness, domain, vpc, *prefix, "TENANT", true).await,
        );
        network_controller.run_single_iteration().await;
        network_controller.run_single_iteration().await;
    }
    segments
}

pub(super) async fn create_dual_tenant_segments(
    harness: &TestHarness,
    network_controller: &TestNetworkController,
    domain: &TestDomain,
) -> (NetworkSegmentId, NetworkSegmentId) {
    let first =
        create_tenant_segments(harness, network_controller, domain, default_vpc_config(), 1).await
            [0];
    let vpc = db::vpc::find_by_segment(&harness.api().database_connection, first)
        .await
        .unwrap()
        .unwrap();
    let second = create_tenant_network_segment(
        harness,
        domain,
        Some(vpc.id),
        FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1],
        "TENANT2",
        false,
    )
    .await;
    network_controller.run_single_iteration().await;
    network_controller.run_single_iteration().await;
    (first, second)
}

pub(super) async fn create_peer_tenant_segments(
    harness: &TestHarness,
    network_controller: &TestNetworkController,
    domain: &TestDomain,
    first_type: rpc::forge::VpcVirtualizationType,
    second_type: rpc::forge::VpcVirtualizationType,
) -> PeerVpcSegments {
    let first_vpc = harness
        .api()
        .create_vpc(
            VpcCreationRequest::builder(FIXTURE_TENANT_ORG_ID)
                .metadata(Metadata {
                    name: "test vpc".into(),
                    ..Default::default()
                })
                .network_virtualization_type(first_type)
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner()
        .id;
    let first_segment_id = create_tenant_network_segment(
        harness,
        domain,
        first_vpc,
        FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[0],
        "TENANT1",
        true,
    )
    .await;
    network_controller.run_single_iteration().await;
    network_controller.run_single_iteration().await;
    let second_vpc = harness
        .api()
        .create_vpc(
            VpcCreationRequest::builder("e65a9d69-39d2-4872-a53e-e5cb87c84e75")
                .metadata(Metadata {
                    name: "test peer vpc".into(),
                    ..Default::default()
                })
                .network_virtualization_type(second_type)
                .tonic_request(),
        )
        .await
        .unwrap()
        .into_inner()
        .id;
    let second_segment_id = create_tenant_network_segment(
        harness,
        domain,
        second_vpc,
        FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1],
        "TENANT2",
        true,
    )
    .await;
    network_controller.run_single_iteration().await;
    network_controller.run_single_iteration().await;
    PeerVpcSegments {
        first_vpc,
        first_segment_id,
        second_vpc,
        second_segment_id,
    }
}

pub(super) fn fnn_config() -> carbide_api_core::cfg::file::FnnConfig {
    use carbide_api_core::cfg::file::{FnnConfig, FnnRoutingProfileConfig};
    FnnConfig {
        admin_vpc: None,
        common_internal_route_target: None,
        additional_route_target_imports: vec![],
        routing_profiles: HashMap::from([
            (
                "EXTERNAL".into(),
                FnnRoutingProfileConfig {
                    access_tier: Some(2),
                    internal: Some(false),
                    ..Default::default()
                },
            ),
            (
                "INTERNAL".into(),
                FnnRoutingProfileConfig {
                    access_tier: Some(1),
                    internal: Some(true),
                    ..Default::default()
                },
            ),
        ]),
        use_vpc_vrf_loopback: false,
    }
}

fn assigned(instance_state: InstanceState) -> ManagedHostState {
    ManagedHostState::Assigned { instance_state }
}

async fn history(mh: &TestManagedHost, limit: usize) -> Vec<ManagedHostState> {
    let states: Vec<_> = mh
        .host
        .rpc_machine()
        .await
        .events
        .into_iter()
        .map(|event| serde_json::from_str::<ManagedHostState>(&event.event).unwrap())
        .collect();
    states[states.len().saturating_sub(limit)..].to_vec()
}

pub(super) fn default_instance_config() -> rpc::InstanceConfig {
    rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(default_os_config()),
        ..Default::default()
    }
}

pub(super) async fn create_tenant_network_segment(
    harness: &TestHarness,
    domain: &TestDomain,
    vpc_id: Option<VpcId>,
    network: IpNetwork,
    name: &str,
    include_subdomain: bool,
) -> NetworkSegmentId {
    harness
        .api()
        .create_network_segment(
            rpc::forge::NetworkSegmentCreationRequest {
                id: None,
                mtu: Some(1500),
                name: name.into(),
                vpc_id,
                prefixes: vec![rpc::forge::NetworkPrefix {
                    prefix: IpNetwork::new(network.network(), network.prefix())
                        .unwrap()
                        .to_string(),
                    gateway: Some(network.ip().to_string()),
                    reserve_first: 3,
                    ..Default::default()
                }],
                subdomain_id: include_subdomain.then_some(domain.id),
                segment_type: rpc::forge::NetworkSegmentType::Tenant as i32,
                infer_slaac_eui64_addresses: false,
            }
            .into_request(),
        )
        .await
        .unwrap()
        .into_inner()
        .id
        .unwrap()
}

pub(super) async fn create_fixture_tenant(
    harness: &TestHarness,
    organization_id: impl Into<String>,
) -> Result<rpc::forge::Tenant, tonic::Status> {
    let organization_id = organization_id.into();
    Ok(harness
        .api()
        .create_tenant(
            rpc::forge::CreateTenantRequest {
                organization_id: organization_id.clone(),
                routing_profile_type: None,
                metadata: Some(rpc::Metadata {
                    name: organization_id,
                    ..Default::default()
                }),
            }
            .into_request(),
        )
        .await?
        .into_inner()
        .tenant
        .unwrap())
}

pub(super) fn interface_network_config_with_devices(
    segment_ids: &[NetworkSegmentId],
    device_locators: &[DeviceLocator],
) -> rpc::InstanceNetworkConfig {
    let interfaces = device_locators
        .iter()
        .zip(segment_ids)
        .map(|(dl, segment_id)| rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(*segment_id),
            network_details: Some(NetworkDetails::SegmentId(*segment_id)),
            device: Some(dl.device.clone()),
            device_instance: dl.device_instance as u32,
            virtual_function_id: None,
            ip_address: None,
            ipv6_interface_config: None,
            routing_profile: None,
        })
        .collect();
    rpc::InstanceNetworkConfig {
        interfaces,
        #[allow(deprecated)]
        auto: false,
        auto_config: None,
    }
}

pub(super) fn single_interface_network_config(
    segment_id: NetworkSegmentId,
) -> rpc::InstanceNetworkConfig {
    rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(segment_id),
            network_details: Some(NetworkDetails::SegmentId(segment_id)),
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
    }
}

pub(super) fn single_interface_network_config_with_vfs(
    segment_ids: Vec<NetworkSegmentId>,
) -> rpc::InstanceNetworkConfig {
    let mut segment_iter = segment_ids.into_iter().enumerate();
    let (_function_id, segment_id) = segment_iter.next().unwrap();
    let mut interfaces = vec![rpc::InstanceInterfaceConfig {
        function_type: rpc::InterfaceFunctionType::Physical as i32,
        network_segment_id: Some(segment_id),
        network_details: Some(NetworkDetails::SegmentId(segment_id)),
        device: None,
        device_instance: 0,
        virtual_function_id: None,
        ip_address: None,
        ipv6_interface_config: None,
        routing_profile: None,
    }];

    interfaces.extend(
        segment_iter.map(|(function_id, segment_id)| rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Virtual as i32,
            network_segment_id: Some(segment_id),
            network_details: Some(NetworkDetails::SegmentId(segment_id)),
            device: None,
            device_instance: 0,
            virtual_function_id: Some(function_id as u32),
            ip_address: None,
            ipv6_interface_config: None,
            routing_profile: None,
        }),
    );

    rpc::InstanceNetworkConfig {
        interfaces,
        #[allow(deprecated)]
        auto: false,
        auto_config: None,
    }
}

pub(super) fn single_interface_network_config_with_vpc_prefix(
    prefix_id: VpcPrefixId,
) -> rpc::InstanceNetworkConfig {
    rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: Some(NetworkDetails::VpcPrefixId(prefix_id)),
            device: None,
            device_instance: 0u32,
            virtual_function_id: None,
            ip_address: None,
            ipv6_interface_config: None,
            routing_profile: None,
        }],
        #[allow(deprecated)]
        auto: false,
        auto_config: None,
    }
}

pub(super) fn default_os_config() -> rpc::forge::InstanceOperatingSystemConfig {
    rpc::forge::InstanceOperatingSystemConfig {
        phone_home_enabled: false,
        run_provisioning_instructions_on_every_boot: false,
        user_data: Some("SomeRandomData".to_string()),
        variant: Some(rpc::forge::instance_operating_system_config::Variant::Ipxe(
            rpc::forge::InlineIpxe {
                ipxe_script: "SomeRandomiPxe".to_string(),
            },
        )),
    }
}

pub(super) fn default_tenant_config() -> rpc::TenantConfig {
    rpc::TenantConfig {
        tenant_organization_id: "Tenant1".to_string(),
        tenant_keyset_ids: vec![],
        hostname: None,
    }
}

pub(super) async fn create_tenant_overlay_prefix(
    harness: &TestHarness,
    vpc_id: VpcId,
) -> VpcPrefixId {
    create_tenant_overlay_prefix_with_prefix(
        harness,
        vpc_id,
        "vpc prefix 1",
        IpNetwork::V4(Ipv4Network::new(Ipv4Addr::new(10, 217, 5, 224), 27).unwrap()),
    )
    .await
}

/// Creates a tenant overlay VPC prefix with an explicit CIDR for allocation tests.
pub(super) async fn create_tenant_overlay_prefix_with_prefix(
    harness: &TestHarness,
    vpc_id: VpcId,
    name: &str,
    prefix: IpNetwork,
) -> VpcPrefixId {
    let mut txn = harness.db_txn().await;

    // Look up the current VPC version so the prefix insert can increment it.
    let vpcs = db::vpc::find_by(
        txn.as_mut(),
        ObjectColumnFilter::One(db::vpc::IdColumn, &vpc_id),
    )
    .await
    .unwrap();
    assert_eq!(vpcs.len(), 1);
    let expected_vpc_version = vpcs[0].version;

    // Persist the prefix directly so tests can focus on allocation behavior.
    let vpc_prefix_id = db::vpc_prefix::persist(
        model::vpc_prefix::NewVpcPrefix {
            id: uuid::Uuid::new_v4().into(),
            site_prefix_id: None,
            vpc_id,
            overlap_vpc_id: None,
            config: VpcPrefixConfig { prefix },
            metadata: Metadata {
                name: name.to_string(),
                description: "desc".to_string(),
                labels: HashMap::new(),
            },
        },
        expected_vpc_version,
        &mut txn,
    )
    .await
    .unwrap()
    .id;
    txn.commit().await.unwrap();
    vpc_prefix_id
}

pub(super) async fn update_time_params(
    pool: &sqlx::PgPool,
    machine: &model::machine::Machine<impl carbide_uuid::machine::MachineIdSubtypeTrait>,
    retry_count: i64,
    last_reboot_requested: Option<chrono::DateTime<chrono::Utc>>,
) {
    let mut txn = pool.begin().await.unwrap();
    let data = model::machine::MachineLastRebootRequested {
        time: if let Some(last_reboot_requested) = last_reboot_requested {
            last_reboot_requested
        } else {
            machine.status.last_reboot_requested.as_ref().unwrap().time
                - chrono::Duration::minutes(1)
        },
        mode: machine.status.last_reboot_requested.as_ref().unwrap().mode,
        restart_verified: None,
        verification_attempts: None,
    };

    let last_reboot_time =
        machine.status.last_reboot_time.unwrap() - chrono::Duration::minutes(2i64);

    let ts = machine.status.last_reboot_requested.as_ref().unwrap().time
        - chrono::Duration::minutes(retry_count);
    let last_discovery_time = ts - chrono::Duration::minutes(1);

    let version = format!(
        "V{}-T{}",
        machine.current_version().version_nr(),
        ts.timestamp_micros()
    );

    let query = "UPDATE machines SET last_reboot_requested=$1, controller_state_version=$3, last_reboot_time=$4, last_discovery_time=$5 WHERE id=$2 RETURNING *";
    sqlx::query(query)
        .bind(sqlx::types::Json(&data))
        .bind(machine.id.to_string())
        .bind(version)
        .bind(last_reboot_time)
        .bind(last_discovery_time)
        .execute(&mut *txn)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

/// Send a health report entry
pub(super) async fn send_health_report_entry(
    harness: &TestHarness,
    machine_id: &DpuMachineId,
    entry: (
        health_report::HealthReport,
        health_report::HealthReportApplyMode,
    ),
) {
    use rpc::forge::forge_server::Forge;
    use tonic::Request;
    let _ = harness
        .api()
        .insert_machine_health_report(Request::new(rpc::forge::InsertMachineHealthReportRequest {
            machine_id: Some((*machine_id).into()),
            health_report_entry: Some(rpc::forge::HealthReportEntry {
                report: Some(entry.0.into()),
                mode: entry.1 as i32,
            }),
        }))
        .await
        .unwrap();
}

/// Remove a health report entry
pub(super) async fn remove_health_report_entry(
    harness: &TestHarness,
    machine_id: &DpuMachineId,
    source: String,
) {
    use rpc::forge::forge_server::Forge;
    use tonic::Request;
    let _ = harness
        .api()
        .remove_machine_health_report(Request::new(rpc::forge::RemoveMachineHealthReportRequest {
            machine_id: Some((*machine_id).into()),
            source,
        }))
        .await
        .unwrap();
}

pub(super) fn host_id(mh: &TestManagedHost) -> StableHostMachineId {
    mh.host.id.try_into().unwrap()
}

pub(super) trait TestManagedHostInstanceExt {
    fn dpu_ids(&self) -> Vec<DpuMachineId>;
}

impl TestManagedHostInstanceExt for TestManagedHost {
    fn dpu_ids(&self) -> Vec<DpuMachineId> {
        self.dpus.iter().map(|dpu| dpu.id).collect()
    }
}

pub(super) struct PeerVpcSegments {
    pub(super) first_vpc: Option<VpcId>,
    pub(super) first_segment_id: NetworkSegmentId,
    pub(super) second_vpc: Option<VpcId>,
    pub(super) second_segment_id: NetworkSegmentId,
}

pub(super) fn default_vpc_config() -> rpc::forge::VpcCreationRequest {
    VpcCreationRequest::builder(FIXTURE_TENANT_ORG_ID)
        .metadata(Metadata {
            name: "test vpc 1".into(),
            ..Default::default()
        })
        .rpc()
}
