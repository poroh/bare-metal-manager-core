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

pub(super) mod controller;

use std::collections::HashMap;

use carbide_api_core::cfg::file::{FnnConfig, FnnRoutingProfileConfig};
use carbide_api_core::test_support::default_config;
use carbide_api_core::test_support::network_segment::FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS;
use carbide_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials};
use carbide_test_harness::dns::TestDomain;
use carbide_test_harness::network::controller::TestNetworkController;
use carbide_test_harness::prelude::*;
use carbide_test_harness::{CarbideConfig, TestNetworkSegment};
use carbide_uuid::machine::StableHostMachineId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use db::ObjectColumnFilter;
use ipnetwork::IpNetwork;
use model::metadata::Metadata;
use model::resource_pool;
use model::test_support::ManagedHostConfig;
use model::vpc_prefix::VpcPrefixConfig;
use rpc::forge::instance_interface_config::NetworkDetails;
use tonic::IntoRequest;

/// Data returned after explicitly creating the DHCP networks used for host discovery.
pub(super) struct BootNetworks {
    pub(super) domain: TestDomain,
    pub(super) admin: TestNetworkSegment,
    pub(super) underlay: TestNetworkSegment,
}

/// Creates the fixture domain and ready admin/underlay segments using the caller's controller.
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

/// Returns the same finite pool capacities used by the migrated instance API scenarios.
pub(super) fn instance_resource_pools(
    fnn_enabled: bool,
) -> HashMap<String, resource_pool::ResourcePoolDef> {
    let pools = ResourcePoolBuilder::default()
        .with_vlan_ids(1, 5)
        .with_vnis(10_001, 10_005)
        .with_integer_pool(resource_pool::common::DPA_VNI, 40_001, 40_005);
    if fnn_enabled {
        pools
            .with_integer_pool(resource_pool::common::EXTERNAL_VPC_VNI, 50_001, 50_005)
            .with_integer_pool(resource_pool::common::FNN_ASN, 30_001, 30_035)
            .build()
    } else {
        pools.build()
    }
}

/// Discovers one host using the supplied networks/explorer and records its stable Ready fixture.
/// Matches the API fixtures' BIOS setup, BMC credentials and agent-version defaults;
/// instance allocation and controller progression remain separate caller actions.
pub(super) async fn create_ready_host(
    harness: &TestHarness,
    site_explorer: &TestSiteExplorer,
    boot: &BootNetworks,
    config: ManagedHostConfig,
) -> TestManagedHost {
    let mut mh = harness
        .managed_host_builder(site_explorer, boot.underlay)
        .with_config(config)
        .with_dpu_network_status_reported()
        .build()
        .await
        .0;
    mh.host.discover_primary_iface(boot.admin).await;
    mh.advance_to_converged_ready().await;
    // Completed ingestion records BIOS setup; idle Ready hosts must remain stable when
    // the instance fixture drives the shared machine controller for a sibling host.
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
                    username: "root".to_string(),
                    password: "notforprod".to_string(),
                },
            )
            .await
            .unwrap();
    }
    for dpu in &mh.dpus {
        let status = dpu.network_status().dpu_agent_version("test").build().await;
        harness
            .api()
            .record_dpu_network_status(status.into_request())
            .await
            .unwrap();
    }
    mh
}

/// Creates one tenant segment and advances it to Ready with the caller's network controller.
pub(super) async fn create_ready_tenant_segment(
    api: &Api,
    network_controller: &TestNetworkController,
    domain: &TestDomain,
    vpc_id: VpcId,
    network: IpNetwork,
    name: &str,
) -> NetworkSegmentId {
    let segment = api
        .create_network_segment(
            rpc::forge::NetworkSegmentCreationRequest {
                id: None,
                mtu: Some(1500),
                name: name.to_string(),
                prefixes: vec![rpc::forge::NetworkPrefix {
                    id: None,
                    prefix: ipnetwork::IpNetwork::new(network.network(), network.prefix())
                        .unwrap()
                        .to_string(),
                    gateway: Some(network.ip().to_string()),
                    reserve_first: 3,
                    free_ip_count: 0,
                    svi_ip: None,
                    free_ip_count_v2: None,
                    free_ip_count_saturated: false,
                    dhcpv6_link_address: None,
                }],
                subdomain_id: Some(domain.id),
                vpc_id: Some(vpc_id),
                segment_type: rpc::forge::NetworkSegmentType::Tenant as i32,
                infer_slaac_eui64_addresses: false,
            }
            .into_request(),
        )
        .await
        .unwrap()
        .into_inner();
    // Get the tenant segment into ready state, as in the shared network fixtures.

    network_controller.run_single_iteration().await;
    network_controller.run_single_iteration().await;
    segment.id.unwrap()
}

pub(super) async fn tenant_segments(
    api: &Api,
    network_controller: &TestNetworkController,
    domain: &TestDomain,
    segment_id: NetworkSegmentId,
    count: usize,
) -> Vec<NetworkSegmentId> {
    let vpc_id = db::vpc::find_by_segment(&api.database_connection, segment_id)
        .await
        .unwrap()
        .unwrap()
        .id;
    let mut ids = vec![segment_id];
    for network in FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS
        .iter()
        .take(count)
        .skip(1)
    {
        ids.push(
            create_ready_tenant_segment(
                api,
                network_controller,
                domain,
                vpc_id,
                *network,
                "TENANT",
            )
            .await,
        );
    }
    ids
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

pub(super) async fn find_instances_by_label(
    api: &Api,
    label: rpc::forge::Label,
) -> rpc::forge::InstanceList {
    let instance_ids = api
        .find_instance_ids(tonic::Request::new(rpc::forge::InstanceSearchFilter {
            label: Some(label),
            tenant_org_id: None,
            vpc_id: None,
            instance_type_id: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .instance_ids;

    api.find_instances_by_ids(tonic::Request::new(rpc::forge::InstancesByIdsRequest {
        instance_ids,
    }))
    .await
    .unwrap()
    .into_inner()
}

pub(super) fn host_id(mh: &TestManagedHost) -> StableHostMachineId {
    mh.host.id.try_into().unwrap()
}

pub(super) fn fnn_config() -> CarbideConfig {
    let mut config = default_config::get();
    config.fnn = Some(FnnConfig {
        admin_vpc: None,
        common_internal_route_target: None,
        additional_route_target_imports: vec![],
        routing_profiles: HashMap::from([
            (
                "EXTERNAL".to_string(),
                FnnRoutingProfileConfig {
                    access_tier: Some(2),
                    internal: Some(false),
                    ..Default::default()
                },
            ),
            (
                "INTERNAL".to_string(),
                FnnRoutingProfileConfig {
                    access_tier: Some(1),
                    internal: Some(true),
                    ..Default::default()
                },
            ),
        ]),
        use_vpc_vrf_loopback: false,
    });
    config
}

/// Persists a tenant overlay prefix with explicit capacity for allocation tests.
pub(super) async fn create_tenant_overlay_prefix_with_prefix(
    pool: &PgPool,
    vpc_id: VpcId,
    name: &str,
    prefix: IpNetwork,
) -> VpcPrefixId {
    let mut txn = pool.begin().await.unwrap();

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

pub(super) async fn create_fixture_tenant(
    api: &Api,
    organization_id: impl Into<String>,
) -> Result<rpc::forge::Tenant, tonic::Status> {
    let organization_id = organization_id.into();

    // Let the API apply the runtime default routing-profile behavior.
    let response = api
        .create_tenant(tonic::Request::new(rpc::forge::CreateTenantRequest {
            organization_id: organization_id.clone(),
            routing_profile_type: None,
            metadata: Some(rpc::Metadata {
                name: organization_id,
                ..Default::default()
            }),
        }))
        .await?;

    Ok(response
        .into_inner()
        .tenant
        .expect("created tenant response must include tenant"))
}
