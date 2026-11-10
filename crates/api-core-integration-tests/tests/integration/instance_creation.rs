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

use std::sync::Arc;

use carbide_api_core::test_support::default_config;
use carbide_redfish::libredfish::test_support::RedfishSim;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::FixtureDefault as _;
use carbide_uuid::machine::StableHostMachineId;
use model::test_support::ManagedHostConfig;
use rpc::forge::InstanceConfig;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::instance_common::controller::{advance_instance_to_ready, instance_controller};
use super::instance_common::{
    create_boot_networks, create_ready_host, default_os_config, default_tenant_config,
    find_instances_by_label, instance_resource_pools, single_interface_network_config,
    tenant_segments,
};

#[sqlx_test]
async fn test_allocate_instance_with_labels(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let config = default_config::get();
    let redfish = Arc::new(RedfishSim::default());
    let api_redfish = redfish.clone();
    let pools = instance_resource_pools(config.fnn.is_some());
    let harness = Box::pin(
        TestHarness::builder(pool)
            .with_resource_pools(pools)
            .with_api_builder_fn(move |builder| {
                builder
                    .with_runtime_config(Arc::new(config))
                    .with_redfish_pool(api_redfish)
            })
            .build(),
    )
    .await;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(&harness, &network_controller).await;
    let vpc_id = network_controller.create_vpc("test vpc 1").await;
    let segment_id = network_controller
        .create_tenant_segment(&boot.domain, vpc_id)
        .await
        .id;
    let site_explorer = harness.default_test_site_explorer();
    let mut controller = instance_controller(&harness, &redfish);

    let mh = create_ready_host(
        &harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default(),
    )
    .await;

    let txn = harness
        .api()
        .database_connection
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    txn.commit().await.unwrap();

    let instance_metadata = rpc::forge::Metadata {
        name: "test_instance_with_labels".to_string(),
        description: "this instance must have labels.".to_string(),
        labels: vec![
            rpc::forge::Label {
                key: "key1".to_string(),
                value: Some("value1".to_string()),
            },
            rpc::forge::Label {
                key: "key2".to_string(),
                value: None,
            },
        ],
    };

    let tinstance = mh
        .instance_builder(&harness)
        .single_interface_network_config(segment_id)
        .metadata(instance_metadata.clone())
        .build()
        .await;
    advance_instance_to_ready(
        &mut controller,
        &harness,
        &network_controller,
        &mh,
        &tinstance,
    )
    .await;

    // Test searching based on instance id.
    let mut instance_matched_by_id = tinstance.rpc_instance().await;

    instance_matched_by_id.metadata = instance_matched_by_id.metadata.take().map(|mut metadata| {
        metadata.labels.sort_by(|l1, l2| l1.key.cmp(&l2.key));
        metadata
    });

    assert_eq!(
        instance_matched_by_id.metadata,
        Some(instance_metadata.clone())
    );

    let mut txn = harness.db_txn().await;
    let fetched_instance = tinstance.db_instance(&mut txn).await;
    assert_eq!(fetched_instance.machine_id, mh.host.id);

    assert_eq!(fetched_instance.metadata.name, "test_instance_with_labels");
    assert_eq!(
        fetched_instance.metadata.description,
        "this instance must have labels."
    );
    assert!(fetched_instance.metadata.labels.len() == 2);
    assert_eq!(
        fetched_instance.metadata.labels.get("key1").unwrap(),
        "value1"
    );
    assert_eq!(fetched_instance.metadata.labels.get("key2").unwrap(), "");

    txn.rollback().await.unwrap();

    let mut instances = find_instances_by_label(
        harness.api(),
        rpc::forge::Label {
            key: "key1".to_string(),
            value: None,
        },
    )
    .await
    .instances;
    assert_eq!(instances.len(), 1);
    let mut instance_matched_by_label = instances.remove(0);

    instance_matched_by_label.metadata =
        instance_matched_by_label
            .metadata
            .take()
            .map(|mut metadata| {
                metadata.labels.sort_by(|l1, l2| l1.key.cmp(&l2.key));
                metadata
            });

    assert_eq!(
        instance_matched_by_label.machine_id.unwrap(),
        StableHostMachineId::try_from(mh.host.id).unwrap()
    );

    assert_eq!(instance_matched_by_label.metadata, Some(instance_metadata));
}

#[sqlx_test]
async fn test_instance_hostname_creation(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let config = default_config::get();
    let redfish = Arc::new(RedfishSim::default());
    let api_redfish = redfish.clone();
    let pools = instance_resource_pools(config.fnn.is_some());
    let harness = Box::pin(
        TestHarness::builder(pool)
            .with_resource_pools(pools)
            .with_api_builder_fn(move |builder| {
                builder
                    .with_runtime_config(Arc::new(config))
                    .with_redfish_pool(api_redfish)
            })
            .build(),
    )
    .await;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(&harness, &network_controller).await;
    let vpc_id = network_controller.create_vpc("test vpc 1").await;
    let segment_id = network_controller
        .create_tenant_segment(&boot.domain, vpc_id)
        .await
        .id;
    let site_explorer = harness.default_test_site_explorer();
    let mut controller = instance_controller(&harness, &redfish);

    let mh = create_ready_host(
        &harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default(),
    )
    .await;

    let txn = harness
        .api()
        .database_connection
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    txn.commit().await.unwrap();

    let instance_hostname = "test-hostname";

    let tinstance = mh
        .instance_builder(&harness)
        .single_interface_network_config(segment_id)
        .hostname(instance_hostname)
        .tenant_org("org-nebulon")
        .build()
        .await;
    advance_instance_to_ready(
        &mut controller,
        &harness,
        &network_controller,
        &mh,
        &tinstance,
    )
    .await;

    let mut txn = harness.db_txn().await;

    let fetched_instance = tinstance.db_instance(&mut txn).await;

    let returned_hostname = fetched_instance.config.tenant.hostname;

    assert_eq!(returned_hostname.unwrap(), instance_hostname);

    txn.rollback().await.unwrap();

    //Check for duplicate hostnames
    let txn = harness
        .api()
        .database_connection
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    txn.commit().await.unwrap();

    let other_mh = create_ready_host(
        &harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default(),
    )
    .await;
    let other_instance = other_mh
        .instance_builder(&harness)
        .single_interface_network_config(segment_id)
        .hostname(instance_hostname)
        .tenant_org("org-nvidia") // different org, should fail on the same one
        .build()
        .await;
    advance_instance_to_ready(
        &mut controller,
        &harness,
        &network_controller,
        &other_mh,
        &other_instance,
    )
    .await;
}

#[sqlx_test]
async fn test_instance_phone_home(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let config = default_config::get();
    let redfish = Arc::new(RedfishSim::default());
    let api_redfish = redfish.clone();
    let pools = instance_resource_pools(config.fnn.is_some());
    let harness = Box::pin(
        TestHarness::builder(pool)
            .with_resource_pools(pools)
            .with_api_builder_fn(move |builder| {
                builder
                    .with_runtime_config(Arc::new(config))
                    .with_redfish_pool(api_redfish)
            })
            .build(),
    )
    .await;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(&harness, &network_controller).await;
    let vpc_id = network_controller.create_vpc("test vpc 1").await;
    let segment_id = network_controller
        .create_tenant_segment(&boot.domain, vpc_id)
        .await
        .id;
    let site_explorer = harness.default_test_site_explorer();
    let mut controller = instance_controller(&harness, &redfish);

    let mh = create_ready_host(
        &harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default(),
    )
    .await;

    let mut os = default_os_config();
    os.phone_home_enabled = true;
    let instance_config = rpc::InstanceConfig {
        tenant: Some(default_tenant_config()),
        os: Some(os),
        network: Some(single_interface_network_config(segment_id)),
        infiniband: None,
        nvlink: None,
        spxconfig: None,
        network_security_group_id: None,
        dpu_extension_services: None,
        power_profile: None,
    };

    let tinstance = mh
        .instance_builder(&harness)
        .config(instance_config)
        .build()
        .await;
    advance_instance_to_ready(
        &mut controller,
        &harness,
        &network_controller,
        &mh,
        &tinstance,
    )
    .await;

    let instance = tinstance.rpc_instance().await;

    // Should be in a provisioning state
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

    // Phone home to transition to the ready state
    let mut phone_home_req = tonic::Request::new(rpc::forge::InstancePhoneHomeLastContactRequest {
        instance_id: Some(tinstance.id),
    });
    let mut auth_context = carbide_api_core::AuthContext::default();
    auth_context.principals.push(
        carbide_authn::middleware::Principal::SpiffeMachineIdentifier(mh.host.id.to_string()),
    );
    phone_home_req.extensions_mut().insert(auth_context);
    harness
        .api()
        .update_instance_phone_home_last_contact(phone_home_req)
        .await
        .unwrap();

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
        rpc::TenantState::Ready
    );
}

#[sqlx_test]
async fn test_instance_dns_resolution(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let config = default_config::get();
    let redfish = Arc::new(RedfishSim::default());
    let api_redfish = redfish.clone();
    let pools = instance_resource_pools(config.fnn.is_some());
    let harness = Box::pin(
        TestHarness::builder(pool)
            .with_resource_pools(pools)
            .with_api_builder_fn(move |builder| {
                builder
                    .with_runtime_config(Arc::new(config))
                    .with_redfish_pool(api_redfish)
            })
            .build(),
    )
    .await;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(&harness, &network_controller).await;
    let vpc_id = network_controller.create_vpc("test vpc 1").await;
    let segment_id = network_controller
        .create_tenant_segment(&boot.domain, vpc_id)
        .await
        .id;
    let site_explorer = harness.default_test_site_explorer();
    let mut controller = instance_controller(&harness, &redfish);

    let (segment_id_1, segment_id_2) = {
        let ids = tenant_segments(
            harness.api(),
            &network_controller,
            &boot.domain,
            segment_id,
            2,
        )
        .await;
        (ids[0], ids[1])
    };
    let mh = create_ready_host(
        &harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default(),
    )
    .await;

    let network = rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some(segment_id_1),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some(segment_id_2),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
            },
        ],
        #[allow(deprecated)]
        auto: false,
        auto_config: None,
    };

    // Create instance with hostname
    let tinstance = mh
        .instance_builder(&harness)
        .network(network)
        .hostname("test-hostname")
        .tenant_org("nvidia-org")
        .build()
        .await;
    advance_instance_to_ready(
        &mut controller,
        &harness,
        &network_controller,
        &mh,
        &tinstance,
    )
    .await;

    let response = harness
        .api()
        .get_managed_host_network_config(tonic::Request::new(
            rpc::forge::ManagedHostNetworkConfigRequest {
                dpu_machine_id: Some(mh.first_dpu().id),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    //DNS record domain always uses IP Address (for now)
    let dns_record = harness
        .api()
        .lookup_record(tonic::Request::new(
            rpc::protos::dns::DnsResourceRecordLookupRequest {
                qname: "192-0-2-3.dwrt1.com.".to_string(),
                zone_id: uuid::Uuid::new_v4().to_string(),
                local: None,
                remote: None,
                qtype: "A".to_string(),
                real_remote: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();

    tracing::info!(
        dns_record = ?dns_record,
        "Fetched DNS record",
    );
    assert_eq!(dns_record.records.first().unwrap().content, "192.0.2.3");

    //DHCP response uses hostname set during allocation
    assert_eq!(
        "test-hostname.dwrt1.com",
        response.tenant_interfaces[0].fqdn
    );
}

#[sqlx_test]
async fn test_instance_null_hostname(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let config = default_config::get();
    let redfish = Arc::new(RedfishSim::default());
    let api_redfish = redfish.clone();
    let pools = instance_resource_pools(config.fnn.is_some());
    let harness = Box::pin(
        TestHarness::builder(pool)
            .with_resource_pools(pools)
            .with_api_builder_fn(move |builder| {
                builder
                    .with_runtime_config(Arc::new(config))
                    .with_redfish_pool(api_redfish)
            })
            .build(),
    )
    .await;
    let network_controller = harness.network_controller();
    let boot = create_boot_networks(&harness, &network_controller).await;
    let vpc_id = network_controller.create_vpc("test vpc 1").await;
    let segment_id = network_controller
        .create_tenant_segment(&boot.domain, vpc_id)
        .await
        .id;
    let site_explorer = harness.default_test_site_explorer();
    let mut controller = instance_controller(&harness, &redfish);

    let mh = create_ready_host(
        &harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default(),
    )
    .await;

    //Create instance with no hostname set
    let mut tenant_config = default_tenant_config();
    tenant_config.hostname = None;
    let instance_config = InstanceConfig::builder()
        .tenant(tenant_config)
        .os(default_os_config())
        .network(single_interface_network_config(segment_id))
        .rpc();

    let tinstance = mh
        .instance_builder(&harness)
        .config(instance_config)
        .build()
        .await;
    advance_instance_to_ready(
        &mut controller,
        &harness,
        &network_controller,
        &mh,
        &tinstance,
    )
    .await;

    let _response = harness
        .api()
        .get_managed_host_network_config(tonic::Request::new(
            rpc::forge::ManagedHostNetworkConfigRequest {
                dpu_machine_id: Some(mh.first_dpu().id),
            },
        ))
        .await
        .unwrap()
        .into_inner();

    //DNS record domain always uses dashed IP (for now)
    let dns_record = harness
        .api()
        .lookup_record(tonic::Request::new(
            rpc::protos::dns::DnsResourceRecordLookupRequest {
                qname: "192-0-2-3.dwrt1.com.".to_string(),
                zone_id: uuid::Uuid::new_v4().to_string(),
                local: None,
                remote: None,
                qtype: "A".to_string(),
                real_remote: None,
            },
        ))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(dns_record.records.first().unwrap().content, "192.0.2.3");

    //DHCP response uses dashed IP
    assert_eq!(
        dns_record.records.first().unwrap().qname,
        "192-0-2-3.dwrt1.com."
    );
}
