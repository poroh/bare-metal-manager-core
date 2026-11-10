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

use carbide_api_core::cfg::file::VmaasConfig;
use carbide_api_core::test_support::default_config;
use carbide_api_core::test_support::network_segment::FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::FixtureDefault as _;
use carbide_uuid::machine::StableHostMachineId;
use model::test_support::ManagedHostConfig;
use rpc::forge::{InstanceAllocationRequest, InstanceConfig};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

use super::instance_common::{
    create_boot_networks, create_ready_host, create_ready_tenant_segment, default_os_config,
    default_tenant_config, instance_resource_pools, single_interface_network_config,
    single_interface_network_config_with_vfs,
};

#[sqlx_test]
async fn test_instance_with_vf_when_vf_disabled(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let mut config = default_config::get();
    config.vmaas_config = Some(VmaasConfig {
        allow_instance_vf: false,
        hbn_reps: None,
        bridging: None,
    });

    let pools = instance_resource_pools(config.fnn.is_some());
    let harness = Box::pin(
        TestHarness::builder(pool)
            .with_resource_pools(pools)
            .with_api_builder_fn(move |builder| builder.with_runtime_config(Arc::new(config)))
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

    let mh = create_ready_host(
        &harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default(),
    )
    .await;
    let vpc_id = db::vpc::find_by_segment(&harness.api().database_connection, segment_id)
        .await
        .unwrap()
        .unwrap()
        .id;
    let segment_id = vec![
        segment_id,
        create_ready_tenant_segment(
            harness.api(),
            &network_controller,
            &boot.domain,
            vpc_id,
            FIXTURE_TENANT_NETWORK_SEGMENT_GATEWAYS[1],
            "TENANT",
        )
        .await,
    ];

    // Create instance configuration
    let config = InstanceConfig::builder()
        .tenant(default_tenant_config())
        .os(default_os_config())
        .network(single_interface_network_config_with_vfs(segment_id));

    // Allocate an instance
    let instance_result = harness
        .api()
        .allocate_instance(
            InstanceAllocationRequest::builder(false)
                .machine_id(StableHostMachineId::try_from(mh.host.id).unwrap())
                .config(config)
                .metadata(rpc::Metadata {
                    name: "test-disabled-vf".to_string(),
                    description: "Testing instance creation when vf disabled".to_string(),
                    labels: Vec::new(),
                })
                .tonic_request(),
        )
        .await;

    assert!(instance_result.is_err());
}

#[sqlx_test]
async fn test_instance_without_vf_when_vf_disabled(_: PgPoolOptions, options: PgConnectOptions) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let mut config = default_config::get();
    config.vmaas_config = Some(VmaasConfig {
        allow_instance_vf: false,
        hbn_reps: None,
        bridging: None,
    });

    let pools = instance_resource_pools(config.fnn.is_some());
    let harness = Box::pin(
        TestHarness::builder(pool)
            .with_resource_pools(pools)
            .with_api_builder_fn(move |builder| builder.with_runtime_config(Arc::new(config)))
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

    let mh = create_ready_host(
        &harness,
        &site_explorer,
        &boot,
        ManagedHostConfig::default(),
    )
    .await;
    // Create instance configuration
    let config = InstanceConfig::builder()
        .tenant(default_tenant_config())
        .os(default_os_config())
        .network(single_interface_network_config(segment_id));

    // Allocate an instance
    let instance_result = harness
        .api()
        .allocate_instance(
            InstanceAllocationRequest::builder(false)
                .machine_id(StableHostMachineId::try_from(mh.host.id).unwrap())
                .config(config)
                .metadata(rpc::Metadata {
                    name: "test-disabled-vf".to_string(),
                    description: "Testing instance creation when vf disabled".to_string(),
                    labels: Vec::new(),
                })
                .tonic_request(),
        )
        .await;

    assert!(instance_result.is_ok());
}
