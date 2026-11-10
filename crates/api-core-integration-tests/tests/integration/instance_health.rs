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

use std::str::FromStr;
use std::sync::Arc;

use carbide_api_core::test_support::default_config;
use carbide_test_harness::prelude::*;
use carbide_test_harness::test_support::fixture_config::FixtureDefault as _;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::{MachineId, StableHostMachineId};
use model::test_support::ManagedHostConfig;
use rpc::InstanceReleaseRequest;
use rpc::forge::{InstanceAllocationRequest, InstanceConfig};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tonic::IntoRequest;

use super::instance_common::{
    create_boot_networks, create_ready_host, default_os_config, default_tenant_config,
    instance_resource_pools, single_interface_network_config,
};

async fn send_health_report_entry(
    harness: &TestHarness,
    machine_id: &MachineId,
    entry: (
        health_report::HealthReport,
        health_report::HealthReportApplyMode,
    ),
) {
    harness
        .api()
        .insert_machine_health_report(tonic::Request::new(
            rpc::forge::InsertMachineHealthReportRequest {
                machine_id: Some(*machine_id),
                health_report_entry: Some(rpc::forge::HealthReportEntry {
                    report: Some(entry.0.into()),
                    mode: entry.1 as i32,
                }),
            },
        ))
        .await
        .unwrap();
}

async fn remove_health_report_entry(harness: &TestHarness, machine_id: &MachineId, source: String) {
    harness
        .api()
        .remove_machine_health_report(tonic::Request::new(
            rpc::forge::RemoveMachineHealthReportRequest {
                machine_id: Some(*machine_id),
                source,
            },
        ))
        .await
        .unwrap();
}

#[sqlx_test]
async fn test_cannot_create_instance_on_unhealthy_dpu(
    _: PgPoolOptions,
    options: PgConnectOptions,
) -> eyre::Result<()> {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let config = default_config::get();
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

    let host_machine_id: StableHostMachineId = mh.host.id.try_into().unwrap();

    // Report an unhealthy DPU
    let status = mh
        .first_dpu()
        .network_status()
        .dpu_health(rpc::health::HealthReport {
            source: "forge-dpu-agent".to_string(),
            triggered_by: None,
            observed_at: None,
            successes: vec![],
            alerts: vec![rpc::health::HealthProbeAlert {
                id: "everything".to_string(),
                target: None,
                in_alert_since: None,
                message: "test_cannot_create_instance_on_unhealthy_dpu".to_string(),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_allocations().to_string(),
                    health_report::HealthAlertClassification::prevent_host_state_changes()
                        .to_string(),
                ],
            }],
        })
        .build()
        .await;
    harness
        .api()
        .record_dpu_network_status(status.into_request())
        .await
        .expect("DPU network status should be recorded");

    let result = harness
        .api()
        .allocate_instance(
            InstanceAllocationRequest::builder(false)
                .machine_id(host_machine_id)
                .config(
                    InstanceConfig::builder()
                        .tenant(default_tenant_config())
                        .os(default_os_config())
                        .network(single_interface_network_config(segment_id)),
                )
                .metadata(rpc::Metadata {
                    name: "test_instance".to_string(),
                    description: "tests/instance".to_string(),
                    labels: Vec::new(),
                })
                .tonic_request(),
        )
        .await;
    let Err(err) = result else {
        panic!("Creating an instance should have been refused");
    };
    if err.code() != tonic::Code::FailedPrecondition {
        panic!("Expected grpc code FailedPrecondition, got {}", err.code());
    }
    assert_eq!(
        err.message(),
        "host is not available for allocation due to health probe alert"
    );
    Ok(())
}

#[sqlx_test]
async fn test_create_instance_with_allow_unhealthy_machine_true(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let config = default_config::get();
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

    let host_machine_id: StableHostMachineId = mh.host.id.try_into().unwrap();

    // Report an unhealthy DPU
    let status = mh
        .first_dpu()
        .network_status()
        .dpu_health(rpc::health::HealthReport {
            source: "forge-dpu-agent".to_string(),
            triggered_by: None,
            observed_at: None,
            successes: vec![],
            alerts: vec![rpc::health::HealthProbeAlert {
                id: "everything".to_string(),
                target: None,
                in_alert_since: None,
                message: "test_cannot_create_instance_on_unhealthy_dpu".to_string(),
                tenant_message: None,
                classifications: vec![
                    health_report::HealthAlertClassification::prevent_allocations().to_string(),
                    health_report::HealthAlertClassification::prevent_host_state_changes()
                        .to_string(),
                ],
            }],
        })
        .build()
        .await;
    harness
        .api()
        .record_dpu_network_status(status.into_request())
        .await
        .expect("DPU network status should be recorded");

    let instance_id: InstanceId = uuid::Uuid::new_v4().into();

    let instance = harness
        .api()
        .allocate_instance(
            InstanceAllocationRequest::builder(true)
                .instance_id(instance_id)
                .machine_id(host_machine_id)
                .config(
                    InstanceConfig::builder()
                        .tenant(default_tenant_config())
                        .os(default_os_config())
                        .network(single_interface_network_config(segment_id)),
                )
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

    assert_eq!(instance.id, Some(instance_id));

    let instance = harness
        .api()
        .find_instances_by_ids(tonic::Request::new(rpc::forge::InstancesByIdsRequest {
            instance_ids: vec![instance_id],
        }))
        .await
        .unwrap()
        .into_inner()
        .instances;
    assert_eq!(instance.len(), 1);
    assert_eq!(instance[0].id.unwrap(), instance_id);
}

/// Release is rejected when aggregate health includes `PreventInstanceDeletion`; succeeds after the override is removed.
#[sqlx_test]
async fn test_instance_release_rejected_when_aggregate_health_has_prevent_instance_deletion(
    _: PgPoolOptions,
    options: PgConnectOptions,
) {
    let pool = PgPoolOptions::new().connect_with(options).await.unwrap();
    let config = default_config::get();
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

    let config = InstanceConfig::builder()
        .tenant(default_tenant_config())
        .os(default_os_config())
        .network(single_interface_network_config(segment_id));

    let instance_result = harness
        .api()
        .allocate_instance(
            InstanceAllocationRequest::builder(false)
                .machine_id(StableHostMachineId::try_from(mh.host.id).unwrap())
                .config(config)
                .metadata(rpc::Metadata {
                    name: "test-prevent-instance-deletion".to_string(),
                    description: "PreventInstanceDeletion blocks release".to_string(),
                    labels: Vec::new(),
                })
                .tonic_request(),
        )
        .await
        .expect("allocate instance");

    let instance = instance_result.into_inner();
    let instance_id = *instance.id.as_ref().expect("Instance ID should be present");

    let block_release = health_report::HealthReport {
        source: "test-prevent-instance-deletion-override".to_string(),
        triggered_by: None,
        observed_at: Some(chrono::Utc::now()),
        successes: vec![],
        alerts: vec![health_report::HealthProbeAlert {
            id: health_report::HealthProbeId::from_str("TestPreventInstanceDeletion").unwrap(),
            target: None,
            in_alert_since: None,
            message: "hold instance".to_string(),
            tenant_message: None,
            classifications: vec![
                health_report::HealthAlertClassification::prevent_instance_deletion(),
            ],
        }],
    };

    send_health_report_entry(
        &harness,
        &mh.host.id.into(),
        (block_release, health_report::HealthReportApplyMode::Merge),
    )
    .await;

    let err = harness
        .api()
        .release_instance(tonic::Request::new(InstanceReleaseRequest {
            id: Some(instance_id),
            issue: None,
            is_repair_tenant: None,
            delete_attribution: None,
        }))
        .await
        .expect_err(
            "release should fail when PreventInstanceDeletion is present on aggregate health",
        );

    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    assert!(
        err.message().contains("PreventInstanceDeletion"),
        "unexpected message: {}",
        err.message()
    );

    remove_health_report_entry(
        &harness,
        &mh.host.id.into(),
        "test-prevent-instance-deletion-override".to_string(),
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
        .expect("release should succeed after removing PreventInstanceDeletion source");
}
