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
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::DpuMachineId;
use carbide_uuid::vpc::VpcPrefixId;
use model::instance::config::extension_services::InstanceExtensionServiceConfig;
use model::instance::config::network::InstanceServiceInterfaceConfig;
use rpc::forge::DpuExtensionService;

use crate::api::Api;
use crate::network_segment::allocate::PrefixAllocator;

/// Seeds a registered service attachment and IPv4 endpoint on slot zero of the supplied DPU.
///
/// The Instance, registration and parent VPC prefix must already exist. Uses the production
/// allocator to persist its generated segment, prefix, address and service MAC, then atomically
/// updates the attachment and service interface. Intended for compatibility tests while public
/// service-VPC activation is gated; the caller owns the configured parent prefix's capacity.
pub async fn seed_networked_attachment(
    api: &Api,
    instance_id: InstanceId,
    dpu_id: DpuMachineId,
    service: &DpuExtensionService,
    parent_id: VpcPrefixId,
) -> Result<InstanceServiceInterfaceConfig, Box<dyn std::error::Error>> {
    let attachment_id = uuid::Uuid::new_v4();
    let service_id = service.service_id.parse()?;
    let service_version = service
        .latest_version_info
        .as_ref()
        .expect("created service has a version")
        .version
        .parse()?;

    let mut txn = api.database_connection.begin().await?;
    let mac_assignment = match db::extension_service::find_interface_macs(txn.as_mut(), service_id)
        .await?
        .into_iter()
        .find(|assignment| assignment.interface_ordinal == 0)
    {
        Some(assignment) => assignment,
        None => {
            let assignment =
                model::extension_service::ExtensionServiceInterfaceMac::candidate(service_id, 0, 0);
            db::extension_service::insert_interface_mac(txn.as_mut(), assignment).await?;
            assignment
        }
    };

    // Allocate the same segment, prefix, and address records produced by activation so compatibility
    // requests validate a persisted network segment, network prefix, and Instance address rather
    // than a synthetic service interface.
    let parent = db::vpc_prefix::lock_for_allocation(txn.as_mut(), parent_id)
        .await?
        .expect("service VPC prefix remains available");
    let allocator = PrefixAllocator::new(
        parent.id,
        parent.config.prefix,
        parent.status.last_used_prefix,
        31,
    )?;
    let link_prefix = allocator.next_free_prefix(txn.as_mut()).await?;
    let (network_segment_id, network_prefix) = allocator
        .allocate_service_network_segment_for_prefix(txn.as_mut(), parent.vpc_id, link_prefix)
        .await?;
    db::vpc_prefix::update_last_used_prefix(txn.as_mut(), &parent.id, link_prefix).await?;
    db::instance_address::insert_service_address(
        txn.as_mut(),
        instance_id,
        network_segment_id,
        parent.vpc_id,
        &network_prefix,
    )
    .await?;

    let stored_instance = db::instance::find_by_id(txn.as_mut(), instance_id)
        .await?
        .expect("instance remains stored");

    let current_extension_services = stored_instance.config.extension_services.clone();
    let mut seeded_extension_services = current_extension_services.clone();
    let registered_target = service
        .dpu_target
        .and_then(|target| rpc::forge::DpuExtensionServiceDpuTarget::try_from(target).ok())
        .map(Into::into)
        .expect("networked service has a registered DPU target");
    seeded_extension_services
        .service_configs
        .push(InstanceExtensionServiceConfig {
            id: Some(attachment_id),
            dpu_target: Some(registered_target),
            service_id,
            version: service_version,
            removed: None,
        });

    let mut seeded_network_config = stored_instance.config.network.clone();
    let endpoint = InstanceServiceInterfaceConfig {
        attachment_id,
        interface_ordinal: 0,
        dpu_id,
        slot_index: 0,
        vpc_id: parent.vpc_id,
        vpc_prefix_id: parent.id,
        network_segment_id,
        network_prefix_id: network_prefix.id,
        link_prefix,
        mac_address: mac_assignment.mac_address,
        internal_uuid: uuid::Uuid::new_v4(),
    };
    seeded_network_config
        .service_interfaces
        .push(endpoint.clone());

    assert!(matches!(
        db::instance::update_service_network_config(
            txn.as_mut(),
            stored_instance.id,
            stored_instance.extension_services_config_version,
            &current_extension_services,
            &seeded_extension_services,
            stored_instance.network_config_version,
            &stored_instance.config.network,
            &seeded_network_config,
            false,
        )
        .await?,
        db::ConditionalWrite::Applied(_)
    ));
    txn.commit().await?;

    Ok(endpoint)
}
