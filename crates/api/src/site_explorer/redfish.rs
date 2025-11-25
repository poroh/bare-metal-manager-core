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
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use forge_network::deserialize_input_mac_to_address;
use forge_secrets::credentials::Credentials;
use libredfish::model::oem::nvidia_dpu::NicMode;
use libredfish::model::service_root::RedfishVendor;
use libredfish::{Redfish, RedfishError};
use mac_address::MacAddress;
use model::site_explorer::{
    BootOption, BootOrder, Chassis, ComputerSystem, ComputerSystemAttributes,
    EndpointExplorationError, EndpointExplorationReport, EndpointType, EthernetInterface,
    InternalLockdownStatus, Inventory, LockdownStatus, MachineSetupDiff, MachineSetupStatus,
    Manager, NetworkAdapter, PCIeDevice, SecureBootStatus, Service, UefiDevicePath,
};
use nv_redfish::chassis::Chassis as NvChassis;
use nv_redfish::computer_system::SecureBootCurrentBootType;
use nv_redfish::resource::{PowerState as NvPowerState, ResourceIdRef};
use nv_redfish::service_root::Vendor;
use nv_redfish::{Bmc, Error as NvRedfishError, Resource, ResourceProvidesStatus, ServiceRoot};
use nv_redfish_bmc_http::HttpBmc;
use nv_redfish_bmc_http::reqwest::Client as NvRedfishReqwestClient;
use regex::Regex;

use crate::nv_redfish::NvRedfishClientPool;
use crate::redfish::{RedfishAuth, RedfishClientCreationError, RedfishClientPool, redact_password};
use crate::site_explorer::PowerState;

const NOT_FOUND: u16 = 404;

pub type NvRedfishBmc = HttpBmc<NvRedfishReqwestClient>;

// RedfishClient is a wrapper around a redfish client pool and implements redfish utility functions that the site explorer utilizes.
// TODO: In the future, we should refactor a lot of this client's work to api/src/redfish.rs because other components in carbide can utilize this functionality.
// Eventually, this file should only have code related to generating the site exploration report.
pub struct RedfishClient {
    redfish_client_pool: Arc<dyn RedfishClientPool>,
    nv_redfish_client_pool: Arc<NvRedfishClientPool>,
}

impl RedfishClient {
    pub fn new(
        redfish_client_pool: Arc<dyn RedfishClientPool>,
        nv_redfish_client_pool: Arc<NvRedfishClientPool>,
    ) -> Self {
        Self {
            redfish_client_pool,
            nv_redfish_client_pool,
        }
    }

    fn nv_redfish_bmc(
        &self,
        bmc_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<Arc<NvRedfishBmc>, RedfishClientCreationError> {
        self.nv_redfish_client_pool
            .nv_redfish_bmc(bmc_address, credentials)
    }

    async fn create_redfish_client(
        &self,
        bmc_ip_address: SocketAddr,
        auth: RedfishAuth,
        initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.redfish_client_pool
            .create_client(
                &bmc_ip_address.ip().to_string(),
                Some(bmc_ip_address.port()),
                auth,
                initialize,
            )
            .await
    }

    async fn create_anon_redfish_client(
        &self,
        bmc_ip_address: SocketAddr,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_redfish_client(bmc_ip_address, RedfishAuth::Anonymous, false)
            .await
    }

    async fn create_direct_redfish_client(
        &self,
        bmc_ip_address: SocketAddr,
        Credentials::UsernamePassword { username, password }: Credentials,
        initialize: bool,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_redfish_client(
            bmc_ip_address,
            RedfishAuth::Direct(username, password),
            initialize,
        )
        .await
    }

    async fn create_authenticated_redfish_client(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<Box<dyn Redfish>, RedfishClientCreationError> {
        self.create_direct_redfish_client(bmc_ip_address, credentials, true)
            .await
    }

    pub async fn probe_redfish_endpoint(
        &self,
        bmc_ip_address: SocketAddr,
    ) -> Result<RedfishVendor, EndpointExplorationError> {
        let client = self
            .create_anon_redfish_client(bmc_ip_address)
            .await
            .map_err(map_redfish_client_creation_error)?;

        let service_root = client.get_service_root().await.map_err(map_redfish_error)?;

        let Some(vendor) = service_root.vendor() else {
            tracing::info!("No vendor found for BMC at {bmc_ip_address}");
            return Err(EndpointExplorationError::MissingVendor);
        };

        Ok(vendor)
    }

    pub async fn set_bmc_root_password(
        &self,
        bmc_ip_address: SocketAddr,
        vendor: RedfishVendor,
        current_bmc_root_credentials: Credentials,
        new_password: String,
    ) -> Result<(), EndpointExplorationError> {
        let (curr_user, curr_password) = match &current_bmc_root_credentials {
            Credentials::UsernamePassword { username, password } => (username, password),
        };
        let mut client = self
            .create_direct_redfish_client(
                bmc_ip_address,
                current_bmc_root_credentials.clone(),
                false,
            )
            .await
            .map_err(|e| {
                tracing::error!(
                    "Failed to create Redfish client while setting BMC password for vendor {:?} (bmc_ip = {}): {:?}",
                    vendor,
                    bmc_ip_address,
                    e
                );
                map_redfish_client_creation_error(e)
            })?;

        match vendor {
            RedfishVendor::Lenovo => {
                // Change (factory_user, factory_pass) to (factory_user, site_pass)
                client
                    .change_password_by_id("1", new_password.as_str())
                    .await
                    .map_err(|err| redact_password(err, new_password.as_str()))
                    .map_err(|err| redact_password(err, curr_password.as_str()))
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::NvidiaDpu
            | RedfishVendor::NvidiaGH200
            | RedfishVendor::NvidiaGBSwitch
            | RedfishVendor::P3809
            | RedfishVendor::LiteOnPowerShelf
            | RedfishVendor::NvidiaGBx00 => {
                // change_password does things that require a password and DPUs need a first
                // password use to be change, so just change it directly
                //
                // GH200 doesn't require change-on-first-use, but it's good practice. GB200
                // probably will.
                client
                    .change_password_by_id(curr_user.as_str(), new_password.as_str())
                    .await
                    .map_err(|err| redact_password(err, new_password.as_str()))
                    .map_err(|err| redact_password(err, curr_password.as_str()))
                    .map_err(map_redfish_error)?;
            }
            // Handle Vikings
            RedfishVendor::AMI => {
                /*
                https://docs.nvidia.com/dgx/dgxh100-user-guide/redfish-api-supp.html

                You should set the password after the first boot. The following curl command changes the password for the admin user.
                curl -k -u <bmc-user>:<password> --request PATCH 'https://<bmc-ip-address>/redfish/v1/AccountService/Accounts/2' --header 'If-Match: *'  --header 'Content-Type: application/json' --data-raw '{ "Password" : "<password>" }'
                */
                client
                    .change_password_by_id("2", new_password.as_str())
                    .await
                    .map_err(|err| redact_password(err, new_password.as_str()))
                    .map_err(|err| redact_password(err, curr_password.as_str()))
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Supermicro => {
                client
                    .change_password(curr_user.as_str(), new_password.as_str())
                    .await
                    .map_err(|err| redact_password(err, new_password.as_str()))
                    .map_err(|err| redact_password(err, curr_password.as_str()))
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Dell => {
                client
                    .change_password(curr_user.as_str(), new_password.as_str())
                    .await
                    .map_err(|err| redact_password(err, new_password.as_str()))
                    .map_err(|err| redact_password(err, curr_password.as_str()))
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Hpe => {
                client
                    .change_password(curr_user.as_str(), new_password.as_str())
                    .await
                    .map_err(|err| redact_password(err, new_password.as_str()))
                    .map_err(|err| redact_password(err, curr_password.as_str()))
                    .map_err(map_redfish_error)?;
            }
            RedfishVendor::Unknown => {
                return Err(EndpointExplorationError::UnsupportedVendor {
                    vendor: vendor.to_string(),
                });
            }
        };

        // log in using the new credentials
        client = self
            .create_authenticated_redfish_client(
                bmc_ip_address,
                Credentials::UsernamePassword {
                    username: curr_user.to_string(),
                    password: new_password,
                },
            )
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .set_machine_password_policy()
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn generate_exploration_report(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        boot_interface_mac: Option<MacAddress>,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        let service_root = client.get_service_root().await.map_err(map_redfish_error)?;
        let vendor = service_root.vendor().map(|v| v.into());

        let manager = fetch_manager(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let system = fetch_system(client.as_ref()).await?;

        // TODO (spyda): once we test the BMC reset logic, we can enhance our logic here
        // to detect cases where the host's BMC is returning invalid (empty) chassis information, even though
        // an error is not returned.
        let chassis = fetch_chassis(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let service = fetch_service(client.as_ref())
            .await
            .map_err(map_redfish_error)?;
        let machine_setup_status = fetch_machine_setup_status(client.as_ref(), boot_interface_mac)
            .await
            .inspect_err(|error| tracing::warn!(%error, "Failed to fetch machine setup status."))
            .ok();

        let secure_boot_status = fetch_secure_boot_status(client.as_ref())
            .await
            .inspect_err(
                |error| tracing::warn!(%error, "Failed to fetch forge secure boot status."),
            )
            .ok();

        let lockdown_status = fetch_lockdown_status(client.as_ref())
            .await
            .inspect_err(|error| {
                if !matches!(error, libredfish::RedfishError::NotSupported(_)) {
                    tracing::warn!(%error, "Failed to fetch lockdown status.");
                }
            })
            .ok();

        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            machine_id: None,
            managers: vec![manager],
            systems: vec![system],
            chassis,
            service,
            vendor,
            versions: HashMap::default(),
            model: None,
            power_shelf_id: None,
            switch_id: None,
            machine_setup_status,
            secure_boot_status,
            lockdown_status,
            physical_slot_number: None,
            compute_tray_index: None,
            topology_id: None,
            revision_id: None,
        })
    }

    pub async fn nv_generate_exploration_report(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<EndpointExplorationReport, EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials.clone())
            .await
            .map_err(map_redfish_client_creation_error)?;

        let bmc = self
            .nv_redfish_bmc(bmc_ip_address, credentials)
            .map_err(map_redfish_client_creation_error)?;
        let root = ServiceRoot::new(bmc)
            .await
            .map_err(|err| map_nv_redfish_error("service root", err))?;

        let vendor = nv_bmc_vendor(&root);

        let manager = nv_fetch_manager(&root).await?;
        let nv_chassis_members = root
            .chassis()
            .await
            .map_err(|err| map_nv_redfish_error("chassis collection", err))?
            .members()
            .await
            .map_err(|err| map_nv_redfish_error("chassis collection members", err))?;
        let (system, nv_system_handle) = nv_fetch_system(&root, &nv_chassis_members).await?;

        let chassis = nv_fetch_chassis(root.vendor(), &nv_chassis_members).await?;
        let service = nv_fetch_service(&root).await?;

        let machine_setup_status = fetch_machine_setup_status(client.as_ref(), None)
            .await
            .inspect_err(|error| tracing::warn!(%error, "Failed to fetch forge setup status."))
            .ok();

        let secure_boot_status = nv_system_handle
            .secure_boot()
            .await
            .map_err(|err| map_nv_redfish_error("secure boot", err))
            .and_then(|v| {
                Ok(SecureBootStatus {
                    is_enabled: v
                        .secure_boot_enable()
                        .ok_or_else(|| EndpointExplorationError::RedfishError {
                            details: "SecureBootEnable is not set in SecureBoot resource".into(),
                            response_code: None,
                            response_body: None,
                        })?
                        .into_inner()
                        && v.secure_boot_current_boot().ok_or_else(|| {
                            EndpointExplorationError::RedfishError {
                                details:
                                    "SecureBootCurrentBootType is not set in SecureBoot resource"
                                        .into(),
                                response_code: None,
                                response_body: None,
                            }
                        })? == SecureBootCurrentBootType::Enabled,
                })
            })
            .inspect_err(
                |error| tracing::warn!(%error, "Failed to fetch forge secure boot status."),
            )
            .ok();

        let lockdown_status = fetch_lockdown_status(client.as_ref())
            .await
            .inspect_err(|error| {
                if !matches!(error, libredfish::RedfishError::NotSupported(_)) {
                    tracing::warn!(%error, "Failed to fetch lockdown status.");
                }
            })
            .ok();

        Ok(EndpointExplorationReport {
            endpoint_type: EndpointType::Bmc,
            last_exploration_error: None,
            last_exploration_latency: None,
            machine_id: None,
            managers: vec![manager],
            systems: vec![system],
            chassis,
            service,
            vendor,
            versions: HashMap::default(),
            model: None,
            power_shelf_id: None,
            switch_id: None,
            machine_setup_status,
            secure_boot_status,
            lockdown_status,
            physical_slot_number: None,
            compute_tray_index: None,
            topology_id: None,
            revision_id: None,
        })
    }

    pub async fn reset_bmc(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client.bmc_reset().await.map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn power(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        action: libredfish::SystemPowerControl,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client.power(action).await.map_err(map_redfish_error)?;
        Ok(())
    }

    pub async fn disable_secure_boot(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .disable_secure_boot()
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn lockdown(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        action: libredfish::EnabledDisabled,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client.lockdown(action).await.map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn lockdown_status(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<LockdownStatus, EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        let response = fetch_lockdown_status(client.as_ref())
            .await
            .map_err(map_redfish_error)?;

        Ok(response)
    }

    pub async fn enable_infinite_boot(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .enable_infinite_boot()
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn is_infinite_boot_enabled(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<Option<bool>, EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .is_infinite_boot_enabled()
            .await
            .map_err(map_redfish_error)
    }

    pub async fn machine_setup(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        boot_interface_mac: Option<&str>,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        // We will be redoing machine_setup later and can worry about getting the profile right then.
        client
            .machine_setup(
                boot_interface_mac,
                &HashMap::default(),
                libredfish::BiosProfileType::Performance,
            )
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn set_boot_order_dpu_first(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        boot_interface_mac: &str,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .set_boot_order_dpu_first(boot_interface_mac)
            .await
            .map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn set_nic_mode(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        mode: NicMode,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client.set_nic_mode(mode).await.map_err(map_redfish_error)?;

        Ok(())
    }

    pub async fn is_viking(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<bool, EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        let service_root = client.get_service_root().await.map_err(map_redfish_error)?;
        let system = client.get_system().await.map_err(map_redfish_error)?;
        let manager = client.get_manager().await.map_err(map_redfish_error)?;
        Ok(
            service_root.vendor().unwrap_or(RedfishVendor::Unknown) == RedfishVendor::AMI
                && system.id == "DGX"
                && manager.id == "BMC",
        )
    }

    pub async fn clear_nvram(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client.clear_nvram().await.map_err(map_redfish_error)?;
        Ok(())
    }

    pub async fn create_bmc_user(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        new_username: &str,
        new_password: &str,
        new_user_role_id: libredfish::RoleId,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .create_user(new_username, new_password, new_user_role_id)
            .await
            .map_err(map_redfish_error)?;
        Ok(())
    }

    pub async fn delete_bmc_user(
        &self,
        bmc_ip_address: SocketAddr,
        credentials: Credentials,
        delete_user: &str,
    ) -> Result<(), EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(bmc_ip_address, credentials)
            .await
            .map_err(map_redfish_client_creation_error)?;

        client
            .delete_user(delete_user)
            .await
            .map_err(map_redfish_error)?;
        Ok(())
    }

    pub async fn probe_vendor_name_from_chassis(
        &self,
        bmc_ip_address: SocketAddr,
        username: String,
        password: String,
    ) -> Result<String, EndpointExplorationError> {
        let client = self
            .create_authenticated_redfish_client(
                bmc_ip_address,
                Credentials::UsernamePassword { username, password },
            )
            .await
            .map_err(map_redfish_client_creation_error)?;

        let chassis_all = client.get_chassis_all().await.map_err(map_redfish_error)?;
        if chassis_all.contains(&"powershelf".to_string()) {
            let chassis = client
                .get_chassis("powershelf")
                .await
                .map_err(map_redfish_error)?;
            if let Some(x) = chassis.manufacturer {
                return Ok(x);
            }
        }

        Err(EndpointExplorationError::UnsupportedVendor {
            vendor: "Unknown".to_string(),
        })
    }
}

async fn is_switch(client: &dyn Redfish) -> Result<bool, RedfishError> {
    let chassis = client.get_chassis_all().await?;
    Ok(chassis.contains(&"MGX_NVSwitch_0".to_string()))
}

async fn is_powershelf(client: &dyn Redfish) -> Result<bool, RedfishError> {
    let chassis = client.get_chassis_all().await?;
    Ok(chassis.contains(&"powershelf".to_string()))
}

fn nv_is_switch<B: Bmc>(members: &[NvChassis<B>]) -> bool {
    members
        .iter()
        .any(|m| m.id().inner().as_str() == "MGX_NVSwitch_0")
}

async fn fetch_manager(client: &dyn Redfish) -> Result<Manager, RedfishError> {
    let manager = client.get_manager().await?;
    let ethernet_interfaces = fetch_ethernet_interfaces(client, false, false)
        .await
        .or_else(|err| match err {
            RedfishError::NotSupported(_) => Ok(vec![]),
            _ => Err(err),
        })?;

    Ok(Manager {
        ethernet_interfaces,
        id: manager.id,
    })
}

async fn nv_fetch_manager<B: Bmc>(
    root: &ServiceRoot<B>,
) -> Result<Manager, EndpointExplorationError> {
    let manager = root
        .managers()
        .await
        .map_err(|err| map_nv_redfish_error("managers", err))?
        .members()
        .await
        .map_err(|err| map_nv_redfish_error("managers members", err))?
        .into_iter()
        .next()
        .ok_or(EndpointExplorationError::RedfishError {
            details: "manager not found".into(),
            response_code: None,
            response_body: None,
        })?;
    let ethernet_interfaces = nv_fetch_manager_interfaces(&manager).await?;
    Ok(Manager {
        ethernet_interfaces,
        id: manager.id().cloned().into_inner(),
    })
}

async fn nv_fetch_manager_interfaces<B: Bmc>(
    manager: &nv_redfish::manager::Manager<B>,
) -> Result<Vec<EthernetInterface>, EndpointExplorationError> {
    let interfaces = manager
        .ethernet_interfaces()
        .await
        .map_err(|err| map_nv_redfish_error("manager ethernet interfaces", err))?
        .members()
        .await
        .map_err(|err| map_nv_redfish_error("manager ethernet interfaces members", err))?;
    let mut eth_ifs = Vec::new();
    for iface in interfaces {
        let mac_address = iface
            .mac_address()
            .map(|addr| {
                deserialize_input_mac_to_address(addr.inner())
                    .map_err(|e| RedfishError::GenericError {
                        error: format!("MAC address not valid: {addr} (err: {e})"),
                    })
                    .map_err(map_redfish_error)
            })
            .transpose()
            .or_else(|err| {
                if iface
                    .interface_enabled().is_some_and(|is_enabled| !is_enabled.inner())
                {
                    // disabled interfaces sometimes populate the MAC address with junk,
                    // ignore this error and create the interface with an empty mac address
                    // in the exploration report
                    tracing::debug!(
                        "could not parse MAC address for a disabled interface {} (link_status: {:#?}): {err}",
                        iface.id(), iface.link_status()
                    );
                    Ok(None)
                } else {
                    Err(err)
                }
            })?;

        let uefi_device_path = iface
            .uefi_device_path()
            .map(|v| v.into_inner().as_str())
            .map(UefiDevicePath::from_str)
            .transpose()
            .map_err(map_redfish_error)?;

        let iface = EthernetInterface {
            description: iface.description().map(|d| d.cloned().into_inner()),
            id: Some(iface.id().cloned().into_inner()),
            interface_enabled: iface.interface_enabled().map(|v| v.into_inner()),
            mac_address,
            uefi_device_path,
        };

        eth_ifs.push(iface);
    }
    Ok(eth_ifs)
}

async fn fetch_system(client: &dyn Redfish) -> Result<ComputerSystem, EndpointExplorationError> {
    let mut system = client.get_system().await.map_err(map_redfish_error)?;
    let is_dpu = system.id.to_lowercase().contains("bluefield");
    let ethernet_interfaces = match fetch_ethernet_interfaces(client, true, is_dpu).await {
        Ok(interfaces) => Ok(interfaces),
        Err(e) if is_dpu => {
            tracing::warn!(
                "Error getting system ethernet interfaces.  The error will be ignored. ({e})"
            );
            Ok(Vec::default())
        }
        Err(e) => Err(map_redfish_error(e)),
    }?;
    let mut base_mac = None;
    let mut nic_mode = None;

    let is_switch = is_switch(client).await.map_err(map_redfish_error)?;
    let is_powershelf = is_powershelf(client).await.map_err(map_redfish_error)?;
    if is_dpu {
        // This part processes dpu case and do two things such as
        // 1. update system serial_number in case it is empty using chassis serial_number
        // 2. format serial_number data using the same rules as in fetch_chassis()
        if system.serial_number.is_none() {
            let chassis = client
                .get_chassis("Card1")
                .await
                .map_err(map_redfish_error)?;
            system.serial_number = chassis.serial_number;
        }

        base_mac = match client.get_base_mac_address().await {
            Ok(base_mac) => base_mac,
            Err(error) => {
                tracing::info!(
                    "Could not use new method to retreive base mac address for DPU (serial number {:#?}): {error}",
                    system.serial_number
                );
                None
            }
        };

        nic_mode = match client.get_nic_mode().await {
            Ok(nic_mode) => nic_mode,
            Err(e) => return Err(map_redfish_error(e)),
        };
    }

    system.serial_number = system.serial_number.map(|s| s.trim().to_string());

    let pcie_devices = if !is_powershelf {
        fetch_pcie_devices(client)
            .await
            .map_err(map_redfish_error)?
    } else {
        vec![]
    };

    let is_infinite_boot_enabled = client
        .is_infinite_boot_enabled()
        .await
        .map_err(map_redfish_error)?;

    // If this is an nvswitch, don't set a boot order.
    let boot_order = match is_switch || is_powershelf {
        true => {
            tracing::debug!("Skipping boot order for nvswitch or powershelf");
            None
        }
        false => fetch_boot_order(client, &system)
            .await
            .inspect_err(|error| tracing::warn!(%error, "Failed to fetch boot order."))
            .ok(),
    };

    Ok(ComputerSystem {
        ethernet_interfaces,
        id: system.id,
        manufacturer: system.manufacturer,
        model: system.model,
        serial_number: system.serial_number,
        attributes: ComputerSystemAttributes {
            nic_mode,
            is_infinite_boot_enabled,
        },
        pcie_devices,
        base_mac,
        power_state: system.power_state.into(),
        sku: system.sku,
        boot_order,
    })
}

async fn nv_fetch_system<B: Bmc>(
    root: &ServiceRoot<B>,
    chassis: &[NvChassis<B>],
) -> Result<
    (
        ComputerSystem,
        nv_redfish::computer_system::ComputerSystem<B>,
    ),
    EndpointExplorationError,
> {
    let system = root
        .systems()
        .await
        .map_err(|err| map_nv_redfish_error("systems", err))?
        .members()
        .await
        .map_err(|err| map_nv_redfish_error("systems members", err))?
        .into_iter()
        .next()
        .ok_or(EndpointExplorationError::RedfishError {
            details: "computer system not found".into(),
            response_code: None,
            response_body: None,
        })?;

    let is_switch = nv_is_switch(chassis);
    let is_dpu = system.id().inner().to_lowercase().contains("bluefield");
    let nv_boot_options = system
        .boot_options()
        .await
        .map_err(|err| map_nv_redfish_error("boot options", err))?
        .members()
        .await
        .map_err(|err| map_nv_redfish_error("boot options members", err))?;
    let ethernet_interfaces =
        nv_fetch_system_ethernet_interfaces(&system, &nv_boot_options, is_dpu && !is_switch)
            .await?;
    let bios = system
        .bios()
        .await
        .map_err(|err| map_nv_redfish_error("bios", err))?;
    let mut base_mac = None;
    let mut nic_mode = None;
    let hw_id = system.hardware_id();
    let mut serial_number = hw_id.serial_number.map(|v| v.into_inner());

    if is_dpu {
        // This part processes dpu case and do two things such as
        // 1. update system serial_number in case it is empty using chassis serial_number
        // 2. format serial_number data using the same rules as in fetch_chassis()
        if serial_number.is_none() {
            let chassis = chassis
                .iter()
                .find(|c| c.id().inner().as_str() == "Card1")
                .ok_or(EndpointExplorationError::RedfishError {
                    details: "chassis with id Card1 is not found".into(),
                    response_code: None,
                    response_body: None,
                })?;
            serial_number = chassis.hardware_id().serial_number.map(|v| v.into_inner());
        }

        match system.oem_nvidia_bluefield().await {
            Ok(oem_bf) => {
                // TODO: Apparently this is a bug that it has
                // additional quotes inside String but it is not
                // obvious what will be broken if it will be fixed.
                base_mac = oem_bf.base_mac().map(|v| format!("\"{}\"", v.inner()));
                nic_mode = nv_dpu_mode(&system, &bios, &oem_bf);
            }
            Err(NvRedfishError::NvidiaComputerSystemNotAvailable) => (),
            Err(e) => Err(map_nv_redfish_error("oem nvidia bluefield", e))?,
        };
    }

    let serial_number = serial_number.map(|s| s.trim().to_string());

    let pcie_devices = nv_fetch_pcie_devices(root.vendor(), system.id(), chassis).await?;

    let is_infinite_boot_enabled = nv_is_infinite_boot_enabled(&system, root, &bios);

    let boot_order = if is_switch {
        None
    } else {
        system.boot_order().map(|order| BootOrder {
            boot_order: order
                .iter()
                .filter_map(|boot_ref| {
                    nv_boot_options
                        .iter()
                        .find(|opt| opt.boot_reference() == *boot_ref)
                        .map(|opt| BootOption {
                            id: opt.id().cloned().into_inner(),
                            display_name: opt
                                .display_name()
                                .map(|v| v.cloned().into_inner())
                                .unwrap_or("".into()),
                            uefi_device_path: opt
                                .uefi_device_path()
                                .map(|v| v.cloned().into_inner()),
                            boot_option_enabled: opt.enabled().map(|v| v.into_inner()),
                        })
                })
                .collect(),
        })
    };

    Ok((
        ComputerSystem {
            ethernet_interfaces,
            id: system.id().to_string(),
            manufacturer: hw_id.manufacturer.map(|v| v.to_string()),
            model: hw_id.model.map(|v| v.to_string()),
            serial_number,
            attributes: ComputerSystemAttributes {
                nic_mode,
                is_infinite_boot_enabled,
            },
            pcie_devices,
            base_mac,
            power_state: system
                .power_state()
                .map(|v| match v {
                    NvPowerState::On => PowerState::On,
                    NvPowerState::Off => PowerState::Off,
                    NvPowerState::PoweringOn => PowerState::PoweringOn,
                    NvPowerState::PoweringOff => PowerState::PoweringOff,
                    NvPowerState::Paused => PowerState::Paused,
                })
                .unwrap_or(PowerState::default()),
            sku: system.sku().map(|v| v.to_string()),
            boot_order,
        },
        system,
    ))
}

async fn nv_fetch_system_ethernet_interfaces<B: Bmc>(
    system: &nv_redfish::computer_system::ComputerSystem<B>,
    boot_options: &[nv_redfish::computer_system::BootOption<B>],
    fetch_bluefield_oob: bool,
) -> Result<Vec<EthernetInterface>, EndpointExplorationError> {
    let interfaces = match system.ethernet_interfaces().await {
        Ok(ifaces) => ifaces
            .members()
            .await
            .map_err(|err| map_nv_redfish_error("system ethernet interfaces members", err))?,
        Err(NvRedfishError::EthernetInterfacesNotAvailable) => vec![],
        Err(e) => Err(map_nv_redfish_error("system ethernet interfaces", e))?,
    };

    let mut oob_found = false;
    let mut eth_ifs = Vec::new();
    for iface in interfaces {
        oob_found |= iface.id().inner().to_lowercase().contains("oob");

        let mac_address = iface
            .mac_address()
            .map(|addr| {
                deserialize_input_mac_to_address(addr.inner())
                .map_err(|e| RedfishError::GenericError {
                    error: format!("MAC address not valid: {addr} (err: {e})"),
                })
                    .map_err(map_redfish_error)
            })
            .transpose()
            .or_else(|err| {
                if iface
                    .interface_enabled().is_some_and(|is_enabled| !is_enabled.inner())
                {
                    // disabled interfaces sometimes populate the MAC address with junk,
                    // ignore this error and create the interface with an empty mac address
                    // in the exploration report
                    tracing::debug!(
                        "could not parse MAC address for a disabled interface {} (link_status: {:#?}): {err}",
                    iface.id(), iface.link_status()
                    );
                    Ok(None)
                } else {
                    Err(err)
                }
            })?;

        let uefi_device_path = iface
            .uefi_device_path()
            .map(|v| v.into_inner().as_str())
            .map(UefiDevicePath::from_str)
            .transpose()
            .map_err(map_redfish_error)?;

        let iface = EthernetInterface {
            description: iface.description().map(|d| d.cloned().into_inner()),
            id: Some(iface.id().cloned().into_inner()),
            interface_enabled: iface.interface_enabled().map(|v| v.into_inner()),
            mac_address,
            uefi_device_path,
        };

        eth_ifs.push(iface);
    }

    if !oob_found && fetch_bluefield_oob {
        // Temporary workaround untill get_system_ethernet_interface will return oob interface information
        // Usually the workaround for not even being able to enumerate the interfaces
        // would be used. But if a future Bluefield BMC revision returns interfaces
        // but still misses the OOB interface, we would use this path.
        if let Some(oob_iface) = nv_get_oob_interface(boot_options)? {
            eth_ifs.push(oob_iface);
        } else {
            return Err(EndpointExplorationError::RedfishError {
                details: "oob interface missing for dpu".to_string(),
                response_code: None,
                response_body: None,
            });
        }
    }

    Ok(eth_ifs)
}

fn nv_get_oob_interface<B: Bmc>(
    boot_options: &[nv_redfish::computer_system::BootOption<B>],
) -> Result<Option<EthernetInterface>, EndpointExplorationError> {
    // Temporary workaround until oob mac would be possible to get via Redfish
    let mac_pattern = Regex::new(r"MAC\((?<mac>[[:alnum:]]+)\,").unwrap();

    for boot_option in boot_options {
        // display_name: "NET-OOB-IPV4"
        if boot_option
            .display_name()
            .is_some_and(|v| v.inner().contains("OOB"))
        {
            let Some(uefi_device_path) = boot_option.uefi_device_path().map(|v| v.into_inner())
            else {
                // Try whether there might be other matching options
                continue;
            };
            // UefiDevicePath: "MAC(B83FD2909582,0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)/Uri()"
            if let Some(captures) = mac_pattern.captures(uefi_device_path.as_str()) {
                let mac_addr_str = captures.name("mac").unwrap().as_str();
                let mut mac_addr_builder = String::new();

                // Transform B83FD2909582 -> B8:3F:D2:90:95:82
                for (i, c) in mac_addr_str.chars().enumerate() {
                    mac_addr_builder.push(c);
                    if ((i + 1) % 2 == 0) && ((i + 1) < mac_addr_str.len()) {
                        mac_addr_builder.push(':');
                    }
                }

                let mac_addr =
                    deserialize_input_mac_to_address(&mac_addr_builder).map_err(|e| {
                        EndpointExplorationError::RedfishError {
                            details: format!(
                                "MAC address not valid: {mac_addr_builder} (err: {e})"
                            ),
                            response_code: None,
                            response_body: None,
                        }
                    })?;

                return Ok(Some(EthernetInterface {
                    description: Some("1G DPU OOB network interface".to_string()),
                    id: Some("oob_net0".to_string()),
                    interface_enabled: None,
                    mac_address: Some(mac_addr),
                    uefi_device_path: None,
                }));
            }
        }
    }

    // OOB Interface was not found
    Ok(None)
}

async fn fetch_ethernet_interfaces(
    client: &dyn Redfish,
    fetch_system_interfaces: bool,
    fetch_bluefield_oob: bool,
) -> Result<Vec<EthernetInterface>, RedfishError> {
    let eth_if_ids: Vec<String> = match match fetch_system_interfaces {
        false => client.get_manager_ethernet_interfaces().await,
        true => client.get_system_ethernet_interfaces().await,
    } {
        Ok(ids) => ids,
        Err(e) => {
            match e {
                RedfishError::HTTPErrorCode { status_code, .. } if status_code == NOT_FOUND => {
                    // missing oob for DPUs is handled below
                    Vec::new()
                }
                _ => return Err(e),
            }
        }
    };
    let mut eth_ifs: Vec<EthernetInterface> = Vec::new();
    let mut oob_found = false;

    for iface_id in eth_if_ids.iter() {
        let iface = match fetch_system_interfaces {
            false => client.get_manager_ethernet_interface(iface_id).await,
            true => client.get_system_ethernet_interface(iface_id).await,
        }?;

        oob_found |= iface_id.to_lowercase().contains("oob");

        let mac_address = if let Some(iface_mac_address) = iface.mac_address {
            match deserialize_input_mac_to_address(&iface_mac_address).map_err(|e| {
                RedfishError::GenericError {
                    error: format!("MAC address not valid: {iface_mac_address} (err: {e})"),
                }
            }) {
                Ok(mac) => Ok(Some(mac)),
                Err(e) => {
                    if iface
                        .interface_enabled
                        .is_some_and(|is_enabled| !is_enabled)
                    {
                        // disabled interfaces sometimes populate the MAC address with junk,
                        // ignore this error and create the interface with an empty mac address
                        // in the exploration report
                        tracing::debug!(
                            "could not parse MAC address for a disabled interface {iface_id} (link_status: {:#?}): {e}",
                            iface.link_status
                        );
                        Ok(None)
                    } else {
                        Err(e)
                    }
                }
            }
        } else {
            Ok(None)
        }?;

        let uefi_device_path = if let Some(uefi_device_path) = iface.uefi_device_path {
            let path_as_version_string = UefiDevicePath::from_str(&uefi_device_path)?;
            Some(path_as_version_string)
        } else {
            None
        };

        let iface = EthernetInterface {
            description: iface.description,
            id: iface.id,
            interface_enabled: iface.interface_enabled,
            mac_address,
            uefi_device_path,
        };

        eth_ifs.push(iface);
    }

    if !oob_found && fetch_bluefield_oob {
        // Temporary workaround untill get_system_ethernet_interface will return oob interface information
        // Usually the workaround for not even being able to enumerate the interfaces
        // would be used. But if a future Bluefield BMC revision returns interfaces
        // but still misses the OOB interface, we would use this path.
        if let Some(oob_iface) = get_oob_interface(client).await? {
            eth_ifs.push(oob_iface);
        } else {
            return Err(RedfishError::GenericError {
                error: "oob interface missing for dpu".to_string(),
            });
        }
    }

    Ok(eth_ifs)
}

async fn get_oob_interface(
    client: &dyn Redfish,
) -> Result<Option<EthernetInterface>, RedfishError> {
    // If chassis.contains(&"MGX_NVSwitch_0".to_string()),
    // nvlink switch does not have oob interface. And, if we try
    // querying boot options over redfish, we will get a 404 error.
    // So just return Ok(None) here.
    if is_switch(client).await? || is_powershelf(client).await? {
        return Ok(None);
    }

    // Temporary workaround until oob mac would be possible to get via Redfish
    let boot_options = client.get_boot_options().await?;
    let mac_pattern = Regex::new(r"MAC\((?<mac>[[:alnum:]]+)\,").unwrap();
    let mut boot_order_first_ethernet_interface = None;

    for option in boot_options.members.iter() {
        // odata_id: "/redfish/v1/Systems/Bluefield/BootOptions/Boot0001"
        let option_id = option.odata_id.split('/').next_back().unwrap();
        let boot_option = client.get_boot_option(option_id).await?;
        // display_name: "NET-OOB-IPV4"
        if boot_option.display_name.contains("OOB") {
            if boot_option.uefi_device_path.is_none() {
                // Try whether there might be other matching options
                continue;
            }
            // UefiDevicePath: "MAC(B83FD2909582,0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)/Uri()"
            if let Some(captures) =
                mac_pattern.captures(boot_option.uefi_device_path.unwrap().as_str())
            {
                let mac_addr_str = captures.name("mac").unwrap().as_str();
                let mut mac_addr_builder = String::new();

                // Transform B83FD2909582 -> B8:3F:D2:90:95:82
                for (i, c) in mac_addr_str.chars().enumerate() {
                    mac_addr_builder.push(c);
                    if ((i + 1) % 2 == 0) && ((i + 1) < mac_addr_str.len()) {
                        mac_addr_builder.push(':');
                    }
                }

                let mac_addr =
                    deserialize_input_mac_to_address(&mac_addr_builder).map_err(|e| {
                        RedfishError::GenericError {
                            error: format!("MAC address not valid: {mac_addr_builder} (err: {e})"),
                        }
                    })?;

                let (description, id) = if boot_option.display_name.contains("OOB") {
                    (
                        Some("1G DPU OOB network interface".to_string()),
                        Some("oob_net0".to_string()),
                    )
                } else {
                    (boot_option.description, Some(option_id.to_string()))
                };

                boot_order_first_ethernet_interface = Some(EthernetInterface {
                    description: description.clone(),
                    id: id.clone(),
                    interface_enabled: None,
                    mac_address: Some(mac_addr),
                    uefi_device_path: None,
                });
            }
        }
    }

    Ok(boot_order_first_ethernet_interface)
}

async fn nv_fetch_chassis<B: Bmc>(
    vendor: Option<nv_redfish::service_root::Vendor<&String>>,
    members: &Vec<NvChassis<B>>,
) -> Result<Vec<Chassis>, EndpointExplorationError> {
    let mut chassis: Vec<Chassis> = Vec::new();
    for m in members {
        let network_adapters = match m.network_adapters().await {
            Ok(network_adapters) => network_adapters,
            Err(nv_redfish::Error::NetworkAdaptersNotAvailable) => {
                // This is libredfish behavior. We don't change
                // it.
                //
                // 1. For HPE we enumerate chassis without
                //    network adapters...
                //
                // 2. Libredfish doesn't care about existance of
                //    NetworkAdapters in chassis and requests Chassis/{}/NetworkAdapters
                //    By some magic Bluefield_ERoT:
                //      a. Doesn't provide NetworkAdapters field in Chassis
                //      b. Reponds with empty collection on Chassis/Bluefield_ERoT/NetworkAdapters
                if vendor.is_some_and(|v| v.inner().as_str() == "HPE")
                    || (vendor.is_some_and(|v| v.inner().as_str() == "Nvidia")
                        && m.id().inner().as_str() == "Bluefield_ERoT")
                {
                    vec![]
                } else {
                    continue;
                }
            }
            Err(err) => return Err(map_nv_redfish_error("chassis network adapters", err)),
        };

        let network_adapters: Vec<_> = network_adapters
            .into_iter()
            .map(|adapter| {
                let hw_id = adapter.hardware_id();
                NetworkAdapter {
                    id: adapter.id().cloned().into_inner(),
                    manufacturer: hw_id.manufacturer.map(|v| v.cloned().into_inner()),
                    model: hw_id.model.map(|v| v.cloned().into_inner()),
                    part_number: hw_id.part_number.map(|v| v.cloned().into_inner()),
                    serial_number: Some(
                        hw_id
                            .serial_number
                            .map(|v| v.inner().trim())
                            .unwrap_or("")
                            .to_owned(),
                    ),
                }
            })
            .collect();
        let chassis_id = m.id().cloned();
        let hw_id = m.hardware_id().cloned();
        // For GB200s, use the Chassis_0 assembly serial number to match Nautobot.
        let serial_number = if chassis_id.inner() == "Chassis_0" {
            match m.assembly().await {
                Ok(assembly) => {
                    let assembly_data = assembly
                        .assemblies()
                        .await
                        .map_err(|err| map_nv_redfish_error("chassis assemblies", err))?;
                    assembly_data
                        .iter()
                        .find(|asm| {
                            asm.hardware_id().model.map(|v| v.inner().as_str()) == Some("GB200 NVL")
                        })
                        .and_then(|asm| asm.hardware_id().serial_number)
                        .map(|v| v.cloned().into_inner())
                }
                Err(nv_redfish::Error::AssemblyNotAvailable) => None,
                Err(err) => return Err(map_nv_redfish_error("chassis assembly", err)),
            }
        } else {
            None
        }
        .or(hw_id.serial_number.map(|v| v.into_inner()));

        let nvidia_oem = m.oem_nvidia_baseboard_cbc().ok();
        chassis.push(Chassis {
            id: chassis_id.into_inner(),
            manufacturer: hw_id.manufacturer.map(|v| v.into_inner()),
            model: hw_id.model.map(|v| v.into_inner()),
            part_number: hw_id.part_number.map(|v| v.into_inner()),
            serial_number,
            network_adapters,
            physical_slot_number: nvidia_oem
                .as_ref()
                .and_then(|x| x.chassis_physical_slot_number())
                .map(|v| v.into_inner() as i32),
            compute_tray_index: nvidia_oem
                .as_ref()
                .and_then(|x| x.compute_tray_index())
                .map(|v| v.into_inner() as i32),
            topology_id: nvidia_oem
                .as_ref()
                .and_then(|x| x.topology_id())
                .map(|v| v.into_inner() as i32),
            revision_id: nvidia_oem
                .as_ref()
                .and_then(|x| x.revision_id())
                .map(|v| v.into_inner() as i32),
        });
    }
    Ok(chassis)
}

async fn fetch_chassis(client: &dyn Redfish) -> Result<Vec<Chassis>, RedfishError> {
    let mut chassis: Vec<Chassis> = Vec::new();

    let chassis_list = client.get_chassis_all().await?;
    for chassis_id in &chassis_list {
        let Ok(desc) = client.get_chassis(chassis_id).await else {
            continue;
        };

        let net_adapter_list = if desc.network_adapters.is_some() {
            match client.get_chassis_network_adapters(chassis_id).await {
                Ok(v) => v,
                Err(RedfishError::NotSupported(_)) => vec![],
                // Nautobot uses Chassis_0 as the source of truth for the GB200 chassis serial number.
                // Other chassis subsystems with network adapters may report different serial numbers.
                Err(RedfishError::MissingKey { .. }) if chassis_id == "Chassis_0" => vec![],
                Err(_) => continue,
            }
        } else {
            vec![]
        };

        let mut net_adapters: Vec<NetworkAdapter> = Vec::new();
        for net_adapter_id in &net_adapter_list {
            let value = client
                .get_chassis_network_adapter(chassis_id, net_adapter_id)
                .await?;

            let net_adapter = NetworkAdapter {
                id: value.id,
                manufacturer: value.manufacturer,
                model: value.model,
                part_number: value.part_number,
                serial_number: Some(
                    value
                        .serial_number
                        .as_ref()
                        .unwrap_or(&"".to_string())
                        .trim()
                        .to_string(),
                ),
            };

            net_adapters.push(net_adapter);
        }

        // For GB200s, use the Chassis_0 assembly serial number to match Nautobot.
        let serial_number = if chassis_id == "Chassis_0" {
            client
                .get_chassis_assembly("Chassis_0")
                .await
                .ok()
                .and_then(|assembly| {
                    assembly
                        .assemblies
                        .iter()
                        .find(|asm| asm.model.as_deref() == Some("GB200 NVL"))
                        .and_then(|asm| asm.serial_number.clone())
                })
                .or(desc.serial_number)
        } else {
            desc.serial_number
        };

        let nvidia_oem = desc.oem.as_ref().and_then(|x| x.nvidia.as_ref());
        chassis.push(Chassis {
            id: chassis_id.to_string(),
            manufacturer: desc.manufacturer,
            model: desc.model,
            part_number: desc.part_number,
            serial_number,
            network_adapters: net_adapters,
            physical_slot_number: nvidia_oem.and_then(|x| x.chassis_physical_slot_number),
            compute_tray_index: nvidia_oem.and_then(|x| x.compute_tray_index),
            topology_id: nvidia_oem.and_then(|x| x.topology_id),
            revision_id: nvidia_oem.and_then(|x| x.revision_id),
        });
    }

    Ok(chassis)
}

async fn fetch_boot_order(
    client: &dyn Redfish,
    system: &libredfish::model::ComputerSystem,
) -> Result<BootOrder, RedfishError> {
    let boot_options_id =
        system
            .boot
            .boot_options
            .clone()
            .ok_or_else(|| RedfishError::MissingKey {
                key: "boot.boot_options".to_string(),
                url: system.odata.odata_id.to_string(),
            })?;

    let all_boot_options: Vec<BootOption> = client
        .get_collection(boot_options_id)
        .await
        .and_then(|t1| t1.try_get::<libredfish::model::BootOption>())
        .into_iter()
        .flat_map(|x1| x1.members)
        .map(Into::into)
        .collect();

    let boot_order: Vec<BootOption> = system
        .boot
        .boot_order
        .iter()
        .filter_map(|id| all_boot_options.iter().find(|opt| opt.id == *id).cloned())
        .collect();

    Ok(BootOrder { boot_order })
}

async fn fetch_pcie_devices(client: &dyn Redfish) -> Result<Vec<PCIeDevice>, RedfishError> {
    let pci_device_list = client.pcie_devices().await?;
    let mut pci_devices: Vec<PCIeDevice> = Vec::new();

    for pci_device in pci_device_list {
        pci_devices.push(PCIeDevice {
            description: pci_device.description,
            firmware_version: pci_device.firmware_version,
            id: pci_device.id.clone(),
            manufacturer: pci_device.manufacturer,
            gpu_vendor: pci_device.gpu_vendor,
            name: pci_device.name,
            part_number: pci_device.part_number,
            serial_number: pci_device.serial_number,
            status: pci_device.status.map(|s| s.into()),
        });
    }
    Ok(pci_devices)
}

async fn nv_fetch_pcie_devices<B: Bmc>(
    vendor: Option<Vendor<&String>>,
    system_id: ResourceIdRef<'_>,
    chassis: &[NvChassis<B>],
) -> Result<Vec<PCIeDevice>, EndpointExplorationError> {
    let chassis = match vendor
        .map(|v| v.into_inner().to_lowercase())
        .unwrap_or("".to_string())
        .as_str()
    {
        "ami" => {
            // Viking:
            chassis
                .iter()
                .filter(|c| {
                    c.id().inner().starts_with("HGX_GPU_SXM")
                        || c.id().inner().starts_with("HGX_NVSwitch")
                })
                .collect::<Vec<_>>()
        }
        _ => {
            if let Some(c) = chassis.iter().find(|c| c.id().inner() == system_id.inner()) {
                // chassis with the same name as computer system...
                vec![c]
            } else if let Some(c) = chassis.first() {
                vec![c]
            } else {
                vec![]
            }
        }
    };
    let mut pci_devices: Vec<PCIeDevice> = Vec::new();

    for c in &chassis {
        let chassis_pcie_devices = c
            .pcie_devices()
            .await
            .map_err(|err| map_nv_redfish_error("chassis pcie devices", err))?
            .members()
            .await
            .map_err(|err| map_nv_redfish_error("chassis pcie devices members", err))?;
        for dev in chassis_pcie_devices {
            let hw_id = dev.hardware_id();
            let status = dev.status();
            if hw_id.manufacturer.is_none() {
                continue;
            }
            if status.as_ref().is_some_and(|s| {
                s.state
                    .is_some_and(|v| v != nv_redfish::resource::State::Enabled)
            }) {
                continue;
            }
            pci_devices.push(PCIeDevice {
                description: dev.description().map(|v| v.cloned().into_inner()),
                firmware_version: dev.firmware_version().map(|v| v.cloned().into_inner()),
                id: Some(dev.id().cloned().into_inner()),
                manufacturer: hw_id.manufacturer.map(|v| v.cloned().into_inner()),
                // TODO: In old model it is dev.gpu_vendor, but it is
                // not standard. It can be taken from
                // .Oem.Supermicro.GPUDevice.GPUVendor for Supermicro
                // but it was never implemented.
                gpu_vendor: None,
                name: Some(dev.name().cloned().into_inner()),
                part_number: hw_id.part_number.map(|v| v.cloned().into_inner()),
                // Trim of serial_number is added because serial
                // number of DPU contains trailing spaces... Probably,
                // it should be code specific for DPU...
                serial_number: hw_id.serial_number.map(|v| {
                    if vendor.is_some_and(|v| v.inner().as_str() == "HPE") {
                        // TODO: This is how it is implemented in
                        // libredfish. I'm quite sure that it should
                        // be same way for all vendors but is unknown
                        // if it safe to change
                        v.inner().trim().to_string()
                    } else {
                        v.inner().to_string()
                    }
                }),
                // TODO: Should not be converted to string....
                status: status.map(|status| model::site_explorer::SystemStatus {
                    health: status.health.map(|v| {
                        match v {
                            nv_redfish::resource::Health::Ok => "OK",
                            nv_redfish::resource::Health::Warning => "Warning",
                            nv_redfish::resource::Health::Critical => "Critical",
                        }
                        .into()
                    }),
                    health_rollup: status.health_rollup.map(|v| {
                        match v {
                            nv_redfish::resource::Health::Ok => "OK",
                            nv_redfish::resource::Health::Warning => "Warning",
                            nv_redfish::resource::Health::Critical => "Critical",
                        }
                        .into()
                    }),
                    // Not enabled devices are filtered by code above.
                    state: status
                        .state
                        .map(|_| "Enabled".to_string())
                        .unwrap_or("".into()),
                }),
            });
        }
    }
    Ok(pci_devices)
}

async fn fetch_service(client: &dyn Redfish) -> Result<Vec<Service>, RedfishError> {
    let mut service: Vec<Service> = Vec::new();

    let inventory_list = client.get_software_inventories().await?;
    let mut inventories: Vec<Inventory> = Vec::new();
    for inventory_id in &inventory_list {
        let Ok(value) = client.get_firmware(inventory_id).await else {
            continue;
        };

        let inventory = Inventory {
            id: value.id,
            description: value.description,
            version: value.version,
            release_date: value.release_date,
        };

        inventories.push(inventory);
    }

    service.push(Service {
        id: "FirmwareInventory".to_string(),
        inventories,
    });

    Ok(service)
}

async fn nv_fetch_service<B: Bmc>(
    root: &ServiceRoot<B>,
) -> Result<Vec<Service>, EndpointExplorationError> {
    let fw_inventory = Service {
        id: "FirmwareInventory".to_string(),
        inventories: root
            .update_service()
            .await
            .map_err(|err| map_nv_redfish_error("update service", err))?
            .firmware_inventories()
            .await
            .map_err(|err| map_nv_redfish_error("update service firmware inventories", err))?
            .into_iter()
            .map(|inventory| Inventory {
                id: inventory.id().cloned().into_inner(),
                description: inventory.description().map(|v| v.cloned().into_inner()),
                version: if root
                    .vendor()
                    .is_some_and(|v| v.inner().as_str() == "Lenovo")
                {
                    inventory.version().map(|v| {
                        // Original comment from libredfish:
                        //
                        // Lenovo prepends the last two characters of
                        // their "Build/Vendor" ID and a dash to most
                        // of the versions.  This confuses things, so
                        // trim off anything that's before a dash.
                        v.cloned()
                            .into_inner()
                            .split('-')
                            .next_back()
                            .unwrap_or("")
                            .to_string()
                    })
                } else {
                    inventory.version().map(|v| v.cloned().into_inner())
                },
                release_date: inventory.release_date().map(|v| v.into_inner().to_string()),
            })
            .collect(),
    };
    Ok(vec![fw_inventory])
}

fn nv_is_infinite_boot_enabled<B: Bmc>(
    system: &nv_redfish::computer_system::ComputerSystem<B>,
    root: &nv_redfish::ServiceRoot<B>,
    bios: &nv_redfish::computer_system::Bios<B>,
) -> Option<bool> {
    let hw_id = system.hardware_id();
    let (Some(manufacturer), Some(model)) = (hw_id.manufacturer, hw_id.model) else {
        let (Some(vendor), Some(product)) = (root.vendor(), root.product()) else {
            return None;
        };
        return match (vendor.inner().as_str(), product.inner().as_str()) {
            ("NVIDIA", "GB200 NVL") => bios
                .attribute("EmbeddedUefiShell")
                .and_then(|attr| attr.string_value().map(|v| v == "Enabled")),
            _ => None,
        };
    };
    match manufacturer.inner().as_str() {
        "Dell Inc." => bios
            .attribute("BootSeqRetry")
            .and_then(|attr| attr.string_value().map(|v| v == "Enabled")),
        "WIWYNN" => match model.inner().as_str() {
            "GB200 NVL" => bios
                .attribute("EmbeddedUefiShell")
                .and_then(|attr| attr.string_value().map(|v| v == "Enabled")),
            _ => None,
        },
        "Lenovo" => bios
            .attribute("BootModes_InfiniteBootRetry")
            .and_then(|attr| attr.string_value().map(|v| v == "Enabled")),
        _ => None,
    }
}

fn nv_dpu_mode<B: Bmc>(
    system: &nv_redfish::computer_system::ComputerSystem<B>,
    bios: &nv_redfish::computer_system::Bios<B>,
    bf_ncs: &nv_redfish::oem::nvidia::bluefield::NvidiaComputerSystem<B>,
) -> Option<NicMode> {
    let hw_id = system.hardware_id();
    let manufacturer = hw_id.manufacturer.map(|v| v.inner().as_str());
    let model = hw_id.model.map(|v| v.inner().as_str());
    match manufacturer {
        None | Some("Nvidia") | Some("https://www.mellanox.com") => {
            match model {
                None | Some("BlueField-3 DPU") | Some("BlueField-3 SmartNIC Main Card") => {
                    use nv_redfish::oem::nvidia::bluefield::nvidia_computer_system::Mode;
                    bf_ncs.mode().map(|v| match v {
                        Mode::DpuMode => NicMode::Dpu,
                        Mode::NicMode => NicMode::Nic,
                    })
                }
                Some("Bluefield 2 SmartNIC Main Card") => {
                    // Get from bios
                    bios.attribute("NicMode").and_then(|attr| {
                        attr.string_value().and_then(|v| match v.as_str() {
                            "NicMode" => Some(NicMode::Nic),
                            "DpuMode" => Some(NicMode::Dpu),
                            _ => None,
                        })
                    })
                }
                _ => None,
            }
        }
        _ => None,
    }
}

async fn fetch_machine_setup_status(
    client: &dyn Redfish,
    boot_interface_mac: Option<MacAddress>,
) -> Result<MachineSetupStatus, RedfishError> {
    let status = client
        .machine_setup_status(boot_interface_mac.map(|mac| mac.to_string()).as_deref())
        .await?;
    let mut diffs: Vec<MachineSetupDiff> = Vec::new();

    for diff in status.diffs {
        diffs.push(MachineSetupDiff {
            key: diff.key,
            expected: diff.expected,
            actual: diff.actual,
        });
    }

    Ok(MachineSetupStatus {
        is_done: status.is_done,
        diffs,
    })
}

async fn fetch_secure_boot_status(client: &dyn Redfish) -> Result<SecureBootStatus, RedfishError> {
    let status = client.get_secure_boot().await?;

    let secure_boot_enable =
        status
            .secure_boot_enable
            .ok_or_else(|| RedfishError::GenericError {
                error: "expected secure_boot_enable_field set in secure boot response".to_string(),
            })?;

    let secure_boot_current_boot =
        status
            .secure_boot_current_boot
            .ok_or_else(|| RedfishError::GenericError {
                error: "expected secure_boot_current_boot set in secure boot response".to_string(),
            })?;

    let is_enabled = secure_boot_enable && secure_boot_current_boot.is_enabled();

    Ok(SecureBootStatus { is_enabled })
}

async fn fetch_lockdown_status(client: &dyn Redfish) -> Result<LockdownStatus, RedfishError> {
    let status = client.lockdown_status().await?;
    let internal_status = if status.is_fully_enabled() {
        InternalLockdownStatus::Enabled
    } else if status.is_fully_disabled() {
        InternalLockdownStatus::Disabled
    } else {
        InternalLockdownStatus::Partial
    };
    Ok(LockdownStatus {
        status: internal_status,
        message: status.message().to_string(),
    })
}

fn nv_bmc_vendor<B: Bmc>(root: &nv_redfish::ServiceRoot<B>) -> Option<bmc_vendor::BMCVendor> {
    root.vendor()
        .and_then(|vendor| {
            match vendor.inner().as_str() {
                "Dell" => Some(bmc_vendor::BMCVendor::Dell),
                "Lenovo" => Some(bmc_vendor::BMCVendor::Lenovo),
                "HPE" => Some(bmc_vendor::BMCVendor::Hpe),
                "Nvidia" => Some(bmc_vendor::BMCVendor::Nvidia),
                "AMI" => {
                    // Don't ask... this is highly likely Nvidia Viking...
                    Some(bmc_vendor::BMCVendor::Nvidia)
                }
                _ => None,
            }
        })
        .or_else(|| {
            root.oem_id()
                .map(|v| v.inner().as_str())
                .and_then(|v| match v {
                    "Supermicro" => Some(bmc_vendor::BMCVendor::Supermicro),
                    _ => None,
                })
        })
}

pub(crate) fn map_redfish_client_creation_error(
    error: RedfishClientCreationError,
) -> EndpointExplorationError {
    match error {
        RedfishClientCreationError::MissingCredentials { key } => {
            EndpointExplorationError::MissingCredentials {
                key,
                cause: "credentials are missing in the secret engine".into(),
            }
        }
        RedfishClientCreationError::SecretEngineError { cause } => {
            EndpointExplorationError::SecretsEngineError {
                cause: format!("secret engine error occurred: {cause:#}"),
            }
        }
        RedfishClientCreationError::RedfishError(e) => map_redfish_error(e),
        RedfishClientCreationError::InvalidHeader(original_error) => {
            EndpointExplorationError::Other {
                details: format!("RedfishClientError::InvalidHeader: {original_error}"),
            }
        }
        RedfishClientCreationError::MissingBmcEndpoint(argument)
        | RedfishClientCreationError::MissingArgument(argument) => {
            EndpointExplorationError::Other {
                details: format!("Missing argument to RedFish client: {argument}"),
            }
        }
        RedfishClientCreationError::MachineInterfaceLoadError(db_error) => {
            EndpointExplorationError::Other {
                details: format!(
                    "Database error loading the machine interface for the redfish client: {db_error}"
                ),
            }
        }
    }
}

pub(crate) fn map_redfish_error(error: RedfishError) -> EndpointExplorationError {
    match &error {
        RedfishError::NetworkError { url, source } => {
            let details = format!("url: {url};\nsource: {source};\nerror: {error}");
            if source.is_connect() {
                EndpointExplorationError::ConnectionRefused { details }
            } else if source.is_timeout() {
                EndpointExplorationError::ConnectionTimeout { details }
            } else {
                EndpointExplorationError::Unreachable {
                    details: Some(details),
                }
            }
        }
        RedfishError::HTTPErrorCode {
            status_code,
            response_body,
            url,
        } if *status_code == http::StatusCode::FORBIDDEN && url.contains("FirmwareInventory") => {
            EndpointExplorationError::VikingFWInventoryForbiddenError {
                details: format!(
                    "HTTP {status_code} at {url} - this is a known, intermittent issue for Vikings."
                ),
                response_body: Some(response_body.clone()),
                response_code: Some(status_code.as_u16()),
            }
        }
        RedfishError::HTTPErrorCode {
            status_code,
            response_body,
            url,
        } if *status_code == http::StatusCode::UNAUTHORIZED
            || *status_code == http::StatusCode::FORBIDDEN =>
        {
            let code_str = status_code.as_str();
            EndpointExplorationError::Unauthorized {
                details: format!("HTTP {status_code} {code_str} at {url}"),
                response_body: Some(response_body.clone()),
                response_code: Some(status_code.as_u16()),
            }
        }
        RedfishError::HTTPErrorCode {
            status_code,
            response_body,
            url,
        } => EndpointExplorationError::RedfishError {
            details: format!("HTTP {status_code} at {url}"),
            response_body: Some(response_body.clone()),
            response_code: Some(status_code.as_u16()),
        },
        RedfishError::JsonDeserializeError { url, body, source } => {
            EndpointExplorationError::RedfishError {
                details: format!("Failed to deserialize data from {url}: {source}"),
                response_body: Some(body.clone()),
                response_code: None,
            }
        }
        _ => EndpointExplorationError::RedfishError {
            details: error.to_string(),
            response_body: None,
            response_code: None,
        },
    }
}

fn map_nv_redfish_error<B: Bmc>(topic: &str, error: NvRedfishError<B>) -> EndpointExplorationError {
    EndpointExplorationError::RedfishError {
        details: format!("{topic} error: {error}"),
        response_body: None,
        response_code: None,
    }
}
