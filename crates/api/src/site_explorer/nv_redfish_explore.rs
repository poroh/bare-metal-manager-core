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
use std::convert::identity;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use forge_network::deserialize_input_mac_to_address;
use itertools::Itertools;
use libredfish::Redfish;
use libredfish::model::oem::nvidia_dpu::NicMode;
use model::site_explorer::{
    BootOption, BootOrder, Chassis, ComputerSystem, ComputerSystemAttributes,
    EndpointExplorationReport, EndpointType, EthernetInterface, InternalLockdownStatus, Inventory,
    LockdownStatus, Manager, NetworkAdapter, PCIeDevice, PowerState, SecureBootStatus, Service,
    UefiDevicePath,
};
use nv_redfish::chassis::Chassis as NvChassis;
use nv_redfish::computer_system::SecureBootCurrentBootType;
use nv_redfish::ethernet_interface::EthernetInterface as NvEthernetInterface;
use nv_redfish::hardware_id::Model;
use nv_redfish::manager::Manager as NvManager;
use nv_redfish::oem::lenovo::computer_system::{FpMode, PortSwitchingTo};
use nv_redfish::oem::lenovo::manager::KcsState;
use nv_redfish::oem::lenovo::security_service::FwRollbackState;
use nv_redfish::oem::supermicro::Privilege as SupermicroPrivilege;
use nv_redfish::resource::{PowerState as NvPowerState, ResourceIdRef};
use nv_redfish::service_root::Vendor;
use nv_redfish::{Bmc, Error as NvRedfishError, Resource, ResourceProvidesStatus, ServiceRoot};
use regex::Regex;

use crate::site_explorer::redfish;
pub enum Error<B: Bmc> {
    NvRedfish {
        context: &'static str,
        err: NvRedfishError<B>,
    },
    BmcNotProvided(&'static str),
    InvalidValue(String),
}

impl<B: Bmc> fmt::Display for Error<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NvRedfish { context, err } => write!(f, "redfish error in {context}: {err}"),
            Self::BmcNotProvided(what) => write!(f, "BMC has not provided {what}"),
            Self::InvalidValue(what) => write!(f, "Invalid value {what}"),
        }
    }
}

impl<B: Bmc> Error<B> {
    fn nv_redfish(context: &'static str) -> impl Fn(NvRedfishError<B>) -> Self {
        move |err| Self::NvRedfish { context, err }
    }

    fn bmc_not_provided(what: &'static str) -> impl Fn() -> Self {
        move || Self::BmcNotProvided(what)
    }
    fn bmc_not_provided_opt<T>(what: &'static str) -> impl Fn(Option<T>) -> Result<T, Self> {
        move |v| v.ok_or(Self::BmcNotProvided(what))
    }
}

pub async fn nv_generate_exploration_report<B: Bmc>(
    client: Box<dyn Redfish>,
    bmc: Arc<B>,
) -> Result<EndpointExplorationReport, Error<B>> {
    let root = ServiceRoot::new(bmc)
        .await
        .map_err(Error::nv_redfish("service_root"))?;

    let vendor = nv_bmc_vendor(&root);

    let (manager, nv_manager, nv_manager_eths) = nv_fetch_manager(&root).await?;
    let nv_chassis_members = root
        .chassis()
        .await
        .map_err(Error::nv_redfish("chassis collection"))?
        .ok_or_else(Error::bmc_not_provided("chassis collection"))?
        .members()
        .await
        .map_err(Error::nv_redfish("chassis collection members"))?;
    let (system, nv_system_handle, nv_bios) = nv_fetch_system(&root, &nv_chassis_members).await?;

    let chassis = nv_fetch_chassis(&nv_chassis_members).await?;
    let service = nv_fetch_service(&root).await?;

    let machine_setup_status = redfish::fetch_machine_setup_status(client.as_ref(), None)
        .await
        .inspect_err(|error| tracing::warn!(%error, "Failed to fetch forge setup status."))
        .ok();

    let secure_boot_status = nv_system_handle
        .secure_boot()
        .await
        .map_err(Error::nv_redfish("secure boot"))
        .and_then(Error::bmc_not_provided_opt("secure boot"))
        .and_then(|v| {
            let enabled = v.secure_boot_enable().ok_or_else(Error::bmc_not_provided(
                "SecureBootEnable in SecureBoot resource",
            ))?;
            let current_boot = v
                .secure_boot_current_boot()
                .ok_or_else(Error::bmc_not_provided(
                    "SecureBootCurrentBootType in SecureBoot resource",
                ))?;
            Ok(SecureBootStatus {
                is_enabled: enabled && current_boot == SecureBootCurrentBootType::Enabled,
            })
        })
        .inspect_err(|error| tracing::warn!(%error, "Failed to fetch forge secure boot status."))
        .ok();

    let lockdown_status = nv_fetch_lockdown_status(
        &root,
        &nv_bios,
        &nv_manager,
        &nv_manager_eths,
        &nv_system_handle,
    )
    .await?;

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

pub(crate) fn nv_bmc_vendor<B: Bmc>(
    root: &nv_redfish::ServiceRoot<B>,
) -> Option<bmc_vendor::BMCVendor> {
    root.vendor()
        .and_then(|vendor| {
            match vendor.into_inner() {
                "Dell" => Some(bmc_vendor::BMCVendor::Dell),
                "Lenovo" => Some(bmc_vendor::BMCVendor::Lenovo),
                "HPE" => Some(bmc_vendor::BMCVendor::Hpe),
                "Nvidia" => Some(bmc_vendor::BMCVendor::Nvidia),
                "AMI" => {
                    // Don't ask... this is highly likely Nvidia Viking...
                    Some(bmc_vendor::BMCVendor::Nvidia)
                }
                "WIWYNN" => Some(bmc_vendor::BMCVendor::Nvidia),
                _ => None,
            }
        })
        .or_else(|| {
            root.oem_id().map(|v| v.into_inner()).and_then(|v| match v {
                "Supermicro" => Some(bmc_vendor::BMCVendor::Supermicro),
                _ => None,
            })
        })
}

async fn nv_fetch_manager<B: Bmc>(
    root: &ServiceRoot<B>,
) -> Result<(Manager, NvManager<B>, Vec<NvEthernetInterface<B>>), Error<B>> {
    let manager = root
        .managers()
        .await
        .map_err(Error::nv_redfish("managers"))?
        .ok_or_else(Error::bmc_not_provided("managers"))?
        .members()
        .await
        .map_err(Error::nv_redfish("managers members"))?
        .into_iter()
        .next()
        .ok_or_else(Error::bmc_not_provided("at least one manager"))?;
    let (ethernet_interfaces, nv_eth_ifaces) = nv_fetch_manager_interfaces(&manager).await?;
    Ok((
        Manager {
            ethernet_interfaces,
            id: manager.id().inner().to_string(),
        },
        manager,
        nv_eth_ifaces,
    ))
}

async fn nv_fetch_manager_interfaces<B: Bmc>(
    manager: &nv_redfish::manager::Manager<B>,
) -> Result<(Vec<EthernetInterface>, Vec<NvEthernetInterface<B>>), Error<B>> {
    let interfaces = manager
        .ethernet_interfaces()
        .await
        .map_err(Error::nv_redfish("manager ethernet interfaces"))?
        .ok_or_else(Error::bmc_not_provided("manager ethernet interfaces"))?
        .members()
        .await
        .map_err(Error::nv_redfish("manager ethernet interfaces members"))?;
    let mut eth_ifs = Vec::new();
    for iface in &interfaces {
        let mac_address = iface
            .mac_address()
            .map(|addr| {
                deserialize_input_mac_to_address(addr.inner())
                    .map_err(|e| Error::InvalidValue(format!("MAC address not valid: {addr} (err: {e})")))
            })
            .transpose()
            .or_else(|err| {
                if iface
                    .interface_enabled().is_some_and(|is_enabled| !is_enabled)
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
            .map(|v| v.into_inner())
            .map(UefiDevicePath::from_str)
            .transpose()
            .map_err(|err| Error::InvalidValue(format!("UefiDevicePath: {err}")))?;

        let iface = EthernetInterface {
            description: iface.description().map(|v| v.to_string()),
            id: Some(iface.id().to_string()),
            interface_enabled: iface.interface_enabled(),
            mac_address,
            uefi_device_path,
        };

        eth_ifs.push(iface);
    }
    Ok((eth_ifs, interfaces))
}

async fn nv_fetch_system<B: Bmc>(
    root: &ServiceRoot<B>,
    chassis: &[NvChassis<B>],
) -> Result<
    (
        ComputerSystem,
        nv_redfish::computer_system::ComputerSystem<B>,
        nv_redfish::computer_system::Bios<B>,
    ),
    Error<B>,
> {
    let system = root
        .systems()
        .await
        .map_err(Error::nv_redfish("systems"))?
        .ok_or_else(Error::bmc_not_provided("systems"))?
        .members()
        .await
        .map_err(Error::nv_redfish("systems members"))?
        .into_iter()
        .next()
        .ok_or_else(Error::bmc_not_provided("at least one computer system"))?;

    let is_switch = nv_is_switch(chassis);
    let is_powershelf = nv_is_powershelf(chassis);
    let is_dpu = system.id().inner().to_lowercase().contains("bluefield");
    let nv_boot_options = system
        .boot_options()
        .await
        .map_err(Error::nv_redfish("boot options"))?
        .ok_or_else(Error::bmc_not_provided("boot_options"))?
        .members()
        .await
        .map_err(Error::nv_redfish("boot options members"))?;
    let ethernet_interfaces = nv_fetch_system_ethernet_interfaces(
        &system,
        &nv_boot_options,
        is_dpu && !is_switch && !is_powershelf,
    )
    .await?;
    let bios = system
        .bios()
        .await
        .map_err(Error::nv_redfish("bios"))?
        .ok_or_else(Error::bmc_not_provided("bios"))?;
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
                .find(|c| c.id().into_inner() == "Card1")
                .ok_or_else(Error::bmc_not_provided("chassis with id Card1"))?;
            serial_number = chassis.hardware_id().serial_number.map(|v| v.into_inner());
        }

        match system.oem_nvidia_bluefield().await {
            Ok(Some(oem_bf)) => {
                // TODO: Apparently this is a bug that it has
                // additional quotes inside String but it is not
                // obvious what will be broken if it will be fixed.
                base_mac = oem_bf.base_mac().map(|v| format!("\"{}\"", v.inner()));
                nic_mode = nv_dpu_mode(&system, &bios, &oem_bf);
            }
            Ok(None) => (),
            Err(e) => Err(Error::NvRedfish {
                context: "oem nvidia bluefield",
                err: e,
            })?,
        };
    }

    let serial_number = serial_number.map(|s| s.trim().to_string());

    let pcie_devices = if !is_powershelf {
        nv_fetch_pcie_devices(root.vendor(), system.id(), chassis).await?
    } else {
        vec![]
    };

    let is_infinite_boot_enabled = nv_is_infinite_boot_enabled(&system, root, &bios);

    let boot_order = if is_switch || is_powershelf {
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
                            id: opt.id().to_string(),
                            display_name: opt
                                .display_name()
                                .map(|v| v.to_string())
                                .unwrap_or("".into()),
                            uefi_device_path: opt.uefi_device_path().map(|v| v.to_string()),
                            boot_option_enabled: opt.enabled(),
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
        bios,
    ))
}

async fn nv_fetch_system_ethernet_interfaces<B: Bmc>(
    system: &nv_redfish::computer_system::ComputerSystem<B>,
    boot_options: &[nv_redfish::computer_system::BootOption<B>],
    fetch_bluefield_oob: bool,
) -> Result<Vec<EthernetInterface>, Error<B>> {
    let interfaces = match system.ethernet_interfaces().await {
        Ok(Some(ifaces)) => ifaces
            .members()
            .await
            .map_err(Error::nv_redfish("system ethernet interfaces members"))?,
        Ok(None) => vec![],
        Err(err) => Err(Error::NvRedfish {
            context: "system ethernet interfaces",
            err,
        })?,
    };

    let mut oob_found = false;
    let mut eth_ifs = Vec::new();
    for iface in interfaces {
        oob_found |= iface.id().inner().to_lowercase().contains("oob");

        let mac_address = iface
            .mac_address()
            .map(|addr| {
                deserialize_input_mac_to_address(addr.inner())
                    .map_err(|e| Error::InvalidValue(format!("MAC address not valid: {addr} (err: {e})")))
            })
            .transpose()
            .or_else(|err| {
                if iface
                    .interface_enabled().is_some_and(|is_enabled| !is_enabled)
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
            .map(|v| v.into_inner())
            .map(UefiDevicePath::from_str)
            .transpose()
            .map_err(|err| Error::InvalidValue(format!("UefiDevicePath: {err}")))?;

        let iface = EthernetInterface {
            description: iface.description().map(|d| d.to_string()),
            id: Some(iface.id().to_string()),
            interface_enabled: iface.interface_enabled(),
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
            return Err(Error::BmcNotProvided("oob interface for dpu"));
        }
    }

    Ok(eth_ifs)
}

fn nv_get_oob_interface<B: Bmc>(
    boot_options: &[nv_redfish::computer_system::BootOption<B>],
) -> Result<Option<EthernetInterface>, Error<B>> {
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
            if let Some(captures) = mac_pattern.captures(uefi_device_path) {
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
                        Error::InvalidValue(format!(
                            "MAC address not valid: {mac_addr_builder} (err: {e})"
                        ))
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

async fn nv_fetch_service<B: Bmc>(root: &ServiceRoot<B>) -> Result<Vec<Service>, Error<B>> {
    let fw_inventory = Service {
        id: "FirmwareInventory".to_string(),
        inventories: root
            .update_service()
            .await
            .map_err(Error::nv_redfish("update service"))?
            .ok_or_else(Error::bmc_not_provided("update service"))?
            .firmware_inventories()
            .await
            .map_err(Error::nv_redfish("update service firmware inventories"))?
            .into_iter()
            .flatten()
            .map(|inventory| Inventory {
                id: inventory.id().to_string(),
                description: inventory.description().map(|v| v.to_string()),
                version: match (
                    root.vendor().map(|v| v.into_inner()),
                    root.product().map(|v| v.into_inner()),
                ) {
                    (Some("Lenovo"), _) => {
                        inventory.version().map(|v| {
                            // Original comment from libredfish:
                            //
                            // Lenovo prepends the last two characters of
                            // their "Build/Vendor" ID and a dash to most
                            // of the versions.  This confuses things, so
                            // trim off anything that's before a dash.
                            v.into_inner()
                                .split('-')
                                .next_back()
                                .unwrap_or("")
                                .to_string()
                        })
                    }
                    (Some("WIWYNN"), _) | (Some("Nvidia"), Some("GB200 NVL")) => {
                        inventory.version().map(|v| {
                            // Original comment from libredfish:
                            //
                            // BMC firmware gets prepended with "GB200Nvl-", (L, not 1!) so trim that off when we see it.
                            let x = v.into_inner();
                            x.strip_prefix("GB200Nvl-").unwrap_or(x).to_string()
                        })
                    }
                    _ => inventory.version().map(|v| v.to_string()),
                },
                release_date: inventory.release_date().map(|v| v.into_inner().to_string()),
            })
            .collect(),
    };
    Ok(vec![fw_inventory])
}

async fn nv_fetch_chassis<B: Bmc>(members: &Vec<NvChassis<B>>) -> Result<Vec<Chassis>, Error<B>> {
    let mut chassis: Vec<Chassis> = Vec::new();
    for m in members {
        let network_adapters = match m.network_adapters().await {
            Ok(Some(network_adapters)) => network_adapters,
            Ok(None) => {
                vec![]
            }
            Err(err) => {
                return Err(Error::NvRedfish {
                    context: "chassis network adapters",
                    err,
                });
            }
        };

        let network_adapters: Vec<_> = network_adapters
            .into_iter()
            .map(|adapter| {
                let hw_id = adapter.hardware_id();
                NetworkAdapter {
                    id: adapter.id().to_string(),
                    manufacturer: hw_id.manufacturer.map(|v| v.to_string()),
                    model: hw_id.model.map(|v| v.to_string()),
                    part_number: hw_id.part_number.map(|v| v.to_string()),
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
        let chassis_id = m.id();
        let hw_id = m.hardware_id().cloned();
        // For GB200s, use the Chassis_0 assembly serial number to match Nautobot.
        let serial_number = if *chassis_id.inner() == "Chassis_0" {
            match m.assembly().await {
                Ok(Some(assembly)) => {
                    let assembly_data = assembly
                        .assemblies()
                        .await
                        .map_err(Error::nv_redfish("chassis assemblies"))?;
                    assembly_data
                        .iter()
                        .find(|asm| asm.hardware_id().model == Some(Model::new("GB200 NVL")))
                        .and_then(|asm| asm.hardware_id().serial_number)
                        .map(|v| v.to_string())
                }
                Ok(None) => None,
                Err(err) => {
                    return Err(Error::NvRedfish {
                        context: "chassis assembly",
                        err,
                    });
                }
            }
        } else {
            None
        }
        .or(hw_id.serial_number.map(|v| v.into_inner()));

        let nvidia_oem = m.oem_nvidia_baseboard_cbc().ok().and_then(identity);
        chassis.push(Chassis {
            id: chassis_id.to_string(),
            manufacturer: hw_id.manufacturer.map(|v| v.to_string()),
            model: hw_id.model.map(|v| v.into_inner()),
            part_number: hw_id.part_number.map(|v| v.to_string()),
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

async fn nv_fetch_pcie_devices<B: Bmc>(
    vendor: Option<Vendor<&str>>,
    system_id: ResourceIdRef<'_>,
    chassis: &[NvChassis<B>],
) -> Result<Vec<PCIeDevice>, Error<B>> {
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
            .map_err(Error::nv_redfish("chassis pcie devices"))?
            .ok_or_else(Error::bmc_not_provided("chassis pcie devices"))?
            .members()
            .await
            .map_err(Error::nv_redfish("chassis pcie devices members"))?;
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
                description: dev.description().map(|v| v.to_string()),
                firmware_version: dev.firmware_version().map(|v| v.to_string()),
                id: Some(dev.id().to_string()),
                manufacturer: hw_id.manufacturer.map(|v| v.to_string()),
                // TODO: In old model it is dev.gpu_vendor, but it is
                // not standard. It can be taken from
                // .Oem.Supermicro.GPUDevice.GPUVendor for Supermicro
                // but it was never implemented.
                gpu_vendor: None,
                name: Some(dev.name().to_string()),
                part_number: hw_id.part_number.map(|v| v.to_string()),
                // Trim of serial_number is added because serial
                // number of DPU contains trailing spaces... Probably,
                // it should be code specific for DPU...
                serial_number: hw_id.serial_number.map(|v| {
                    if vendor == Some(Vendor::new("HPE")) {
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

fn nv_dpu_mode<B: Bmc>(
    system: &nv_redfish::computer_system::ComputerSystem<B>,
    bios: &nv_redfish::computer_system::Bios<B>,
    bf_ncs: &nv_redfish::oem::nvidia::bluefield::NvidiaComputerSystem<B>,
) -> Option<NicMode> {
    let hw_id = system.hardware_id();
    let manufacturer = hw_id.manufacturer.map(|v| v.into_inner());
    let model = hw_id.model.map(|v| v.into_inner());
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
                        attr.str_value().and_then(|v| match v {
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

fn nv_is_infinite_boot_enabled<B: Bmc>(
    system: &nv_redfish::computer_system::ComputerSystem<B>,
    root: &nv_redfish::ServiceRoot<B>,
    bios: &nv_redfish::computer_system::Bios<B>,
) -> Option<bool> {
    if let Some(vendor) = root.vendor()
        && vendor.into_inner() == "AMI"
        && system.id().into_inner() == "DGX"
    {
        let infinite_boot = bios.attribute("NvidiaInfiniteboot");
        return infinite_boot
            .as_ref()
            .and_then(|v| v.str_value())
            .map(|v| v == "Enable");
    }
    let hw_id = system.hardware_id();
    let (Some(manufacturer), Some(model)) = (hw_id.manufacturer, hw_id.model) else {
        let (Some(vendor), Some(product)) = (root.vendor(), root.product()) else {
            return None;
        };
        return match (vendor.into_inner(), product.into_inner()) {
            ("NVIDIA", "GB200 NVL") => bios
                .attribute("EmbeddedUefiShell")
                .and_then(|attr| attr.str_value().map(|v| v == "Disabled")),
            _ => None,
        };
    };
    match manufacturer.into_inner() {
        "Dell Inc." => bios
            .attribute("BootSeqRetry")
            .and_then(|attr| attr.str_value().map(|v| v == "Enabled")),
        "WIWYNN" => match model.into_inner() {
            "GB200 NVL" => bios
                .attribute("EmbeddedUefiShell")
                .and_then(|attr| attr.str_value().map(|v| v == "Disabled")),
            _ => None,
        },
        "Lenovo" => bios
            .attribute("BootModes_InfiniteBootRetry")
            .and_then(|attr| attr.str_value().map(|v| v == "Enabled")),
        _ => None,
    }
}

fn nv_is_switch<B: Bmc>(members: &[NvChassis<B>]) -> bool {
    members
        .iter()
        .any(|m| m.id().into_inner() == "MGX_NVSwitch_0")
}

fn nv_is_powershelf<B: Bmc>(members: &[NvChassis<B>]) -> bool {
    members.iter().any(|m| m.id().into_inner() == "powershelf")
}

async fn nv_fetch_lockdown_status<B: Bmc>(
    root: &nv_redfish::ServiceRoot<B>,
    bios: &nv_redfish::computer_system::Bios<B>,
    manager: &nv_redfish::manager::Manager<B>,
    manager_eths: &[NvEthernetInterface<B>],
    system: &nv_redfish::computer_system::ComputerSystem<B>,
) -> Result<Option<LockdownStatus>, Error<B>> {
    let oem_id = root.oem_id().map(|v| v.into_inner());
    match (root.vendor().map(|v| v.into_inner()), oem_id) {
        (Some("AMI"), _) => {
            if system.id().into_inner() == "DGX" && manager.id().into_inner() == "BMC" {
                // Viking:
                let kcs_intreface = bios.attribute("KcsInterfaceDisable");
                let redfish_enable = bios.attribute("RedfishEnable");
                let kcs_intreface = kcs_intreface.as_ref().and_then(|attr| attr.str_value());
                let redfish_enable = redfish_enable.as_ref().and_then(|attr| attr.str_value());
                let message = [
                    ("ipmi_kcs_disable", &kcs_intreface),
                    ("redfish_enable", &redfish_enable),
                ]
                .into_iter()
                .filter_map(|(k, v)| v.map(|v| format!("{k}={v}")))
                .join(", ")
                    + ".";
                let status = match (kcs_intreface, redfish_enable) {
                    (None, None) => InternalLockdownStatus::Disabled,
                    (Some("Deny All"), Some(_)) => InternalLockdownStatus::Enabled,
                    (Some("Allow All"), Some("Enabled")) => InternalLockdownStatus::Disabled,
                    (_, _) => InternalLockdownStatus::Partial,
                };
                Ok(Some(LockdownStatus { status, message }))
            } else {
                let kcsacp = bios.attribute("KCSACP");
                let usb000 = bios.attribute("USB000");
                let hi_enabled = manager
                    .host_interfaces()
                    .await
                    .map_err(Error::nv_redfish("host interfaces"))?
                    .ok_or_else(Error::bmc_not_provided("host interfaces"))?
                    .members()
                    .await
                    .map_err(Error::nv_redfish("host interfaces members"))?
                    .iter()
                    .any(|i| i.interface_enabled().is_none_or(identity));
                let kcsacp = kcsacp.as_ref().and_then(|v| v.str_value());
                let usb000 = usb000.as_ref().and_then(|v| v.str_value());
                let message = format!(
                    "kcsacp: {kcsacp:?}; usb000: {usb000:?}; host_interfaces: {hi_enabled}"
                );
                match (kcsacp, usb000, hi_enabled) {
                    (Some("Deny All"), Some("Disabled"), false) => {
                        Ok(InternalLockdownStatus::Enabled)
                    }
                    (Some("Allow All"), Some("Enabled"), true) => {
                        Ok(InternalLockdownStatus::Disabled)
                    }
                    (Some(_), Some(_), _) => Ok(InternalLockdownStatus::Partial),
                    _ => Err(Error::InvalidValue(format!(
                        "AMI lockdown status: {message}"
                    ))),
                }
                .map(|status| Some(LockdownStatus { status, message }))
            }
        }
        (Some("Dell"), _) => {
            let attributes = manager
                .oem_dell_attributes()
                .await
                .map_err(Error::nv_redfish("Dell OEM Attributes"))?
                .ok_or_else(Error::bmc_not_provided("Dell OEM Attributes"))?;
            let system_lockdown = attributes.attribute("Lockdown.1.SystemLockdown");
            let racadm = attributes.attribute("Racadm.1.Enable");
            let system_lockdown = system_lockdown.as_ref().and_then(|v| v.str_value());
            let racadm = racadm.as_ref().and_then(|v| v.str_value());
            let message = format!("system_lockdown: {system_lockdown:?}; racadm: {racadm:?}");
            match (system_lockdown, racadm) {
                (Some("Enabled"), Some("Disabled")) => Ok(InternalLockdownStatus::Enabled),
                (Some("Disabled"), Some("Enabled")) => Ok(InternalLockdownStatus::Disabled),
                (Some(_), Some(_)) => Ok(InternalLockdownStatus::Partial),
                _ => Err(Error::InvalidValue(format!(
                    "Dell lockdown status: {message}"
                ))),
            }
            .map(|status| Some(LockdownStatus { status, message }))
        }
        (Some("Lenovo"), _) => {
            let oem_lenovo_manager = manager
                .oem_lenovo()
                .map_err(Error::nv_redfish("Lenovo manager OEM"))?
                .ok_or_else(Error::bmc_not_provided("Lenovo manager OEM"))?;
            let kcs_enabled = oem_lenovo_manager
                .kcs_enabled()
                .ok_or(Error::BmcNotProvided("Lenovo manager: KCS state"))?;
            let firmware_rollback = oem_lenovo_manager
                .security()
                .await
                .map_err(Error::nv_redfish("Lenovo security service"))?
                .ok_or_else(Error::bmc_not_provided("Lenovo security service"))?
                .fw_rollback()
                .ok_or(Error::BmcNotProvided(
                    "Lenovo security service: firmware rollback status",
                ))?;
            let eth_usb = manager_eths
                .iter()
                .find(|iface| *iface.id().inner() == "ToHost")
                .and_then(|iface| iface.interface_enabled())
                .ok_or(Error::BmcNotProvided(
                    "Lenovo manager ethernet interfaces: enabled property",
                ))?;

            let oem_lenovo_system = system
                .oem_lenovo()
                .map_err(Error::nv_redfish("Lenovo computer system"))?
                .ok_or_else(Error::bmc_not_provided("Lenovo computer system"))?;

            let fp_mode = oem_lenovo_system
                .front_panel_mode()
                .ok_or(Error::BmcNotProvided(
                    "Lenovo computer system: front panal mode",
                ))?;
            let port_switching_to =
                oem_lenovo_system
                    .port_switching_to()
                    .ok_or(Error::BmcNotProvided(
                        "Lenovo computer system: port switching to",
                    ))?;

            let message = format!(
                "kcs={}, firmware_rollback={firmware_rollback:?}, ethernet_over_usb={eth_usb:?}, front_panel_usb={fp_mode:?}/{port_switching_to:?}",
                kcs_enabled == KcsState::Enabled
            );

            match (
                kcs_enabled,
                firmware_rollback,
                eth_usb,
                fp_mode,
                port_switching_to,
            ) {
                (KcsState::Disabled, FwRollbackState::Disabled, false, FpMode::Server, _) => {
                    Ok(InternalLockdownStatus::Enabled)
                }
                (
                    KcsState::Enabled,
                    FwRollbackState::Enabled,
                    true,
                    FpMode::Shared,
                    PortSwitchingTo::Server,
                ) => Ok(InternalLockdownStatus::Disabled),
                (_, _, _, _, _) => Ok(InternalLockdownStatus::Partial),
            }
            .map(|status| Some(LockdownStatus { status, message }))
        }
        (Some("Supermicro"), _) | (None, Some("Supermicro")) => {
            let hi_enabled = manager
                .host_interfaces()
                .await
                .map_err(Error::nv_redfish("host interfaces"))?
                .ok_or_else(Error::bmc_not_provided("host interfaces"))?
                .members()
                .await
                .map_err(Error::nv_redfish("host interfaces members"))?
                .iter()
                .any(|i| i.interface_enabled().is_none_or(identity));
            let supermicro_oem = manager
                .oem_supermicro()
                .map_err(Error::nv_redfish("Supermicro manager OEM"))?
                .ok_or_else(Error::bmc_not_provided("Supermicro manager OEM"))?;
            let kcs_privilege = supermicro_oem
                .kcs_interface()
                .await
                .map_err(Error::nv_redfish("Supermicro KCS Interface"))?
                .and_then(|iface| iface.privilege());
            let is_syslockdown = supermicro_oem
                .sys_lockdown()
                .await
                .map_err(Error::nv_redfish("Supermicro SysLockdown OEM"))?
                .and_then(|lck| lck.sys_lockdown_enabled())
                .ok_or_else(Error::bmc_not_provided("Supermicro lockdown status"))?;

            let message = format!(
                "SysLockdownEnabled={is_syslockdown}, kcs_privilege={kcs_privilege:#?}, host_interface_enabled={hi_enabled}"
            );
            // Grace-Grace SMCs (ARS-121L-DNR):
            // 1. Need host_interface enabled even with lockdown
            // 2. Doesn't provide KCSInterface
            let model = system.hardware_id().model.map(|v| v.into_inner());

            match (hi_enabled, model, kcs_privilege, is_syslockdown) {
                (true, Some("ARS-121L-DNR"), None, true)
                | (false, _, Some(SupermicroPrivilege::Callback), true) => {
                    Ok(InternalLockdownStatus::Enabled)
                }
                (true, Some("ARS-121L-DNR"), None, false)
                | (true, _, Some(SupermicroPrivilege::Administrator), false) => {
                    Ok(InternalLockdownStatus::Disabled)
                }
                _ => Ok(InternalLockdownStatus::Partial),
            }
            .map(|status| Some(LockdownStatus { status, message }))
        }
        (Some("HPE"), _) => {
            let usb_boot = bios.attribute("UsbBoot");
            let usb_boot = usb_boot.as_ref().and_then(|v| v.str_value());
            let virtual_nic_enabled = manager
                .oem_hpe()
                .map_err(Error::nv_redfish("HPE manager OEM"))?
                .and_then(|oem| oem.virtual_nic_enabled())
                .ok_or_else(Error::bmc_not_provided("HPE manager virtual NIC state"))?;
            let message = format!(
                "usb_boot={}, virtual_nic_enabled={}",
                usb_boot.unwrap_or("Unknown"),
                virtual_nic_enabled
            );
            // TODO KCS
            let status = match (usb_boot, virtual_nic_enabled) {
                (Some("Disabled"), false) => InternalLockdownStatus::Enabled,
                (Some("Enabled"), true) => InternalLockdownStatus::Disabled,
                (_, _) => InternalLockdownStatus::Partial,
            };
            Ok(Some(LockdownStatus { message, status }))
        }
        _ => Ok(None),
    }
}
