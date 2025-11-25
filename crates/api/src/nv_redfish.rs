/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use forge_secrets::credentials::Credentials;
use nv_redfish::bmc_http::reqwest::{
    Client as NvRedfishReqwestClient, ClientParams as NvRedfishReqwestClientParams,
};
use nv_redfish::bmc_http::{BmcCredentials, CacheSettings, HttpBmc};
use reqwest::header::HeaderMap;
use utils::HostPortPair;

pub type NvRedfishBmc = HttpBmc<NvRedfishReqwestClient>;

pub struct NvRedfishClientPool {
    proxy_address: Arc<ArcSwap<Option<HostPortPair>>>,
    cache: Arc<Mutex<HashMap<PoolKey, Arc<NvRedfishBmc>>>>,
}

#[derive(Hash, PartialEq, Eq)]
struct PoolKey {
    proxy_address: Arc<Option<HostPortPair>>,
    bmc_address: SocketAddr,
    credentials: Credentials,
}

impl NvRedfishClientPool {
    pub fn new(proxy_address: Arc<ArcSwap<Option<HostPortPair>>>) -> Self {
        Self {
            proxy_address,
            cache: Default::default(),
        }
    }

    pub fn nv_redfish_bmc(
        &self,
        bmc_address: SocketAddr,
        credentials: Credentials,
    ) -> Result<Arc<NvRedfishBmc>, reqwest::Error> {
        let proxy_address = self.proxy_address.load();
        let key = PoolKey {
            proxy_address: proxy_address.clone(),
            bmc_address,
            credentials,
        };
        let mut cache = self
            .cache
            .lock()
            .expect("nv-redish client cache mutex poisoned");
        cache
            .get(&key)
            .map(|bmc| Ok(bmc.clone()))
            .unwrap_or_else(|| {
                self.create_nv_redfish_bmc(
                    key.proxy_address.clone(),
                    key.bmc_address,
                    key.credentials.clone(),
                )
                .inspect(|bmc| {
                    cache.insert(key, bmc.clone());
                })
            })
    }

    pub fn create_nv_redfish_bmc(
        &self,
        proxy_address: Arc<Option<HostPortPair>>,
        bmc_address: SocketAddr,
        Credentials::UsernamePassword { username, password }: Credentials,
    ) -> Result<Arc<NvRedfishBmc>, reqwest::Error> {
        let bmc_url = match proxy_address.as_ref() {
            // No override
            None => format!("https://{bmc_address}"),
            Some(HostPortPair::HostAndPort(h, p)) => format!("https://{h}:{p}"),
            Some(HostPortPair::HostOnly(h)) => format!("https://{h}:{}", bmc_address.port()),
            Some(HostPortPair::PortOnly(p)) => format!("https://{}:{p}", bmc_address.ip()),
        }
        .parse::<url::Url>()
        .expect("Generated URI is expected to be valid");

        let headers = if proxy_address.is_some() {
            let mut headers = HeaderMap::new();
            headers.insert(
                reqwest::header::FORWARDED,
                format!("host={}", bmc_address.ip())
                    .parse()
                    .expect("Generated header is expected to be valid"),
            );
            headers
        } else {
            HeaderMap::new()
        };

        let client = NvRedfishReqwestClient::with_params(
            NvRedfishReqwestClientParams::new().accept_invalid_certs(true),
        )?;
        Ok(Arc::new(NvRedfishBmc::with_custom_headers(
            client,
            bmc_url,
            BmcCredentials::new(username, password),
            CacheSettings::with_capacity(10),
            headers,
        )))
    }
}
