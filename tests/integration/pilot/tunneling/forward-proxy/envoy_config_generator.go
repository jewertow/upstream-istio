//go:build integ
// +build integ

// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package forward_proxy

import (
	envoyv3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	envoy_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_cluster_dynamic_forward_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	envoy_common_dynamic_forward_proxy "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	dynamic_forward_proxyv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	http_conn "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	caresv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/network/dns_resolver/cares/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"istio.io/istio/pilot/pkg/networking"
	"istio.io/istio/pkg/util/protomarshal"
)

func GenerateForwardProxyBootstrapConfig(httpVersion string, tlsEnabled bool) (string, error) {
	hcm := createHttpConnectionManager(httpVersion)
	bootstrap := &envoyv3.Bootstrap{
		Admin: &envoyv3.Admin{
			Address: createSocketAddress("127.0.0.1", 9902),
		},
		StaticResources: &envoyv3.Bootstrap_StaticResources{
			Listeners: []*envoy_listener.Listener{
				{
					Name:    "http_forward_proxy",
					Address: createSocketAddress("0.0.0.0", 3128),
					FilterChains: []*envoy_listener.FilterChain{
						{
							Filters: []*envoy_listener.Filter{
								{
									Name: "envoy.filters.network.http_connection_manager",
									ConfigType: &envoy_listener.Filter_TypedConfig{
										TypedConfig: networking.MessageToAny(hcm),
									},
								},
							},
							TransportSocket: createTransportSocket(tlsEnabled),
						},
					},
					StatPrefix: "http_forward_proxy",
				},
			},
			Clusters: []*envoy_cluster.Cluster{
				{
					Name:     "dynamic_forward_proxy_cluster",
					LbPolicy: envoy_cluster.Cluster_CLUSTER_PROVIDED,
					ClusterDiscoveryType: &envoy_cluster.Cluster_ClusterType{
						ClusterType: &envoy_cluster.Cluster_CustomClusterType{
							Name: "envoy.clusters.dynamic_forward_proxy",
							TypedConfig: networking.MessageToAny(&envoy_cluster_dynamic_forward_proxy.ClusterConfig{
								DnsCacheConfig: dynamicForwardProxyCacheConfig,
							}),
						},
					},
				},
			},
		},
	}
	return protomarshal.ToYAML(bootstrap)
}

var dynamicForwardProxyCacheConfig = &envoy_common_dynamic_forward_proxy.DnsCacheConfig{
	Name:            "dynamic_forward_proxy_cache_config",
	DnsLookupFamily: envoy_cluster.Cluster_V4_ONLY,
	TypedDnsResolverConfig: &envoy_core.TypedExtensionConfig{
		Name: "envoy.network.dns_resolver.cares",
		TypedConfig: networking.MessageToAny(&caresv3.CaresDnsResolverConfig{
			Resolvers: []*envoy_core.Address{
				createSocketAddress("8.8.8.8", 53),
			},
		}),
	},
}

func createHttpConnectionManager(httpVersion string) *http_conn.HttpConnectionManager {
	hcm := &http_conn.HttpConnectionManager{
		HttpFilters: []*http_conn.HttpFilter{
			{
				Name: "envoy.filters.http.dynamic_forward_proxy",
				ConfigType: &http_conn.HttpFilter_TypedConfig{
					TypedConfig: networking.MessageToAny(&dynamic_forward_proxyv3.FilterConfig{
						DnsCacheConfig: dynamicForwardProxyCacheConfig,
					}),
				},
			},
			{
				Name: "envoy.filters.http.router",
			},
		},
		RouteSpecifier: &http_conn.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoy_route.RouteConfiguration{
				Name: "default",
				VirtualHosts: []*envoy_route.VirtualHost{
					{
						Name:    "http_forward_proxy",
						Domains: []string{"*"},
						Routes: []*envoy_route.Route{
							{
								Action: &envoy_route.Route_Route{
									Route: &envoy_route.RouteAction{
										ClusterSpecifier: &envoy_route.RouteAction_Cluster{
											Cluster: "dynamic_forward_proxy_cluster",
										},
										UpgradeConfigs: []*envoy_route.RouteAction_UpgradeConfig{
											{
												UpgradeType:   "CONNECT",
												ConnectConfig: &envoy_route.RouteAction_UpgradeConfig_ConnectConfig{},
											},
										},
									},
								},
								Match: &envoy_route.RouteMatch{
									PathSpecifier: &envoy_route.RouteMatch_ConnectMatcher_{},
								},
							},
						},
					},
				},
			},
		},
		StatPrefix: "http_forward_proxy",
	}
	if httpVersion == "HTTP1" {
		hcm.CodecType = http_conn.HttpConnectionManager_HTTP1
		hcm.HttpProtocolOptions = &envoy_core.Http1ProtocolOptions{}
	}
	if httpVersion == "HTTP2" {
		hcm.CodecType = http_conn.HttpConnectionManager_HTTP2
		hcm.Http2ProtocolOptions = &envoy_core.Http2ProtocolOptions{
			AllowConnect: true,
		}
	}
	return hcm
}

func createTransportSocket(tlsEnabled bool) *envoy_core.TransportSocket {
	if !tlsEnabled {
		return nil
	}
	return &envoy_core.TransportSocket{
		Name: "envoy.transport_sockets.tls",
		ConfigType: &envoy_core.TransportSocket_TypedConfig{
			TypedConfig: networking.MessageToAny(&tls.DownstreamTlsContext{
				CommonTlsContext: &tls.CommonTlsContext{
					TlsCertificates: []*tls.TlsCertificate{
						{
							CertificateChain: &envoy_core.DataSource{
								Specifier: &envoy_core.DataSource_Filename{
									Filename: "/etc/pki/tls/certs/external-forward-proxy.testdomain.crt",
								},
							},
							PrivateKey: &envoy_core.DataSource{
								Specifier: &envoy_core.DataSource_Filename{
									Filename: "/etc/pki/tls/private/external-forward-proxy.testdomain.key",
								},
							},
						},
					},
				},
			}),
		},
	}
}

func createSocketAddress(addr string, port uint32) *envoy_core.Address {
	return &envoy_core.Address{
		Address: &envoy_core.Address_SocketAddress{
			SocketAddress: &envoy_core.SocketAddress{
				Address: addr,
				PortSpecifier: &envoy_core.SocketAddress_PortValue{
					PortValue: port,
				},
			},
		},
	}
}
