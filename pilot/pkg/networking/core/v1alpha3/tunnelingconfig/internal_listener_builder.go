package tunnelingconfig

import (
	"fmt"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	tcp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	networking "istio.io/api/networking/v1alpha3"
	"istio.io/istio/pilot/pkg/util/protoconv"
	"net"
	"strconv"
)

type InternalTunnelingListenerSpec struct {
	TargetHost          string
	TargetPort          uint32
	TunnelProxyHostname string
	Protocol            string
}

func internalListenerName(tunnelSettings *networking.TrafficPolicy_TunnelSettings) string {
	return fmt.Sprintf("tunneling-proxy-%s-%d", tunnelSettings.TargetHost, tunnelSettings.TargetPort)
}

func internalClusterName(tunnelSettings *networking.TrafficPolicy_TunnelSettings) string {
	if isAutoSNI(tunnelSettings) {
		// TODO
	}
	return fmt.Sprintf("outbound|internal|%s|%s", tunnelSettings.TargetHost, internalListenerName(tunnelSettings))
}

func tunnelProxyClusterName(hostname, subset string, port uint32) string {
	return fmt.Sprintf("outbound|%d|%s|%s", port, subset, hostname)
}

func isAutoSNI(tunnelSettings *networking.TrafficPolicy_TunnelSettings) bool {
	return false
}

func BuildInternalListener(tunnelProxyHostname string, tunnelSettings *networking.TrafficPolicy_TunnelSettings) *listener.Listener {
	if isAutoSNI(tunnelSettings) {
		// TODO:
	}
	tcpProxy := &tcp.TcpProxy{
		StatPrefix: internalListenerName(tunnelSettings),
		// TODO(jewertow): handle port and subset
		ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: tunnelProxyClusterName(tunnelProxyHostname, "", 3128)},
		TunnelingConfig: &tcp.TcpProxy_TunnelingConfig{
			Hostname: net.JoinHostPort(tunnelSettings.TargetHost, strconv.Itoa(int(tunnelSettings.TargetPort))),
			UsePost:  tunnelSettings.Protocol == "POST",
		},
	}

	return &listener.Listener{
		Name: internalListenerName(tunnelSettings),
		ListenerSpecifier: &listener.Listener_InternalListener{
			InternalListener: &listener.Listener_InternalListenerConfig{},
		},
		FilterChains: []*listener.FilterChain{
			{
				// TODO: apply if AutoSNI == true
				//FilterChainMatch: &listener.FilterChainMatch{
				//	TransportProtocol: "tls",
				//},
				Filters: []*listener.Filter{
					{
						Name:       wellknown.TCPProxy,
						ConfigType: &listener.Filter_TypedConfig{TypedConfig: protoconv.MessageToAny(tcpProxy)},
					},
				},
			},
		},
		TrafficDirection: core.TrafficDirection_OUTBOUND,
	}
	//if isAutoSNI(tunnelSettings) {
	//	internalTunnelingListener.ListenerFilters = append(internalTunnelingListener.ListenerFilters, &listener.ListenerFilter{
	//		Name:       wellknown.TLSInspector,
	//		ConfigType: xdsfilters.TLSInspector.ConfigType,
	//	})
	//}
}

func ChangeToInternalTunnelingCluster(c *cluster.Cluster, tunnelSettings *networking.TrafficPolicy_TunnelSettings) {
	c.Name = internalClusterName(tunnelSettings)
	c.LoadAssignment.ClusterName = internalClusterName(tunnelSettings)
	c.LoadAssignment.Endpoints = []*endpoint.LocalityLbEndpoints{
		{
			LbEndpoints: []*endpoint.LbEndpoint{
				{
					HostIdentifier: &endpoint.LbEndpoint_Endpoint{
						Endpoint: &endpoint.Endpoint{
							Address: &core.Address{
								Address: &core.Address_EnvoyInternalAddress{
									EnvoyInternalAddress: &core.EnvoyInternalAddress{
										AddressNameSpecifier: &core.EnvoyInternalAddress_ServerListenerName{
											ServerListenerName: internalListenerName(tunnelSettings),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}
