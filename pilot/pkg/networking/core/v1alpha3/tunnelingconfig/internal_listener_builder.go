package tunnelingconfig

import (
	"fmt"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
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

func getListenerName(tunnelSettings *networking.TrafficPolicy_TunnelSettings) string {
	return fmt.Sprintf("tunneling-proxy-%s-%d", tunnelSettings.TargetHost, tunnelSettings.TargetPort)
}

func getClusterName(tunnelProxyHostname string) string {
	return fmt.Sprintf("outbound|TODO||%s", tunnelProxyHostname)
}

func isAutoSNI(tunnelSettings *networking.TrafficPolicy_TunnelSettings) bool {
	return false
}

func BuildInternalListener(tunnelProxyHostname string, tunnelSettings *networking.TrafficPolicy_TunnelSettings) *listener.Listener {
	if isAutoSNI(tunnelSettings) {
		// TODO:
	}
	tcpProxy := &tcp.TcpProxy{
		StatPrefix:       getListenerName(tunnelSettings),
		ClusterSpecifier: &tcp.TcpProxy_Cluster{Cluster: getClusterName(tunnelProxyHostname)},
		TunnelingConfig: &tcp.TcpProxy_TunnelingConfig{
			Hostname: net.JoinHostPort(tunnelSettings.TargetHost, strconv.Itoa(int(tunnelSettings.TargetPort))),
			UsePost:  tunnelSettings.Protocol == "POST",
		},
	}

	return &listener.Listener{
		Name: getListenerName(tunnelSettings),
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
