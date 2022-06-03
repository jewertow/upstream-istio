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

package pilot

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"istio.io/istio/pkg/config/protocol"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/echo"
	"istio.io/istio/pkg/test/framework/components/echo/common/ports"
	"istio.io/istio/pkg/test/framework/components/istioctl"
	kubetest "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
	forward_proxy "istio.io/istio/tests/integration/pilot/tunneling/forward-proxy"
)

type tunnelingTestCase struct {
	// configDir is a directory with Istio configuration files for a particular test case
	configDir string
}

type testRequestSpec struct {
	protocol protocol.Instance
	portName string
}

var forwardProxyConfigurations = []forward_proxy.ListenerSettings{
	{
		Port:        3128,
		HTTPVersion: http1,
		TLSEnabled:  false,
	},
	//{
	//	Port:        4128,
	//	HTTPVersion: http1,
	//	TLSEnabled:  true,
	//},
	{
		Port:        5128,
		HTTPVersion: http2,
		TLSEnabled:  false,
	},
	//{
	//	Port:        6128,
	//	HTTPVersion: http2,
	//	TLSEnabled:  true,
	//},
}

var requestsSpec = []testRequestSpec{
	{
		protocol: protocol.HTTP,
		portName: ports.TCPForHTTP,
	},
	{
		protocol: protocol.HTTPS,
		portName: ports.HTTPS,
	},
}

var testCases = []tunnelingTestCase{
	{
		configDir: "sidecar",
	},
	{
		configDir: "gateway/tcp",
	},
	{
		configDir: "gateway/tls/istio-mutual",
	},
	{
		configDir: "gateway/tls/passthrough",
	},
}

const (
	http1 = "HTTP1"
	http2 = "HTTP2"
)

func TestTunnelingOutboundTraffic(t *testing.T) {
	framework.
		NewTest(t).
		Features("traffic.tunneling").
		Run(func(ctx framework.TestContext) {
			meshNs := apps.A.NamespaceName()
			externalNs := apps.External.Namespace.Name()

			applyForwardProxyConfigMap(ctx, externalNs)
			ctx.ConfigIstio().File(externalNs, "tunneling/forward-proxy/deployment.yaml").ApplyOrFail(ctx)
			applyForwardProxyService(ctx, externalNs, forwardProxyConfigurations)
			waitForPodsReadyOrFail(ctx, externalNs, "external-forward-proxy")
			externalForwardProxyIP := getPodIP(ctx, externalNs, "external-forward-proxy")

			for _, proxySettings := range forwardProxyConfigurations {
				templateParams := map[string]interface{}{
					"forwardProxyPort":  proxySettings.Port,
					"tlsEnabled":        proxySettings.TLSEnabled,
					"externalNamespace": externalNs,
					"httpPort":          apps.External.All.PortForName(ports.TCPForHTTP).ServicePort,
					"httpsPort":         apps.External.All.PortForName(ports.HTTPS).ServicePort,
				}
				ctx.ConfigIstio().EvalFile(externalNs, templateParams, "tunneling/forward-proxy/destination-rule.tmpl.yaml").ApplyOrFail(ctx)

				for _, tc := range testCases {
					for _, res := range listFilesInDirectory(ctx, tc.configDir) {
						ctx.ConfigIstio().EvalFile(meshNs, templateParams, "tunneling/"+res).ApplyOrFail(ctx)
					}

					for _, spec := range requestsSpec {
						testName := fmt.Sprintf("%s/%s/%s/%s-request",
							proxySettings.HTTPVersion, proxySettings.TLSEnabledStr(), tc.configDir, spec.protocol)
						ctx.NewSubTest(testName).Run(func(ctx framework.TestContext) {
							// requests will fail until istio-proxy gets the Envoy configuration from istiod, so retries are necessary
							retry.UntilSuccessOrFail(ctx, func() error {
								client := apps.A[0]
								target := apps.External.All[0]
								if err := testConnectivity(client, target, spec.protocol, spec.portName, testName); err != nil {
									return err
								}
								if err := verifyThatRequestWasTunneled(target, externalForwardProxyIP, testName); err != nil {
									return err
								}
								return nil
							}, retry.Timeout(10*time.Second))
						})
					}

					for _, res := range listFilesInDirectory(ctx, tc.configDir) {
						ctx.ConfigIstio().EvalFile(meshNs, templateParams, "tunneling/"+res).DeleteOrFail(ctx)
					}

					// Make sure that configuration changes were pushed to istio-proxies.
					// Otherwise, test results could be false-positive,
					// because subsequent test cases could work thanks to previous configurations.
					waitUntilTunnelingConfigurationIsRemovedOrFail(ctx, meshNs)
				}

				ctx.ConfigIstio().EvalFile(externalNs, templateParams, "tunneling/forward-proxy/destination-rule.tmpl.yaml").DeleteOrFail(ctx)
			}
		})
}

func testConnectivity(from, to echo.Instance, p protocol.Instance, portName, testName string) error {
	res, err := from.Call(echo.CallOptions{
		Address: apps.External.All[0].ClusterLocalFQDN(),
		Port: echo.Port{
			Protocol:    p,
			ServicePort: to.PortForName(portName).ServicePort,
		},
		HTTP: echo.HTTP{
			Path: "/" + testName,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to request to external service: %s", err)
	}
	if res.Responses[0].Code != "200" {
		return fmt.Errorf("expected to get 200 status code, got: %s", res.Responses[0].Code)
	}
	return nil
}

func verifyThatRequestWasTunneled(target echo.Instance, expectedSourceIP, expectedPath string) error {
	workloads, err := target.Workloads()
	if err != nil {
		return fmt.Errorf("failed to get workloads of %s: %s", target.ServiceName(), err)
	}
	var logs strings.Builder
	for _, w := range workloads {
		workloadLogs, err := w.Logs()
		if err != nil {
			return fmt.Errorf("failed to get logs of workload %s: %s", w.PodName(), err)
		}
		logs.WriteString(workloadLogs)
	}

	expectedLog := fmt.Sprintf("remoteAddr=%s method=GET url=/%s", expectedSourceIP, expectedPath)
	if !strings.Contains(logs.String(), expectedLog) {
		return fmt.Errorf("failed to find expected log: %s in logs of %s", expectedLog, target.ServiceName())
	}
	return nil
}

func applyForwardProxyConfigMap(ctx framework.TestContext, externalNs string) {
	kubeClient := ctx.Clusters().Default().Kube()

	bootstrapYaml, err := forward_proxy.GenerateForwardProxyBootstrapConfig(forwardProxyConfigurations)
	if err != nil {
		ctx.Fatalf("failed to generate bootstrap configuration for external-forward-proxy: %s", err)
	}

	cfgMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: "external-forward-proxy-config",
		},
		Data: map[string]string{
			"envoy.yaml": bootstrapYaml,
		},
	}
	if _, err := kubeClient.CoreV1().ConfigMaps(externalNs).Create(context.TODO(), cfgMap, metav1.CreateOptions{}); err != nil {
		ctx.Fatalf("failed to create config map for external-forward-proxy: %s", err)
	}
}

func applyForwardProxyService(ctx framework.TestContext, externalNs string, configs []forward_proxy.ListenerSettings) {
	kubeClient := ctx.Clusters().Default().Kube()

	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: "external-forward-proxy",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{},
			Selector: map[string]string{
				"app": "external-forward-proxy",
			},
		},
	}
	for _, cfg := range configs {
		svc.Spec.Ports = append(svc.Spec.Ports, corev1.ServicePort{
			Name:       selectPortName(cfg.HTTPVersion),
			Port:       int32(cfg.Port),
			TargetPort: intstr.FromInt(int(cfg.Port)),
			Protocol:   corev1.ProtocolTCP,
		})
	}
	if _, err := kubeClient.CoreV1().Services(externalNs).Create(context.TODO(), svc, metav1.CreateOptions{}); err != nil {
		ctx.Fatalf("failed to create service external-forward-proxy")
	}
}

func listFilesInDirectory(ctx framework.TestContext, dir string) []string {
	files, err := os.ReadDir("tunneling/" + dir)
	if err != nil {
		ctx.Fatalf("failed to read files in directory: %s", err)
	}
	filesList := make([]string, 0, len(files))
	for _, file := range files {
		filesList = append(filesList, fmt.Sprintf("%s/%s", dir, file.Name()))
	}
	return filesList
}

func selectPortName(httpVersion string) string {
	if httpVersion == http1 {
		return "http-connect"
	}
	return "http2-connect"
}

func getPodIP(ctx framework.TestContext, ns, appSelector string) string {
	return getPodStringProperty(ctx, ns, appSelector, func(pod corev1.Pod) string {
		return pod.Status.PodIP
	})
}

func getPodName(ctx framework.TestContext, ns, appSelector string) string {
	return getPodStringProperty(ctx, ns, appSelector, func(pod corev1.Pod) string {
		return pod.Name
	})
}

func getPodStringProperty(ctx framework.TestContext, ns, selector string, getPodProperty func(pod corev1.Pod) string) string {
	var podProperty string
	kubeClient := ctx.Clusters().Default()
	retry.UntilSuccessOrFail(ctx, func() error {
		pods, err := kubeClient.PodsForSelector(context.TODO(), ns, fmt.Sprintf("app=%s", selector))
		if err != nil {
			return fmt.Errorf("failed to get pods for selector app=%s: %v", selector, err)
		}
		if len(pods.Items) == 0 {
			return fmt.Errorf("no pods for selector app=%s", selector)
		}
		if len(pods.Items) > 1 {
			return fmt.Errorf("expected to get only 1 pod for selector app=%s, got: %d", selector, len(pods.Items))
		}
		podProperty = getPodProperty(pods.Items[0])
		return nil
	}, retry.Timeout(30*time.Second))
	return podProperty
}

func waitForPodsReadyOrFail(ctx framework.TestContext, ns, appSelector string) {
	kubeClient := ctx.Clusters().Kube().Default()
	retry.UntilSuccessOrFail(ctx, func() error {
		if _, err := kubetest.CheckPodsAreReady(kubetest.NewPodFetch(kubeClient, ns, "app="+appSelector)); err != nil {
			return fmt.Errorf("pods app=%s are not ready: %v", appSelector, err)
		}
		return nil
	}, retry.Timeout(1*time.Minute), retry.Delay(500*time.Millisecond))
}

func waitUntilTunnelingConfigurationIsRemovedOrFail(ctx framework.TestContext, meshNs string) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		waitForTunnelingRemovedOrFail(ctx, meshNs, "a")
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		waitForTunnelingRemovedOrFail(ctx, "istio-system", "istio-egressgateway")
	}()
	wg.Wait()
}

func waitForTunnelingRemovedOrFail(ctx framework.TestContext, ns, app string) {
	istioCtl := istioctl.NewOrFail(ctx, ctx, istioctl.Config{Cluster: ctx.Clusters().Default()})
	podName := getPodName(ctx, ns, app)
	args := []string{"proxy-config", "listeners", "-n", ns, podName, "-o", "json"}
	retry.UntilSuccessOrFail(ctx, func() error {
		out, _, err := istioCtl.Invoke(args)
		if err != nil {
			return fmt.Errorf("failed to get listeners of %s/%s: %s", app, ns, err)
		}
		if strings.Contains(out, "tunnelingConfig") {
			return fmt.Errorf("tunnelingConfig was not removed from istio-proxy configuration in %s/%s", app, ns)
		}
		return nil
	}, retry.Timeout(10*time.Second))
}
