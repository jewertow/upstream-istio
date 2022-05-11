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

package tunneling

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/framework/resource"
	kubetest "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
	"istio.io/istio/tests/integration/pilot/common"
)

type tunnelingTestCase struct {
	// name must be unique, because it's used in the requested URL and then it's searched for in the access.log file,
	// so a duplicated name would make test false positive
	name string
	// protocols specifies what types of requests to test; it can contain "http" or "https" values
	protocols []string
	// istioResourcesToApply is a list of files with Istio resources required to apply to test a particular case
	istioResourcesToApply []string
}

func testCases() []tunnelingTestCase {
	return []tunnelingTestCase{
		{
			"gateway/tcp",
			[]string{"http", "https"},
			[]string{
				"gateway/tcp/virtual-service.yaml",
				"gateway/tcp/gateway.yaml",
			},
		},
		{
			"gateway/tls/istio-mutual",
			[]string{"http", "https"},
			[]string{
				"gateway/tls-istio-mutual/mtls.yaml",
				"gateway/tls-istio-mutual/virtual-service.yaml",
				"gateway/tls-istio-mutual/gateway.yaml",
			},
		},
		{
			"gateway/tls/passthrough",
			[]string{"https"},
			[]string{
				"gateway/tls-passthrough/virtual-service.yaml",
				"gateway/tls-passthrough/gateway.yaml",
			},
		},
		{
			"sidecar",
			[]string{"http", "https"},
			[]string{
				"sidecar/virtual-service.yaml",
			},
		},
	}
}

var i istio.Instance

const (
	http1 = "HTTP1"
	http2 = "HTTP2"
)

func TestMain(m *testing.M) {
	framework.
		NewSuite(m).
		Setup(istio.Setup(&i, enableRegistryOnlyMode)).
		Run()
}

func enableRegistryOnlyMode(_ resource.Context, cfg *istio.Config) {
	cfg.ControlPlaneValues = `
meshConfig:
  accessLogFile: /dev/stdout
  outboundTrafficPolicy:
    mode: REGISTRY_ONLY`
}

func TestTunnelingViaHTTP1Proxy(t *testing.T) {
	framework.
		NewTest(t).
		Features("traffic.tunneling.http1_proxy.plain_text").
		Run(func(ctx framework.TestContext) {
			runTunnelingTests(t, ctx, http1, false)
		})
}

func TestTunnelingViaHTTP1ProxyWithTLS(t *testing.T) {
	framework.
		NewTest(t).
		Features("traffic.tunneling.http1_proxy.tls").
		Run(func(ctx framework.TestContext) {
			runTunnelingTests(t, ctx, http1, true)
		})
}

func TestTunnelingViaHTTP2Proxy(t *testing.T) {
	framework.
		NewTest(t).
		Features("traffic.tunneling.http2_proxy.plain_text").
		Run(func(ctx framework.TestContext) {
			runTunnelingTests(t, ctx, http2, false)
		})
}

func TestTunnelingViaHTTP2ProxyWithTLS(t *testing.T) {
	framework.
		NewTest(t).
		Features("traffic.tunneling.http2_proxy.tls").
		Run(func(ctx framework.TestContext) {
			runTunnelingTests(t, ctx, http2, true)
		})
}

func runTunnelingTests(t *testing.T, ctx framework.TestContext, proxyHTTPVersion string, proxyTLSEnabled bool) {
	meshNs := namespace.NewOrFail(t, ctx, namespace.Config{Prefix: "mesh", Inject: true})
	externalNs := namespace.NewOrFail(t, ctx, namespace.Config{Prefix: "external", Inject: false})

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		common.ApplyFileOrFail(ctx, meshNs.Name(), path.Join(env.IstioSrc, "samples/sleep/sleep.yaml"))
		waitForPodsReadyOrFail(ctx, meshNs.Name(), "sleep")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		templateParams := map[string]interface{}{
			"codecType":  proxyHTTPVersion,
			"tlsEnabled": proxyTLSEnabled,
			"protocol":   serviceEntryProtocol(proxyHTTPVersion, proxyTLSEnabled),
		}
		ctx.ConfigIstio().EvalFile(meshNs.Name(), templateParams, "forward-proxy/service-entry.tmpl.yaml").ApplyOrFail(ctx)
		ctx.ConfigIstio().EvalFile(meshNs.Name(), templateParams, "forward-proxy/destination-rule.tmpl.yaml").ApplyOrFail(ctx)
		common.ApplyFileOrFail(ctx, externalNs.Name(), "forward-proxy/ssl-certificate-configmap.yaml")
		common.ApplyFileOrFail(ctx, externalNs.Name(), "forward-proxy/ssl-private-key-configmap.yaml")
		ctx.ConfigIstio().EvalFile(externalNs.Name(), templateParams, "forward-proxy/configmap.tmpl.yaml").ApplyOrFail(ctx)
		common.ApplyFileOrFail(ctx, externalNs.Name(), "forward-proxy/deployment.yaml")
		waitForPodsReadyOrFail(ctx, externalNs.Name(), "external-forward-proxy")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		common.ApplyFileOrFail(ctx, meshNs.Name(), "external-app/service-entry.yaml")
		common.ApplyFileOrFail(ctx, externalNs.Name(), "external-app/ssl-certificate-configmap.yaml")
		common.ApplyFileOrFail(ctx, externalNs.Name(), "external-app/ssl-private-key-configmap.yaml")
		common.ApplyFileOrFail(ctx, externalNs.Name(), "external-app/configmap.yaml")
		common.ApplyFileOrFail(ctx, externalNs.Name(), "external-app/deployment.yaml")
		waitForPodsReadyOrFail(ctx, externalNs.Name(), "external-app")
	}()

	wg.Wait()
	makeExternalServicesResolvable(ctx, externalNs.Name(), meshNs.Name())

	for _, tc := range testCases() {
		for _, res := range tc.istioResourcesToApply {
			common.ApplyFileOrFail(ctx, meshNs.Name(), res)
		}

		for _, protocol := range tc.protocols {
			ctx.NewSubTest(fmt.Sprintf("%s/%s-request", tc.name, protocol)).Run(func(ctx framework.TestContext) {
				// requests will fail until istio-proxy gets the Envoy configuration from istiod, so retries are necessary
				retry.UntilSuccessOrFail(ctx, func() error {
					if err := executeRequestToExternalApp(ctx, meshNs.Name(), protocol, tc.name); err != nil {
						return err
					}
					externalForwardProxyIP := getPodIP(ctx, externalNs.Name(), "external-forward-proxy")
					if err := verifyThatRequestWasTunneled(ctx, externalNs.Name(), externalForwardProxyIP, protocol, tc.name); err != nil {
						return err
					}
					return nil
				}, retry.Timeout(10*time.Second), retry.Delay(1*time.Second))
			})
		}

		for _, res := range tc.istioResourcesToApply {
			common.DeleteFileOrFail(ctx, meshNs.Name(), res)
		}
	}
}

func executeRequestToExternalApp(ctx framework.TestContext, meshNs, protocol, testName string) error {
	kubeClient := ctx.Clusters().Default()
	sleepPodName := getPodName(ctx, meshNs, "sleep")

	testRequestCmd := fmt.Sprintf(
		// The command below performs a GET request and writes only HTTP status code to the output.
		// Flag --insecure must be passed, because self-signed certificates are used.
		"curl --insecure -s -o /dev/null -w '%%{http_code}' %s://external-app.testdomain:%d/test/%s",
		protocol, selectPort(protocol), testName)

	stdout, _, err := kubeClient.PodExec(sleepPodName, meshNs, "sleep", testRequestCmd)
	if err != nil {
		return fmt.Errorf("failed to execute command in %s pod: %v: %s", sleepPodName, err, stdout)
	}
	if stdout != "'200'" {
		return fmt.Errorf("test request failed: %s", stdout)
	}
	return nil
}

func verifyThatRequestWasTunneled(ctx framework.TestContext, externalNs, expectedSourceIP, expectedProtocol, expectedPath string) error {
	kubeClient := ctx.Clusters().Default()

	externalAppPodName := getPodName(ctx, externalNs, "external-app")
	getAccessLogCmd := "cat /var/log/nginx/access.log"
	stdout, _, err := kubeClient.PodExec(externalAppPodName, externalNs, "external-app", getAccessLogCmd)
	if err != nil {
		return fmt.Errorf("failed to get logs of external-app: %v", err)
	}

	expectedLog := fmt.Sprintf("%s - GET %s://external-app.testdomain:%d/test/%s - 200",
		expectedSourceIP, expectedProtocol, selectPort(expectedProtocol), expectedPath)
	if !strings.Contains(stdout, expectedLog) {
		return fmt.Errorf("failed to find expected log: %s; logs: %s", expectedLog, stdout)
	}
	return nil
}

// makeExternalServicesResolvable sets host aliases for external-app and external-forward-proxy in sleep
// and istio-egressgateway deployments. Without host aliases domains of external-app and external-forward-proxy
// would not be resolvable, because there are no Kubernetes services for them. Instead, Istio service entries are used.
// The reason for this approach is to simulate communication with mesh-external services.
func makeExternalServicesResolvable(ctx framework.TestContext, externalNs, meshNs string) {
	externalAppIP := getPodIP(ctx, externalNs, "external-app")
	// "127.0.0.1" is used as the IP address for external-forward-proxy.testdomain,
	// because external-forward-proxy will not need to resolve its own domain name
	// and setting its current IP address doesn't make sense, because it will change after this update
	updateHostAliasesInDeploymentOrFail(ctx, externalNs, "external-forward-proxy", externalAppIP, "127.0.0.1")
	externalForwardProxyIP := getPodIP(ctx, externalNs, "external-forward-proxy")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		updateHostAliasesInDeploymentOrFail(ctx, "istio-system", "istio-egressgateway", externalAppIP, externalForwardProxyIP)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		updateHostAliasesInDeploymentOrFail(ctx, meshNs, "sleep", externalAppIP, externalForwardProxyIP)
	}()

	wg.Wait()
}

func updateHostAliasesInDeploymentOrFail(ctx framework.TestContext, ns, name, externalAppIP, externalForwardProxyIP string) {
	kubeClient := ctx.Clusters().Default().Kube()

	scaleDeploymentOrFail(ctx, ns, name, 0)
	waitForPodsDeletedOrFail(ctx, ns, name)

	// updating a deployment may fail due to incorrect deployment version caused by preceding deployment update,
	// so it's necessary to retry the operation to make it reliable
	retry.UntilSuccessOrFail(ctx, func() error {
		deployment, err := kubeClient.AppsV1().Deployments(ns).Get(context.TODO(), name, v1.GetOptions{})
		if err != nil {
			ctx.Fatalf("failed to get deployment %s: %v", name, err)
		}
		deployment.Spec.Template.Spec.HostAliases = []corev1.HostAlias{
			{
				IP:        externalAppIP,
				Hostnames: []string{"external-app.testdomain"},
			},
			{
				IP:        externalForwardProxyIP,
				Hostnames: []string{"external-forward-proxy.testdomain"},
			},
		}

		_, err = kubeClient.AppsV1().Deployments(ns).Update(context.TODO(), deployment, v1.UpdateOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "the object has been modified") {
				return fmt.Errorf("failed to update deployment %s: %v", name, err)
			}
			ctx.Fatalf("failed to update deployment %s: %v", name, err)
		}
		return nil
	})

	scaleDeploymentOrFail(ctx, ns, name, 1)
	waitForPodsReadyOrFail(ctx, ns, name)
}

// scaling a deployment may fail due to incorrect deployment version caused by preceding deployment update,
// so it's necessary to retry the operation to make it reliable
func scaleDeploymentOrFail(ctx framework.TestContext, ns, name string, scale int32) {
	kubeClient := ctx.Clusters().Default().Kube()
	retry.UntilSuccessOrFail(ctx, func() error {
		s, err := kubeClient.AppsV1().Deployments(ns).GetScale(context.TODO(), name, v1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get scale of deployment %s: %v", name, err)
		}

		s.Spec.Replicas = scale
		_, err = kubeClient.AppsV1().Deployments(ns).UpdateScale(context.TODO(), name, s, v1.UpdateOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "the object has been modified") {
				return fmt.Errorf("failed to update scale of deployment %s: %v", name, err)
			}
			ctx.Fatalf("failed to update scale of deployment %s: %v", name, err)
		}
		return nil
	}, retry.Timeout(3*time.Second), retry.Delay(1*time.Second))
}

func selectPort(protocol string) int32 {
	if protocol == "http" {
		return 8080
	}
	return 443
}

func serviceEntryProtocol(httpVersion string, tlsEnabled bool) string {
	if httpVersion == http1 {
		if tlsEnabled {
			return "HTTPS"
		}
		return "HTTP"
	}
	return "HTTP2"
}

func getPodIP(ctx framework.TestContext, ns, selector string) string {
	return getPodStringProperty(ctx, ns, selector, func(pod corev1.Pod) string {
		return pod.Status.PodIP
	})
}

func getPodName(ctx framework.TestContext, ns, selector string) string {
	return getPodStringProperty(ctx, ns, selector, func(pod corev1.Pod) string {
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
	}, retry.Timeout(1*time.Minute), retry.Delay(1*time.Second))
}

func waitForPodsDeletedOrFail(ctx framework.TestContext, ns, appSelector string) {
	kubeClient := ctx.Clusters().Default()
	retry.UntilSuccessOrFail(ctx, func() error {
		pods, err := kubeClient.PodsForSelector(context.TODO(), ns, "app="+appSelector)
		if err != nil {
			return fmt.Errorf("failed to get pods for app=%s: %v", appSelector, err)
		}
		if len(pods.Items) > 0 {
			return fmt.Errorf("expected to get 0 pods for app=%s, got: %d", appSelector, len(pods.Items))
		}
		return nil
	}, retry.Timeout(30*time.Second))
}
