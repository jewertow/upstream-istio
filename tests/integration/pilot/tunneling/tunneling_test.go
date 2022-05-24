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
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"istio.io/istio/pkg/test/env"
	"istio.io/istio/pkg/test/framework"
	"istio.io/istio/pkg/test/framework/components/istio"
	"istio.io/istio/pkg/test/framework/components/istioctl"
	"istio.io/istio/pkg/test/framework/components/namespace"
	"istio.io/istio/pkg/test/framework/resource"
	kubetest "istio.io/istio/pkg/test/kube"
	"istio.io/istio/pkg/test/util/retry"
	forward_proxy "istio.io/istio/tests/integration/pilot/tunneling/forward-proxy"
)

type tunnelingTestCase struct {
	// name must be unique, because it's used in the requested URL and then it's searched for in the access.log file,
	// so a duplicated name would make test false positive
	name string
	// requestsSpec specifies what types of requests to execute and what protocols are expected on the destination side;
	// requested and expected protocols are different when TLS is originating
	requestsSpec []testRequestSpec
}

type testRequestSpec struct {
	requestedProtocol string
	expectedProtocol  string
}

var forwardProxyConfigurations = []forward_proxy.ListenerSettings{
	{
		Port:        3128,
		HTTPVersion: http1,
		TLSEnabled:  false,
	},
	{
		Port:        4128,
		HTTPVersion: http1,
		TLSEnabled:  true,
	},
	{
		Port:        5128,
		HTTPVersion: http2,
		TLSEnabled:  false,
	},
	{
		Port:        6128,
		HTTPVersion: http2,
		TLSEnabled:  true,
	},
}

var basicRequestsSpec = []testRequestSpec{
	{
		requestedProtocol: "http",
		expectedProtocol:  "http",
	},
	{
		requestedProtocol: "https",
		expectedProtocol:  "https",
	},
}

var testCases = []tunnelingTestCase{
	{
		name:         "sidecar",
		requestsSpec: basicRequestsSpec,
	},
	{
		name:         "gateway/tcp",
		requestsSpec: basicRequestsSpec,
	},
	//{
	//	name:         "gateway/tls/istio-mutual",
	//	requestsSpec: basicRequestsSpec,
	//},
	{
		name: "gateway/tls/passthrough",
		requestsSpec: []testRequestSpec{
			{
				// TLS originating
				requestedProtocol: "http",
				expectedProtocol:  "https",
			},
			{
				requestedProtocol: "https",
				expectedProtocol:  "https",
			},
		},
	},
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

func TestTunnelingOutboundTraffic(t *testing.T) {
	framework.
		NewTest(t).
		Features("traffic.tunneling.http1_proxy.plain_text").
		Run(func(ctx framework.TestContext) {
			runTunnelingTests(t, ctx)
		})
}

func runTunnelingTests(t *testing.T, ctx framework.TestContext) {
	meshNs := namespace.NewOrFail(t, ctx, namespace.Config{Prefix: "mesh", Inject: true})
	externalNs := namespace.NewOrFail(t, ctx, namespace.Config{Prefix: "external", Inject: false})

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx.ConfigIstio().File(meshNs.Name(), path.Join(env.IstioSrc, "samples/sleep/sleep.yaml")).ApplyOrFail(ctx)
		waitForPodsReadyOrFail(ctx, meshNs.Name(), "sleep")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx.ConfigIstio().File(externalNs.Name(), "forward-proxy/ssl-certificate-configmap.yaml").ApplyOrFail(ctx)
		ctx.ConfigIstio().File(externalNs.Name(), "forward-proxy/ssl-private-key-configmap.yaml").ApplyOrFail(ctx)
		applyForwardProxyConfigMap(ctx, externalNs.Name())
		ctx.ConfigIstio().File(externalNs.Name(), "forward-proxy/deployment.yaml").ApplyOrFail(ctx)
		waitForPodsReadyOrFail(ctx, externalNs.Name(), "external-forward-proxy")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx.ConfigIstio().File(meshNs.Name(), "external-app/service-entry.yaml").ApplyOrFail(ctx)
		ctx.ConfigIstio().File(externalNs.Name(), "external-app/ssl-certificate-configmap.yaml").ApplyOrFail(ctx)
		ctx.ConfigIstio().File(externalNs.Name(), "external-app/ssl-private-key-configmap.yaml").ApplyOrFail(ctx)
		ctx.ConfigIstio().File(externalNs.Name(), "external-app/configmap.yaml").ApplyOrFail(ctx)
		ctx.ConfigIstio().File(externalNs.Name(), "external-app/deployment.yaml").ApplyOrFail(ctx)
		waitForPodsReadyOrFail(ctx, externalNs.Name(), "external-app")
	}()

	wg.Wait()
	makeExternalServicesResolvable(ctx, externalNs.Name(), meshNs.Name())
	externalForwardProxyIP := getPodIP(ctx, externalNs.Name(), "external-forward-proxy")

	for _, proxySettings := range forwardProxyConfigurations {
		templateParams := map[string]interface{}{
			"port":       proxySettings.Port,
			"protocol":   serviceEntryProtocol(proxySettings.HTTPVersion),
			"tlsEnabled": proxySettings.TLSEnabled,
		}
		ctx.ConfigIstio().EvalFile(meshNs.Name(), templateParams, "forward-proxy/service-entry.tmpl.yaml").ApplyOrFail(ctx)
		ctx.ConfigIstio().EvalFile(meshNs.Name(), templateParams, "forward-proxy/destination-rule.tmpl.yaml").ApplyOrFail(ctx)

		for _, tc := range testCases {
			for _, res := range listFilesInDirectory(ctx, tc.name) {
				ctx.ConfigIstio().EvalFile(meshNs.Name(), templateParams, res).ApplyOrFail(ctx)
			}

			for _, requestSpec := range tc.requestsSpec {
				testName := fmt.Sprintf("%s/%s/%s/%s-request", proxySettings.HTTPVersion, proxySettings.TLSEnabledStr(), tc.name, requestSpec.requestedProtocol)
				ctx.NewSubTest(testName).Run(func(ctx framework.TestContext) {
					// requests will fail until istio-proxy gets the Envoy configuration from istiod, so retries are necessary
					retry.UntilSuccessOrFail(ctx, func() error {
						if err := executeRequestToExternalApp(ctx, meshNs.Name(), requestSpec.requestedProtocol, tc.name); err != nil {
							return err
						}
						if err := verifyThatRequestWasTunneled(ctx, externalNs.Name(), externalForwardProxyIP, requestSpec.expectedProtocol, tc.name); err != nil {
							return err
						}
						return nil
					}, retry.Timeout(10*time.Second))
				})
			}

			for _, res := range listFilesInDirectory(ctx, tc.name) {
				ctx.ConfigIstio().EvalFile(meshNs.Name(), templateParams, res).DeleteOrFail(ctx)
			}

			// Make sure that configuration changes were pushed to istio-proxies.
			// Otherwise, test results could be false-positive,
			// because subsequent test cases could work thanks to previous configurations.
			waitUntilTunnelingConfigurationIsRemovedOrFail(ctx, meshNs.Name())
		}

		ctx.ConfigIstio().EvalFile(meshNs.Name(), templateParams, "forward-proxy/service-entry.tmpl.yaml").DeleteOrFail(ctx)
		ctx.ConfigIstio().EvalFile(meshNs.Name(), templateParams, "forward-proxy/destination-rule.tmpl.yaml").DeleteOrFail(ctx)
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
		deployment, err := kubeClient.AppsV1().Deployments(ns).Get(context.TODO(), name, metav1.GetOptions{})
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

		_, err = kubeClient.AppsV1().Deployments(ns).Update(context.TODO(), deployment, metav1.UpdateOptions{})
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
		s, err := kubeClient.AppsV1().Deployments(ns).GetScale(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("failed to get scale of deployment %s: %v", name, err)
		}

		s.Spec.Replicas = scale
		_, err = kubeClient.AppsV1().Deployments(ns).UpdateScale(context.TODO(), name, s, metav1.UpdateOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "the object has been modified") {
				return fmt.Errorf("failed to update scale of deployment %s: %v", name, err)
			}
			ctx.Fatalf("failed to update scale of deployment %s: %v", name, err)
		}
		return nil
	}, retry.Timeout(3*time.Second))
}

func listFilesInDirectory(ctx framework.TestContext, dir string) []string {
	files, err := os.ReadDir(dir)
	if err != nil {
		ctx.Fatalf("failed to read files in directory: %s", err)
	}
	filesList := make([]string, 0, len(files))
	for _, file := range files {
		filesList = append(filesList, fmt.Sprintf("%s/%s", dir, file.Name()))
	}
	return filesList
}

func selectPort(protocol string) int32 {
	if protocol == "http" {
		return 8080
	}
	return 443
}

func serviceEntryProtocol(httpVersion string) string {
	if httpVersion == http1 {
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
	}, retry.Timeout(1*time.Minute), retry.Delay(500*time.Millisecond))
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
	}, retry.Timeout(30*time.Second), retry.Delay(500*time.Millisecond))
}

func waitUntilTunnelingConfigurationIsRemovedOrFail(ctx framework.TestContext, meshNs string) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		waitForTunnelingRemovedOrFail(ctx, meshNs, "sleep")
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
	args := []string{"proxy-config", "listeners", fmt.Sprintf("deploy/%s.%s", app, ns), "-o", "json"}
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
