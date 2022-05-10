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

package common

import "istio.io/istio/pkg/test/framework"

// ApplyFileOrFail applies the given yaml file and deletes it during context cleanup
func ApplyFileOrFail(t framework.TestContext, ns, filename string) {
	t.Helper()
	if err := t.Clusters().Default().ApplyYAMLFiles(ns, filename); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		t.Clusters().Default().DeleteYAMLFiles(ns, filename)
	})
}

// DeleteFileOrFail deletes resource from the given yaml file
func DeleteFileOrFail(t framework.TestContext, ns, filename string) {
	if err := t.Clusters().Default().DeleteYAMLFiles(ns, filename); err != nil {
		t.Fatal(err)
	}
}
