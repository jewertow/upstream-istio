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

package builder

import (
	"reflect"
	"testing"

	"istio.io/istio/tools/istio-iptables/pkg/constants"
	iptableslog "istio.io/istio/tools/istio-iptables/pkg/log"
)

func TestAppendNftRulesV4(t *testing.T) {
	nftables := NewNftablesBuilder(nil)
	nftables.AppendRuleV4(iptableslog.UndefinedCommand, constants.PREROUTING, constants.NAT, "ip", "protocol", "tcp", "counter", "jump", constants.ISTIOINBOUND)
	nftables.AppendRuleV4(iptableslog.UndefinedCommand, constants.OUTPUT, constants.NAT, "ip", "protocol", "tcp", "counter", "jump", constants.ISTIOOUTPUT)
	nftables.AppendRuleV4(iptableslog.UndefinedCommand, constants.ISTIOINBOUND, constants.NAT, "tcp", "dport", "15008", "counter", "return")
	nftables.AppendRuleV4(iptableslog.UndefinedCommand, constants.ISTIOREDIRECT, constants.NAT, "ip", "protocol", "tcp", "counter", "redirect", "to", ":15001")

	if err := len(nftables.rules.rulesv6) != 0; err {
		t.Errorf("Expected rulesV6 to be empty; but got %#v", nftables.rules.rulesv6)
	}

	actual := nftables.BuildV4()
	expected := [][]string{
		{"nft", "add", "chain", "ip", constants.NAT, constants.ISTIOINBOUND},
		{"nft", "add", "chain", "ip", constants.NAT, constants.ISTIOREDIRECT},
		{"nft", "add", "rule", "ip", constants.NAT, constants.PREROUTING, "ip", "protocol", "tcp", "counter", "jump", constants.ISTIOINBOUND},
		{"nft", "add", "rule", "ip", constants.NAT, constants.OUTPUT, "ip", "protocol", "tcp", "counter", "jump", constants.ISTIOOUTPUT},
		{"nft", "add", "rule", "ip", constants.NAT, constants.ISTIOINBOUND, "tcp", "dport", "15008", "counter", "return"},
		{"nft", "add", "rule", "ip", constants.NAT, constants.ISTIOREDIRECT, "ip", "protocol", "tcp", "counter", "redirect", "to", ":15001"},
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("Actual and expected output mismatch; but instead got Actual: %#v ; Expected: %#v", actual, expected)
	}
	// V6 rules should be empty and return an empty slice
	actual = nftables.BuildV6()
	if !reflect.DeepEqual(actual, [][]string{}) {
		t.Errorf("Expected V6 rules to be empty; but instead got Actual: %#v", actual)
	}
}
