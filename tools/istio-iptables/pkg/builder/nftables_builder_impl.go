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
	"fmt"

	"istio.io/istio/pkg/util/sets"
	"istio.io/istio/tools/istio-iptables/pkg/config"
	"istio.io/istio/tools/istio-iptables/pkg/constants"
	"istio.io/istio/tools/istio-iptables/pkg/log"
)

type NftablesBuilder struct {
	rules Rules
	cfg   *config.Config
}

func NewNftablesBuilder(cfg *config.Config) *NftablesBuilder {
	if cfg == nil {
		cfg = &config.Config{}
	}
	return &NftablesBuilder{
		rules: Rules{
			rulesv4: []*Rule{},
			rulesv6: []*Rule{},
		},
		cfg: cfg,
	}
}

func (b *NftablesBuilder) BuildV4() [][]string {
	return buildNftRules(constants.NFTABLES, b.rules.rulesv4)
}

func (b *NftablesBuilder) BuildV6() [][]string {
	return [][]string{}
}

func (b *NftablesBuilder) AppendRuleV4(command log.Command, chain string, table string, params ...string) {
	b.appendInternal(&b.rules.rulesv4, command, chain, table, params...)
}

func (b *NftablesBuilder) appendInternal(nft *[]*Rule, command log.Command, chain string, table string, params ...string) {
	*nft = append(*nft, &Rule{
		chain:  chain,
		table:  table,
		params: params,
	})
}

func buildNftRules(command string, rules []*Rule) [][]string {
	output := make([][]string, 0)
	chainTableLookupSet := sets.New[string]()
	for _, r := range rules {
		chainTable := fmt.Sprintf("%s:%s", r.chain, r.table)
		// Create new chain if key: `chainTable` isn't present in map
		if !chainTableLookupSet.Contains(chainTable) {
			// Ignore chain creation for built-in chains for iptables
			if _, present := constants.BuiltInChainsMap[r.chain]; !present {
				cmd := []string{command, "add", "chain", "ip", r.table, r.chain}
				output = append(output, cmd)
				chainTableLookupSet.Insert(chainTable)
			}
		}
	}
	for _, r := range rules {
		cmd := append([]string{command, "add", "rule", "ip", r.table, r.chain}, r.params...)
		output = append(output, cmd)
	}
	return output
}
