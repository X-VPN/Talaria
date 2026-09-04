// Copyright (C) 2026 LIGHTNINGLINK NETWORKS PTE. LTD.
// SPDX-License-Identifier: AGPL-3.0-only

package server

// allowPrivateTargetPolicy permits private destinations. The packet-path tests
// route to RFC 1918 fixtures, which the default reference policy now denies.
func allowPrivateTargetPolicy() TargetPolicy {
	policy, err := NewReferenceTargetPolicy(ReferenceTargetPolicyConfig{AllowPrivateTargets: true})
	if err != nil {
		panic(err)
	}
	return policy
}
