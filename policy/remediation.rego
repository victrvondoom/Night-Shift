# What Night Shift is allowed to do to the cluster, written down.
#
# Evaluated by OPA for every dry run and every execute. The backend sends
# {phase, action, params, approval, allowed_namespaces}; nothing here is
# decided by a language model.
package beacon.remediation

import rego.v1

allowed_actions := {
	"networkpolicy.restore_ingress",
	"networkpolicy.revoke_ingress",
	"deployment.restart",
	"deployment.rollback",
}

protected_namespaces := {"kube-system", "kube-public", "kube-node-lease", "beacon"}

# Evidence kinds that prove a human, not a model, authorised the change.
verified_evidence := {"typed_console", "typed_telegram", "contract"}

deny contains msg if {
	not input.action in allowed_actions
	msg := sprintf("action %q is not allowlisted", [input.action])
}

deny contains msg if {
	input.params.namespace in protected_namespaces
	msg := sprintf("namespace %q is protected", [input.params.namespace])
}

deny contains msg if {
	not input.params.namespace in input.allowed_namespaces
	msg := sprintf("namespace %q is not in REMEDIABLE_NAMESPACES", [input.params.namespace])
}

deny contains "an execute needs an approval record" if {
	input.phase == "execute"
	input.approval.kind != "approval"
}

deny contains "the approval was already used" if {
	input.phase == "execute"
	input.approval.used_at != null
}

deny contains msg if {
	input.phase == "execute"
	not input.approval.evidence in verified_evidence
	msg := sprintf("approval evidence %q is not verified human consent", [input.approval.evidence])
}

default allow := false

allow if count(deny) == 0

decision := {"allow": allow, "deny": deny}
