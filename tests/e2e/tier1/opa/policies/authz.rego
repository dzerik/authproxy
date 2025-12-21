# Authorization Policy for E2E Testing
# Package: authz
package authz

import rego.v1

# Default deny
default allow := false

# Allow if any permission rule matches
allow if {
    some rule in data.authz.rules
    rule_matches(rule, input)
}

# Check if a rule matches the input
rule_matches(rule, inp) if {
    # Path matching
    path_matches(rule, inp.path)

    # Method matching (if specified)
    method_matches(rule, inp.method)

    # Role matching (if specified)
    role_matches(rule, inp.token)
}

# Path matching helpers
path_matches(rule, path) if {
    rule.path_prefix
    startswith(path, rule.path_prefix)
}

path_matches(rule, path) if {
    rule.path_exact
    path == rule.path_exact
}

path_matches(rule, path) if {
    rule.path_regex
    regex.match(rule.path_regex, path)
}

path_matches(rule, _) if {
    not rule.path_prefix
    not rule.path_exact
    not rule.path_regex
}

# Method matching helpers
method_matches(rule, method) if {
    rule.methods
    method in rule.methods
}

method_matches(rule, _) if {
    not rule.methods
}

# Role matching helpers
role_matches(rule, token) if {
    rule.required_roles
    some role in rule.required_roles
    has_role(token, role)
}

role_matches(rule, _) if {
    not rule.required_roles
}

# Check if token has a specific role
has_role(token, role) if {
    token.realm_access.roles
    role in token.realm_access.roles
}

has_role(token, role) if {
    token.roles
    role in token.roles
}

# Additional decision details for debugging
decision := {
    "allow": allow,
    "path": input.path,
    "method": input.method,
    "matched_rules": matched_rules,
    "user": get_user(input.token),
    "roles": get_roles(input.token),
}

matched_rules := [rule.name |
    some rule in data.authz.rules
    rule_matches(rule, input)
]

get_user(token) := token.preferred_username if {
    token.preferred_username
} else := token.sub if {
    token.sub
} else := "anonymous"

get_roles(token) := token.realm_access.roles if {
    token.realm_access.roles
} else := token.roles if {
    token.roles
} else := []

# Token exchange validation (RFC 8693)
token_exchange_allowed if {
    input.grant_type == "urn:ietf:params:oauth:grant-type:token-exchange"
    valid_subject_token
    valid_target_audience
}

valid_subject_token if {
    input.subject_token
    # Add additional validation as needed
}

valid_target_audience if {
    input.audience in data.authz.allowed_audiences
}

# Agent delegation chain validation
delegation_allowed if {
    input.act
    check_delegation_depth(input.act)
}

# Check delegation depth without recursion
check_delegation_depth(act) if {
    not act.act
}

check_delegation_depth(act) if {
    act.act
    not act.act.act
}

check_delegation_depth(act) if {
    act.act.act
    not act.act.act.act
}

# Rate limiting decision (informational)
rate_limit_tier := "high" if {
    has_role(input.token, "admin")
} else := "medium" if {
    has_role(input.token, "service")
} else := "low"
