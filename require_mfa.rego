package main

# 1. Flag if MFA is explicitly disabled (false)
deny[message] {
    some i
    user := input.users[i]
    user.role == "Administrator"
    user.mfa_enabled == false
    message := sprintf("Admin user '%s' has MFA explicitly disabled (false).", [user.username])
}

# 2. Flag if MFA is misconfigured as 'null'
deny[message] {
    some i
    user := input.users[i]
    user.role == "Administrator"
    user.mfa_enabled == null
    message := sprintf("Admin user '%s' has an invalid 'null' value for MFA.", [user.username])
}

# 3. Flag if the MFA key is completely missing
deny[message] {
    some i
    user := input.users[i]
    user.role == "Administrator"
    
    # object.get looks for the key. If it doesn't exist, it returns the fallback value ("missing")
    mfa_status := object.get(user, "mfa_enabled", "missing")
    mfa_status == "missing"
    
    message := sprintf("Admin user '%s' is completely missing the mfa_enabled field.", [user.username])
}
