users = {
    "forensic_lead": {
        "role": "forensic_analyst",
        "clearance": 4,
        "department": "Forensics",
        "active": True,
    },
    "compliance_off": {
        "role": "compliance_officer",
        "clearance": 3,
        "department": "Compliance",
        "active": True,
    },
    "trainee_sec": {
        "role": "trainee",
        "clearance": 1,
        "department": "Training",
        "active": True,
    },
    "vendor_tech": {
        "role": "vendor_support",
        "clearance": 2,
        "department": "Vendor",
        "active": True,
    },
    "archived_usr": {
        "role": "archived",
        "clearance": 1,
        "department": "Archive",
        "active": False,
    },
}
# (.)(.)
resources = [
    ("forensic_images", 4),
    ("compliance_reports", 3),
    ("training_videos", 1),
    ("vendor_tools", 2),
    ("evidence_locker", 4),
    ("certification_docs", 1),
    ("audit_findings", 3),
    ("chain_of_custody", 4),
    ("support_tickets", 2),
    ("learning_modules", 1),
]

security_levels = ("Basic", "Standard", "Protected", "Maximum")


blocked_users = {"archived_usr", "terminated_vendor", "security_breach"}


def check_access(username, resource_name, users, resources, blocked_users):

    if username not in users:
        return False, "Unknown user"

    user = users[username]

    if username in blocked_users:
        return False, "Blocked user"

    if not user["active"]:
        return False, "Inactive user"

    resource_level = None

    for name, level in resources:
        if name == resource_name:
            resource_level = level
            break

    if resource_level is None:
        return False, "Unknown resource"

    if user["clearance"] < resource_level:
        return False, "Insufficient clearance"

    return True, "Access granted"


print("=" * 50)
print("RESOURCES")
print("=" * 50)

for resource_name, level in resources:
    print(f"{resource_name:<25} -> {security_levels[level - 1]}")


print()
print("=" * 50)
print("ACCESS CHECKS")
print("=" * 50)

for username in users:
    for resource_name, _ in resources:
        allowed, reason = check_access(
            username,
            resource_name,
            users,
            resources,
            blocked_users,
        )

        if allowed:
            print(f"user={username:<18} resource={resource_name:<25} -> ALLOW")
        else:
            print(
                f"user={username:<18} resource={resource_name:<25} -> DENY ({reason})"
            )
