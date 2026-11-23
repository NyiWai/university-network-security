
from adapters.linux.firewall import (
    generate_ruleset,
    validate_ruleset
)

# Use a test interface name and private test subnet.
rules = generate_ruleset(
    interface="test-ap0",
    network="192.168.50.0/24"
)

print("Generated firewall rules:")
print(rules)

print("\nValidating ruleset...")

result = validate_ruleset(rules)

if result["valid"]:
    print("SUCCESS: Firewall ruleset syntax is valid.")
else:
    print("FAILED:")
    print(result["stderr"])
