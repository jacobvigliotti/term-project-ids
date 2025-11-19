from utils.config import load_config

# Load rules once when module is imported
config = load_config()
FILTERING_RULES = config.get("filtering_rules", [])

# Keep track of stats
stats = {
    "allowed": 0,
    "blocked": 0
}

def get_stats():
    """Return current allow/block counts."""
    return stats.copy()

def reset_stats():
    """Reset counters to zero."""
    stats["allowed"] = 0
    stats["blocked"] = 0

def check_packet(features):
    """
    Check a packet against our filtering rules.
    
    Returns a tuple: (action, rule_description)
    - action is either "allow" or "block"
    - rule_description explains why (or "default" if no rule matched)
    """
    # Go through each rule in order
    # First matching rule wins
    for rule in FILTERING_RULES:
        if matches_rule(features, rule):
            action = rule.get("action", "block")
            description = rule.get("description", "No description")
            
            # Update our counters
            if action == "block":
                stats["blocked"] += 1
            else:
                stats["allowed"] += 1
                
            return (action, description)
    
    # No rule matched, default to allow
    # You might want to change this depending on your security needs
    stats["allowed"] += 1
    return ("allow", "default policy")

def matches_rule(features, rule):
    """
    Check if a packet's features match a single rule.
    
    A rule matches if ALL specified conditions are true.
    Conditions not in the rule are ignored (treated as wildcards).
    """
    # Check source IP
    if "src_ip" in rule:
        if features["src_ip"] != rule["src_ip"]:
            return False
    
    # Check destination IP
    if "dst_ip" in rule:
        if features["dst_ip"] != rule["dst_ip"]:
            return False
    
    # Check source port
    if "src_port" in rule:
        if features["src_port"] != rule["src_port"]:
            return False
    
    # Check destination port
    if "dst_port" in rule:
        if features["dst_port"] != rule["dst_port"]:
            return False
    
    # Check protocol
    if "protocol" in rule:
        if features["protocol"] != rule["protocol"].lower():
            return False
    
    # All conditions passed (or rule had no conditions)
    return True