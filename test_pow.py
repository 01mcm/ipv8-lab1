from pow import mine, is_valid_pow

email = "m.c.montalvo@student.tudelft.nl"
github_url = "https://github.com/01mcm/ipv8-lab1.git"

nonce = mine(email, github_url)

print("Nonce:", nonce)
print("Valid:", is_valid_pow(email, github_url, nonce))