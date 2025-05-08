# Security in Internet-of-Things: Security implications, Mobile device security - threats and strategies

import random
import time

# ==========================
# IoT Security Simulation
# ==========================

# Simulate common IoT device vulnerabilities
class IoTSecurity:
    def __init__(self, device_name):
        self.device_name = device_name
        self.security_level = random.choice(["low", "medium", "high"])

    def simulate_attack(self):
        """Simulate various attacks on IoT devices"""
        attack_type = random.choice(["DDOS", "Data interception", "Botnet infection", "Ransomware"])
        print(f"Simulating attack on {self.device_name} with {attack_type}...")
        time.sleep(2)

        if self.security_level == "low":
            print(f"Attack on {self.device_name} was successful due to low security!")
        elif self.security_level == "medium":
            print(f"Attack on {self.device_name} was partially successful, but mitigated.")
        else:
            print(f"Attack on {self.device_name} was thwarted due to high security!")

    def strengthen_security(self):
        """Simulate improving security of the IoT device"""
        print(f"Strengthening security of {self.device_name}...")
        self.security_level = "high"
        print(f"Security level of {self.device_name} is now {self.security_level}.")

    def demonstrate_security_threats(self):
        """Simulate the types of threats faced by IoT devices"""
        print(f"Security Threats for {self.device_name}:")
        print("1. DDoS attacks - Devices can be overwhelmed with traffic.")
        print("2. Data interception - Data can be captured in unencrypted channels.")
        print("3. Botnet attacks - Devices can be hijacked for malicious activities.")
        print("4. Ransomware - Devices can be held hostage until ransom is paid.")

# ==========================
# Mobile Device Security Simulation
# ==========================

class MobileSecurity:
    def __init__(self, device_name):
        self.device_name = device_name
        self.security_level = random.choice(["low", "medium", "high"])

    def simulate_mobile_attack(self):
        """Simulate a mobile device security attack"""
        attack_type = random.choice(["Malware", "Phishing", "Man-in-the-Middle", "App Vulnerability"])
        print(f"Simulating attack on {self.device_name} with {attack_type}...")
        time.sleep(2)

        if self.security_level == "low":
            print(f"Attack on {self.device_name} was successful due to low security!")
        elif self.security_level == "medium":
            print(f"Attack on {self.device_name} was partially successful, but mitigated.")
        else:
            print(f"Attack on {self.device_name} was thwarted due to high security!")

    def strengthen_mobile_security(self):
        """Simulate improving security of the mobile device"""
        print(f"Strengthening security of {self.device_name}...")
        self.security_level = "high"
        print(f"Security level of {self.device_name} is now {self.security_level}.")

    def demonstrate_mobile_security_threats(self):
        """Simulate the types of threats faced by mobile devices"""
        print(f"Security Threats for {self.device_name}:")
        print("1. Malware - Malicious apps or files that can steal data or damage the device.")
        print("2. Phishing - Fake emails or SMS messages that trick users into revealing credentials.")
        print("3. Man-in-the-Middle (MITM) Attacks - Attacker intercepts data between two devices.")
        print("4. App Vulnerabilities - Exploiting bugs in mobile apps to access sensitive data.")

# ==========================
# Example Simulation: IoT & Mobile Device Security
# ==========================

if __name__ == "__main__":
    # Example 1: Simulate IoT Security
    print("\n### IoT Security Simulation ###\n")
    iot_device = IoTSecurity("Smart Thermostat")
    iot_device.demonstrate_security_threats()
    iot_device.simulate_attack()

    print("\nStrengthening IoT Device Security...\n")
    iot_device.strengthen_security()
    iot_device.simulate_attack()

    # Example 2: Simulate Mobile Device Security
    print("\n### Mobile Device Security Simulation ###\n")
    mobile_device = MobileSecurity("Smartphone")
    mobile_device.demonstrate_mobile_security_threats()
    mobile_device.simulate_mobile_attack()

    print("\nStrengthening Mobile Device Security...\n")
    mobile_device.strengthen_mobile_security()
    mobile_device.simulate_mobile_attack()

