def calculate_cvss_score(base_score):
 
  if base_score >= 9.0:
    severity = "Critical"
  elif base_score >= 7.0:
    severity = "High"
  elif base_score >= 4.0:
    severity = "Medium"
  else:
    severity = "Low"
  return base_score, severity

value_mapping = {
  "network": 0.85,
  "adjacent": 0.62,
  "local": 0.55,
  "physical": 0.2,
  "low": 0.5,
  "medium": 1.0,
  "high": 1.5,
  "none": 0.0,
  "partial": 0.275,
  "complete": 0.66,
  "single": 1.0,
  "multiple": 1.5,
}


access_vector = input("Enter the access vector (Network/Adjacent/Local/Physical): ")
access_complexity = input("Enter the access complexity (Low/Medium/High): ")
authentication = input("Enter the authentication required (None/Single/Multiple): ")
confidentiality_impact = input("Enter the confidentiality impact (None/Partial/Complete): ")
integrity_impact = input("Enter the integrity impact (None/Partial/Complete): ")
availability_impact = input("Enter the availability impact (None/Partial/Complete): ")


access_vector_value = value_mapping[access_vector]
access_complexity_value = value_mapping[access_complexity]
authentication_value = value_mapping[authentication]
confidentiality_impact_value = value_mapping[confidentiality_impact]
integrity_impact_value = value_mapping[integrity_impact]
availability_impact_value = value_mapping[availability_impact]


base_score = 10 * (confidentiality_impact_value + integrity_impact_value + availability_impact_value) * access_complexity_value
base_score = base_score * access_vector_value * authentication_value


cvss_score, severity = calculate_cvss_score(base_score)

print(f"CVSS score: {cvss_score:.1f} ({severity})")
