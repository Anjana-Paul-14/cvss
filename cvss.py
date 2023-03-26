
import math

impact = input("enter the  impact (remote/local/physical)")
print(impact)
exploitability = input("enter the  exploitability (remote/local/physical)")
print(exploitability)
temporalscore = input("enter the  temporalscore ")
print(temporalscore)
environmentalscore = input(" enter the environmentalscore ")
print(environmentalscore)


score_mapping = {
  "remote": 10.0,
  "local": 7.5,
  "physical": 5.0
}


def cvss_score(impact, exploitability):
  return (0.6 * impact) + (0.4 * exploitability) - 1.5


def cvss_temporal_score(base_score, temporalscore):
  return base_score * temporalscore


def cvss_environmental_score(tempscore, environmentalscore):
  return tempscore * environmentalscore


def round_to_tenth(score):
  return round(score * 10) / 10


def calculate_cvss_score(impact, exploitability, temporalscore, environmentalscore):

  impact = score_mapping[impact]
  exploitability = score_mapping[exploitability]

  
  base_score = cvss_score(impact, exploitability)

  
  #tempscore = cvss_temporal_score(base_score, temporalscore)
  tempscore = score_mapping[impact]

 
  environmental_score = cvss_environmental_score(tempscore, environmentalscore)

  score = round_to_tenth(environmental_score)

# severity level
  if score >= 9.0:
    severity = "Critical"
  elif score >= 7.0:
    severity = "High"
  elif score >= 5.0:
    severity = "Medium"
  else:
    severity = "Low"

  
  return score, severity




print(calculate_cvss_score(impact, exploitability, temporalscore, environmentalscore))

