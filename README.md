# Brightwave-Security-SQL-Investigation

# 🛡️ Brightwave Logistics: Insider Risk, Data Access & Phishing Response Investigation

> An end-to-end MySQL investigation of employee data access, privilege misuse, phishing exposure, and incident response performance, turning five raw tables into a prioritised list of risks for a security team to review.

![MySQL](https://img.shields.io/badge/MySQL-8.0+-blue) ![Domain](https://img.shields.io/badge/Domain-Security%20Analytics-darkgreen) ![Focus](https://img.shields.io/badge/Focus-Insider%20Risk%20%7C%20Phishing%20%7C%20Incident%20Response-orange)

---

## 📌 Project Overview

Brightwave Logistics needs to understand where its data, people, and processes are most exposed. Using SQL alone, I cleaned and validated the data, profiled access behaviour, tested employee activity against clearance levels, measured phishing susceptibility, benchmarked incident response against SLAs, and built reusable reporting objects (a view and a scoring model).

**Data model (5 tables)**

| Table | Contents |
|---|---|
| `employees` | Department, job role, hire/termination date, clearance level (1-4), employment status |
| `systems` | System name, data classification (Public / Internal / Confidential / Restricted), owner department |
| `access_logs` | Employee, system, timestamp, action type, records accessed, result (Granted/Denied), location |
| `email_security_events` | Email category, sender domain, subject theme, user action, received/action timestamps |
| `incidents` | Incident type, severity, status, linked employee/system, reported/closed timestamps |

---

## 🎯 Objectives

- Validate data quality before drawing any conclusions.
- Profile how systems and sensitive data are accessed, and when.
- Identify privilege and insider-risk indicators (above-clearance access, post-termination activity, unusual data movement).
- Measure phishing and malware exposure by department, sender, and subject theme.
- Evaluate incident response speed against severity-based SLAs.
- Build reusable, management-ready outputs.

---

## ❓ Key Business Questions

| Area | Question |
|---|---|
| **Data quality** | Are there duplicates, NULLs, invalid clearance levels, broken references, or impossible timestamps? |
| **Data access** | Which systems and employees move the most records? How much activity happens out of hours? |
| **Privilege risk** | Who accessed systems above their clearance, and was it granted? Is there activity after termination? |
| **Phishing** | What share of emails are malicious, who interacts with them, and who reports them? |
| **Incident response** | Which incidents remain open, how long do they take to close, and which breach their SLA? |
| **Prioritisation** | Which employees, systems, and processes should be reviewed first? |

---

## 🛠️ SQL Techniques & Concepts Demonstrated

| Category | Techniques Used |
|---|---|
| **Data quality checks** | Duplicate detection (`GROUP BY … HAVING COUNT(*) > 1`), NULL audits, `DISTINCT` value inspection, orphan-record checks via `LEFT JOIN … IS NULL`, logical timestamp validation |
| **Aggregation** | `COUNT`, `SUM`, `AVG`, `MIN`, `MAX`, `ROUND`, `GROUP BY`, `HAVING` |
| **Joins & set logic** | `INNER`, `LEFT`, `CROSS JOIN`, `UNION ALL` |
| **Conditional logic** | `CASE WHEN` for ratings, SLA thresholds, clearance mapping, and pivoted metrics; `COALESCE`, `NULLIF` |
| **CTEs & subqueries** | Multi-step CTEs, scalar subqueries for percentage-of-total calculations, correlated subqueries |
| **Window functions** | `LAG()`, `DENSE_RANK() OVER (PARTITION BY …)`, running totals with `SUM() OVER (ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)` |
| **Date & time analysis** | `TIMESTAMPDIFF`, `DAYOFWEEK`, `TIME`, `DATE`, `YEARWEEK` |
| **Reusable objects** | `CREATE VIEW vw_employee_security_summary` |
| **Risk modelling** | Weighted employee risk score and rule-based flagging |

---

## 🧭 Analytical Approach & Business Rules

These rules are defined directly in the queries:

| Rule | Definition |
|---|---|
| Business hours | Mon-Fri, 08:00-17:59; everything else counts as out-of-hours |
| Above-clearance access | Data classification level (Public=1, Internal=2, Confidential=3, Restricted=4) greater than the employee's clearance level |
| High-risk data movement | Granted Download/Export of **≥ 100 records** from Confidential or Restricted systems |
| Volume anomaly | Granted download/export **> 2× the employee's own average** |
| Malicious email | Category is Phishing or Malware; *interaction* = Clicked Link or Opened Attachment |
| Incident SLA | Critical 24h · High 72h · Medium 120h · Low 240h (open incidents measured to 2026-08-31) |
| Employee risk score (0-100) | 40% above-clearance granted access + 30% malicious-email interaction + 30% Critical/High incident involvement |

---

## 📊 Analysis & Results

> Each table mirrors the output of the named query in the project script. Totals rows are included where the metric is additive.

### A. Data Profile & Quality

**A1: Records per table**

| Table | Total Records |
|---|---|
| employees | `__` |
| systems | `__` |
| access_logs | `__` |
| email_security_events | `__` |
| incidents | `__` |
| **Total** | **`__`** |

| Access log coverage | Value |
|---|---|
| First access | `__` |
| Last access | `__` |

**Data-quality checks (A2-A6)**

| Check | Rows Flagged |
|---|---|
| Duplicate access-log rows | `__` |
| Missing values (access / employees / systems / emails / incidents) | `__` |
| Negative `records_accessed` | `__` |
| Invalid clearance levels | `__` |
| Orphan employee/system references | `__` |
| Illogical timestamps (action before receipt, closed before reported, terminated before hired) | `__` |

### B. Data Access Activity

**B1: Access result**

| Result | Events | % |
|---|---|---|
| Granted | `__` | `__` |
| Denied | `__` | `__` |
| **Total** | **`__`** | **100%** |

**B3: Activity by action type**

| Action Type | Events | % |
|---|---|---|
| `__` | `__` | `__` |
| **Total** | **`__`** | **100%** |

**B4a: Records moved (granted Download/Export) by system**

| System | Total Records Moved |
|---|---|
| `__` | `__` |
| **Total** | **`__`** |

**B5a: Out-of-hours activity**

| Total Access Events | Out-of-Hours Events | Out-of-Hours % |
|---|---|---|
| `__` | `__` | `__` |

### C. Privilege & Insider Risk

| Indicator | Count |
|---|---|
| Above-clearance attempts: Granted (C1/C2) | `__` |
| Above-clearance attempts: Denied (C1) | `__` |
| Activity after termination date (C4) | `__` |
| Download/export > 2× employee average (C5) | `__` |
| High-risk data movement ≥ 100 records (C6) | `__` |
| Granted access to Confidential/Restricted systems owned by another department (B7) | `__` |

### D. Phishing & Email Security

**D1a: Emails by category**

| Category | Emails | % |
|---|---|---|
| `__` | `__` | `__` |
| **Total** | **`__`** | **100%** |

**D2a: Overall malicious-email interaction**

| Total Malicious Emails | Interacted (Click/Open) | Interaction Rate |
|---|---|---|
| `__` | `__` | `__%` |

**D2b / D3: By department**

| Department | Malicious Emails | Interactions | Interaction Rate | Reported | Report Rate |
|---|---|---|---|---|---|
| `__` | `__` | `__` | `__%` | `__` | `__%` |
| **Total** | **`__`** | **`__`** | **`__%`** | **`__`** | **`__%`** |

**D6: Response speed**

| Response Type | Emails | Avg Minutes to Action | Fastest | Slowest |
|---|---|---|---|---|
| Reported | `__` | `__` | `__` | `__` |
| Clicked or opened | `__` | `__` | `__` | `__` |

### E. Incident Response

**E1 / E6b: Incidents**

| Severity | Total Incidents |
|---|---|
| Critical | `__` |
| High | `__` |
| Medium | `__` |
| Low | `__` |
| **Total** | **`__`** |

| Status | Incidents |
|---|---|
| Open | `__` |
| In Progress | `__` |
| Closed | `__` |
| **Total** | **`__`** |

**E3: Resolution time of closed incidents**

| Severity | Closed Incidents | Avg Hours to Close | Fastest | Slowest |
|---|---|---|---|---|
| Critical | `__` | `__` | `__` | `__` |
| High | `__` | `__` | `__` | `__` |
| Medium | `__` | `__` | `__` | `__` |
| Low | `__` | `__` | `__` | `__` |

**E4: SLA breaches**

| Severity | SLA (hrs) | Incidents Breaching SLA |
|---|---|---|
| Critical | 24 | `__` |
| High | 72 | `__` |
| Medium | 120 | `__` |
| Low | 240 | `__` |
| **Total** | | **`__`** |

### F. Advanced Analysis

**F5: Employee risk score distribution**

| Risk Score | Employees |
|---|---|
| 100 | `__` |
| 70 | `__` |
| 60 | `__` |
| 40 | `__` |
| 30 | `__` |
| 0 | `__` |
| **Total** | **`__`** |

---

## 🔎 Key Insights Generated

- **Layered risk view:** Access, email, and incident data were combined into one weighted employee score and a reusable summary view (`vw_employee_security_summary`), so reviewers can start from the highest-risk people rather than scanning raw logs.
- **Privilege gaps surfaced:** A clearance-mapping rule converts classification labels into comparable levels, exposing both *attempted* and *granted* above-clearance access.
- **Offboarding control test:** Activity timestamped after an employee's termination date is isolated, covering both granted and denied events.
- **Data-exfiltration signals:** Two complementary rules (≥ 100 records from sensitive systems, and > 2× personal average) flag unusual downloads and exports, plus a running total of exported records over time.
- **Human-factor exposure:** Phishing interaction and report rates by department, sender domain, and subject theme show who is vulnerable and which lures work.
- **Response performance:** Severity-based SLA logic highlights which incidents were slow to close or are still open past their window.
- **Weekly trend monitoring:** Week-over-week comparison of access volume and records moved supports ongoing monitoring.
- **Responsible framing:** Risk outputs are written as prioritisation aids for human review, not proof of misconduct.

---

## 🧩 Selected Query: Employee Risk Score

```sql
SELECT e.employee_id, e.employee_name, e.department,
       ai.above_clearance_granted, ei.malicious_email_interaction,
       ii.critical_high_incident,
       (40 * ai.above_clearance_granted
        + 30 * ei.malicious_email_interaction
        + 30 * ii.critical_high_incident) AS risk_score
FROM employees e
JOIN access_indicator   ai ON ai.employee_id = e.employee_id
JOIN email_indicator    ei ON ei.employee_id = e.employee_id
JOIN incident_indicator ii ON ii.employee_id = e.employee_id
ORDER BY risk_score DESC, e.department, e.employee_name;
```

*(Each indicator is built in its own CTE with `MAX(CASE WHEN …)`; see the full script.)*

---

## 📁 Repository Contents

```
├── Brightwave_Logistics_All_SQL_Queries.sql   # Sections A-F: quality, access, privilege, phishing, incidents, advanced
└── README.md
```

## ▶️ How to Run

1. Load the five tables into a MySQL 8.0+ database.
2. Run `A4` first to confirm the exact label values (`Granted`, `Phishing`, `Clicked Link`, etc.).
3. Run each section individually and review the output.

---

## 💡 Skills Showcased

`SQL` · `MySQL 8.0` · `Window Functions` · `CTEs` · `Data Validation` · `Risk Scoring` · `SLA Analysis` · `Insider-Risk Analytics` · `Phishing Analysis` · `Business Insight Reporting`
