# 🚨 Incident Report: Create Alert Rule (Potential Impossible Travel) 🚨

![image (10)](https://github.com/user-attachments/assets/0549c26d-254c-424c-8d17-a24e4819b9f3)

## 📝 **Explanation**  
Corporations often have strict policies prohibiting:  
- 🌍 Logging in from multiple geographic regions outside designated areas.  
- 🔄 Account sharing (a standard security measure).  
- 🛡️ Using non-corporate VPNs.  

This scenario detects unusual activity, such as logins from **multiple geographic regions** within a short time frame.  

Whenever a user logs into Azure or authenticates with their main Azure account, logs are created in the **"SigninLogs"** table and forwarded to the **Log Analytics workspace** used by Microsoft Sentinel (our SIEM).  

### **Detection Objective:**  
Trigger an alert in Sentinel if a user logs into more than **one location** within a 7-day time period. Not all alerts will indicate malicious activity, as some may be false positives.  

---

## 🚦 **Creating the Alert Rule (Potential Impossible Travel)**  
**Objective:**  
Set up a Sentinel **Scheduled Query Rule** in Log Analytics to detect users logging into multiple geographic regions.  

### **Rule Configuration Details:**  
1. **Trigger Conditions:**  
   - A user logs into two or more distinct locations within 7 days.  

2. **KQL Query:**

```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
``` 
```kql
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationAllowed = 1;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize count() by UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationAllowed
```
![Screenshot 2025-05-01 at 04 25 00](https://github.com/user-attachments/assets/16e25d61-cc99-4a35-aa9e-6b23f022cc3e)


3. **Analytics Rule Settings:**  
   - **Name:** Potential Impossible Travel Alert  
   - **Description:** Detects logins from multiple geographic regions.  
   - ✅ Enable the Rule.  
   - 🔄 Run Query Every 4 Hours.  
   - 📅 Lookup Data for the Last 24 Hours.  
   - ❌ Stop Running Query After Alert is Generated.

![Screenshot 2025-05-01 at 03 03 05](https://github.com/user-attachments/assets/286ad915-76d2-4131-9912-826e28a0fa17)
![Screenshot 2025-05-01 at 03 19 19](https://github.com/user-attachments/assets/b19b6838-c828-4fb4-a283-3f30407c337d)
![Screenshot 2025-05-01 at 03 19 31](https://github.com/user-attachments/assets/7bbccad3-0c23-4f75-92e2-44ff5b66e61c)
![Screenshot 2025-05-01 at 03 28 00](https://github.com/user-attachments/assets/46e527c6-691b-4040-b8de-bd255bc6bbcd)
![Screenshot 2025-05-01 at 03 28 12](https://github.com/user-attachments/assets/8641fea9-3852-4678-8855-a619e6d4a6e4)
![Screenshot 2025-05-01 at 03 29 24](https://github.com/user-attachments/assets/b778f94e-1049-4a57-a78b-9d6e1c3d9d22)


4. **Entity Mappings:**  
   - **Account ID:** AadUserId → `UserId`  
   - **Display Name:** UserPrincipalName → `Value`  

---

## 🔍 **Detection and Analysis**  

1. **Steps to Validate Incident:**  
   - ✅ Assign the incident to yourself and set the status to **Active**.  
   - 🔄 Use **Investigate** to review entities (may take time).  
   - 📊 Examine output from the analytics rule to identify flagged accounts.

![Screenshot 2025-05-01 at 04 13 41](https://github.com/user-attachments/assets/b199265a-201e-4c87-b9a9-5529ded20f71)
![Screenshot 2025-05-01 at 04 14 34](https://github.com/user-attachments/assets/5506788d-7cc6-4842-89cf-687801489165)



2. **Account Analysis:**  
   **Example Query:**  
   ```kql
   // Investigate Potential Impossible Travel Instances
   let TargetUserPrincipalName = "username@domain.com"; // Change to your target user (UserPrincipalName)
   let TimePeriodThreshold = timespan(7d);
   SigninLogs
   | where TimeGenerated > ago(TimePeriodThreshold)
   | where UserPrincipalName == "username@domain.com"
   | project TimeGenerated, UserPrincipalName, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
   | order by TimeGenerated desc
   ```

![Screenshot 2025-05-01 at 04 35 32](https://github.com/user-attachments/assets/c6ee2d0b-c394-41cf-a149-c3c1aebf47b7)
![Screenshot 2025-05-01 at 04 38 52](https://github.com/user-attachments/assets/237f0ebf-a3b2-4bae-95d6-a068faaf72d1)


   **Observed Findings:**  
   - **Account 1:** Logins from 3 nearby locations within 4 days. No unusual behavior.  
   - **Account 2:** Logins from 4 locations within 7 days. All locations were within a 2-hour train ride.  

---

## 🛠️ **Containment, Eradication, and Recovery**  

- **Outcome:**  
   The alert was determined to be **Benign Positive**:  
   - Account activity aligned with expected behavior.  
   - Users logged into locations within reasonable proximity and timeframes.  

- **Next Steps:**  
   - 🔍 Pivot to analyze additional activity for these accounts using:  
     ```kql
     AzureActivity
     | where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "AzureADObjectID"
     ```  
   - **If suspicious behavior is detected**, disable the account and escalate.  

---

## 🔄 **Post-Incident Activities**  
1. **Policy Updates:**  
   - Implement a **geo-fencing policy** in Azure to restrict logins outside specific regions.  
2. **Documentation:**  
   - Record all findings and lessons learned in the incident management system.  

---

## ✅ **Closure**  
1. **Review Incident:**  
   - Confirm resolution and update notes.  
   - Mark the incident as a **Benign Positive** or **False Positive** (based on findings).  
2. **Finalize Report:**  
   - Submit the report and close the case in Sentinel.  

📌 **Status:** Closed as **Benign Positive**.  

---

**✨ Lessons Learned:**  
- Better geographic restrictions can enhance security.  
- Not all triggers are threats; careful analysis prevents unnecessary escalations.  

📈 **Always stay vigilant!** 🛡️
