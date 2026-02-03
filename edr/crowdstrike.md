# CrowdStrike Falcon \- OpenClaw Detection

This guide provides a technical walkthrough for deploying the openclaw-detector across a mixed environment (Windows, macOS, and Linux) to gain full visibility into OpenClaw AI Agents running on your organization's endpoints, using CrowdStrike Falcon.

---

### **Prerequisites**

Before starting, verify the following configuration to ensure the scripts can execute:

* **RTR Policy:** The Response Policy assigned to your target hosts must have **Custom Scripts** toggled **ON**. If this is disabled, the workflow will trigger, but the script execution will be blocked at the endpoint level.  
* **Permissions:** You must have **RTR Administrator** or **Active Responder** roles to upload scripts and **Falcon Fusion** permissions to manage workflows.

---

### **1\. Script Preparation**

You must first host the detection scripts within the Falcon console:

1. Navigate to **Configuration \> Real Time Response \> Response Scripts and Files**.  
2. **Upload the Windows Script:**  
   * **File:** openclaw-detector.ps1.  
   * **Platform:** Windows.  
   * **Permission:** Set to "Global" or "Workflow".  
3. **Upload the Unix Script:**  
   * **File:** openclaw-detector.sh.  
   * **Platform:** Select both **Linux** and **Mac**.  
   * **Permission:** Set to "Global" or "Workflow".

---

### **2\. Configure the Fusion Workflow**

The workflow acts as a central "traffic cop," routing the correct script to each endpoint based on its operating system.

1. **Create Workflow:** Navigate to **Workflow \> Workflows** and select **Create New Workflow**.  
2. **Trigger:** Choose **Scheduled** (to scan the fleet periodically) or **On-Demand** (for manual execution). Define your scope using a "Host Group" or by targeting all active sensors.  
3. **Branching Logic (Condition):** Add a condition to split the execution path:  
   * **Branch A (Windows):** Set condition to Host Platform **EQUALS** Windows.  
   * **Branch B (Unix-like):** Set condition to Host Platform **IN** Mac, Linux.  
4. **Action:** Under each branch, add a **Real Time Response \> Run script** action:  
   * **Windows Branch:** Select your uploaded openclaw-detector.ps1.  
   * **Mac/Linux Branch:** Select your uploaded openclaw-detector.sh.

---

### **3\. Viewing the Results**

#### **Option A: The Activity Dashboard (Individual Host Detail)**

To see a live view of the deployment and drill down into specific detections:

1. Navigate to **Workflow \> Activity**.  
2. Select your specific workflow execution.  
3. The dashboard will show a list of all targeted hosts. Click on any host to view the **Action Details**.  
4. Review the **Action Output** (stdout) to see exactly where OpenClaw was found (e.g., CLI path, Docker container, or listening port).

#### **Option B: Advanced Reporting (Fleet-Wide Visibility)**

To aggregate data from thousands of endpoints into a single view, use these queries in **Advanced Event Search**:

**Summary of Compliance Status:**

Identifies which hosts are clean and which have active or inactive agents.

```
#event_simpleName=RtrLineOut
| LineDataByLine=/summary: (?<Status>installed-(and-running|not-running|error)|not-installed)/
| table aid, ComputerName, Status

```

**AI Agent Port Distribution:**

Useful for finding if agents are running on non-standard ports.

```
#event_simpleName=RtrLineOut
| LineDataByLine=/gateway-port: (?<Port>\d+)/
| stats count() by Port
| sort -count

```

---

### **4\. How to Read the Results**

The scripts standardize their output into a "Summary" line. Here is what each status represents for your organization:

| Result Summary | Description | Exposure Level |
| :---- | :---- | :---- |
| **summary: not-installed** | No OpenClaw binaries, config files, or containers found. | **None (Compliant)** |
| **summary: installed-not-running** | OpenClaw files or registry keys exist, but the agent is not currently active. | **Low (Dormant)** |
| **summary: installed-and-running** | An active OpenClaw process, service, or container is currently running. | **High (Active Agent)** |
| **summary: error** | The script failed to complete the scan (often due to permissions). | **Unknown** |

