import os
import requests
import streamlit as st
from crewai import Agent, Task, Crew
from crewai.tools import tool

# Streamlit Page Config
st.set_page_config(page_title="AI SOC Analyst Agent", page_icon="🛡️", layout="centered")

st.title("🛡️ AI SOC Analyst SaaS Agent")
st.write("Scan suspicious IP addresses and generate automated threat intelligence reports using AI.")

# 1. Fetching API Keys from Streamlit Secrets Context
if "GROQ_API_KEY" in st.secrets and "VIRUSTOTAL_API_KEY" in st.secrets:
    GROQ_API_KEY = st.secrets["GROQ_API_KEY"]
    VIRUSTOTAL_API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
    # Setting environment variable for CrewAI internal processing
    os.environ["GROQ_API_KEY"] = GROQ_API_KEY
else:
    st.error("⚠️ Error: Missing API Keys! Please configure GROQ_API_KEY and VIRUSTOTAL_API_KEY in the Streamlit App Secrets settings.")
    st.stop()

# 2. VirusTotal Scanner Custom Tool definition
@tool("VirusTotal IP Scanner")
def scan_ip_tool(ip_address: str) -> str:
    """Scans suspicious IP addresses via VirusTotal API and returns threat analytics data."""
    url = f"https://virustotal.com{ip_address}"
    headers = {
        "accept": "application/json",
        "x-key": VIRUSTOTAL_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return f"VirusTotal Analytics for {ip_address} -> Harmless: {stats['harmless']}, Malicious: {stats['malicious']}, Suspicious: {stats['suspicious']}"
        else:
            return f"VirusTotal Error: IP address details not found or invalid API key configuration."
    except Exception as e:
        return f"An exception occurred during lookup: {str(e)}"

# User Input Interface
target_ip = st.text_input("Enter Suspicious IP Address:", placeholder="e.g., 185.220.101.5")

if st.button("🤖 Analyze with AI Agent"):
    if target_ip.strip() == "":
        st.warning("Please provide a valid IP address to initiate analysis.")
    else:
        with st.spinner("AI Agent is investigating threat data... Please wait a few seconds..."):
            try:
                # 3. AI Agent Architecture setup using Free Groq Model
                soc_agent = Agent(
                    role='Automated SOC Threat Analyst',
                    goal='Utilize scanning tools to extract threat intelligence and compile high-fidelity security reports.',
                    backstory='You are an elite, autonomous tier-3 SOC AI agent specialized in rapid incident response, malware classification, and infrastructure threat hunting.',
                    llm="groq/llama3-70b-8192",
                    tools=[scan_ip_tool],
                    verbose=True
                )

                # 4. Action Task Mapping
                analysis_task = Task(
                    description=f'Perform a deep investigation on the following suspicious IP address: "{target_ip}". Cross-verify with the scanning tool to determine malicious associations, risk level, and adversary context.',
                    expected_output='A comprehensive, professional corporate-ready Cyber Security Threat Report structured with Risk Level (High/Medium/Low), Threat Analysis Findings, and actionable Remediation/Mitigation Steps.',
                    agent=soc_agent
                )

                # 5. Execute Agent Crew orchestrations
                cyber_crew = Crew(agents=[soc_agent], tasks=[analysis_task])
                result = cyber_crew.kickoff()

                # Render output directly onto the Web Dashboard UI
                st.success("🎯 Threat Analysis Completed!")
                st.markdown("### 📝 AI Generated Security Incident Report")
                st.write(result)
                
            except Exception as e:
                st.error(f"Execution Error: Failed to complete automated pipeline reasoning. Details: {str(e)}")
