import os
import requests
import streamlit as st
from crewai import Agent, Task, Crew
from crewai.tools import tool

# --- Streamlit Page Configuration ---
st.set_page_config(page_title="AI SOC Analyst Agent", page_icon="🛡️", layout="centered")

st.title("🛡️ AI SOC Analyst SaaS Agent")
st.write("Scan suspicious IP addresses and generate automated threat intelligence reports using AI.")

# --- 1. Load API Keys ---
if "GROQ_API_KEY" in st.secrets and "VIRUSTOTAL_API_KEY" in st.secrets:
    GROQ_API_KEY = st.secrets["GROQ_API_KEY"]
    VIRUSTOTAL_API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]
    
    # Standard Environment Variables for CrewAI & Groq
    os.environ["GROQ_API_KEY"] = GROQ_API_KEY
    os.environ["VIRUSTOTAL_API_KEY"] = VIRUSTOTAL_API_KEY
else:
    st.error("⚠️ Error: Missing API Keys! Please configure GROQ_API_KEY and VIRUSTOTAL_API_KEY in Streamlit Secrets.")
    st.stop()

# --- 2. Define the VirusTotal Scanning Tool ---
@tool("VirusTotal IP Scanner")
def scan_ip_tool(ip_address: str) -> str:
    """
    Scans a suspicious IP address using the VirusTotal API.
    Returns a summary of harmless, malicious, and suspicious votes.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    url = f"https://virustotal.com{ip_address}"
    headers = {
        "accept": "application/json",
        "x-key": api_key
    }
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            return (f"VirusTotal Scan Results for {ip_address} -> "
                    f"Malicious: {stats['malicious']}, "
                    f"Suspicious: {stats['suspicious']}, "
                    f"Harmless: {stats['harmless']}")
        else:
            return f"Error: Could not fetch data. Status Code: {response.status_code}"
    except Exception as e:
        return f"Exception during scan: {str(e)}"

# --- 3. User Interface ---
target_ip = st.text_input("Enter Suspicious IP Address:", placeholder="e.g., 185.220.101.5")

if st.button("🤖 Analyze with AI Agent"):
    if not target_ip.strip():
        st.warning("Please enter a valid IP address.")
    else:
        with st.spinner("🕵️‍♂️ AI Agent is investigating..."):
            try:
                # --- 4. Define the AI Agent ---
                soc_analyst = Agent(
                    role='Senior SOC Threat Analyst',
                    goal='Analyze network threats and generate a comprehensive security report.',
                    backstory=(
                        "You are an expert Security Operations Center (SOC) analyst. "
                        "Your job is to investigate suspicious IPs using available tools "
                        "and provide a detailed incident response report."
                    ),
                    # Direct Groq String Method (Supported by updated litellm)
                    llm="groq/llama3-70b-8192",
                    
                    tools=[scan_ip_tool],
                    verbose=True,
                    allow_delegation=False,
                    
                    # ⚠️ Critical: Disable caching to avoid Groq unsupported param error
                    cache=False 
                )

                # --- 5. Define the Task ---
                analysis_task = Task(
                    description=(
                        f"Investigate the IP address '{target_ip}' using the VirusTotal Scanner tool. "
                        "Determine if it is malicious based on the scan results. "
                        "If it is malicious, explain the potential risks."
                    ),
                    expected_output=(
                        "A professional markdown report in English including:\n"
                        "1. Executive Summary\n"
                        "2. Threat Analysis (Malicious/Clean status)\n"
                        "3. Recommended Mitigation Steps"
                    ),
                    agent=soc_analyst
                )

                # --- 6. Execute the Crew ---
                crew = Crew(
                    agents=[soc_analyst],
                    tasks=[analysis_task]
                )
                
                result = crew.kickoff()

                # --- 7. Display Results ---
                st.success("✅ Analysis Completed!")
                st.markdown("### 📝 Security Incident Report")
                st.markdown(result)

            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
