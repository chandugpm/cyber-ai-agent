import os
import re
import requests
import streamlit as st
from crewai import Agent, Task, Crew, LLM
from crewai.tools import tool

# ---------------------------------------------------------------------------
# Workaround for CrewAI issue #5886 (github.com/crewAIInc/crewAI/issues/5886):
# CrewAI's agent executor tags every outbound message with an Anthropic-only
# prompt-cache marker ("cache_breakpoint"). Only the native Anthropic adapter
# strips it before sending; the LiteLLM path used for Groq does not, so Groq's
# strict schema validation rejects the request with:
#   GroqException - 'messages.0': property 'cache_breakpoint' is unsupported
# This no-ops the marker. It's safe to leave in even after upgrading to a
# CrewAI version that already fixes this internally.
# ---------------------------------------------------------------------------
try:
    import crewai.llms.cache as _crewai_cache
    _crewai_cache.mark_cache_breakpoint = lambda msg: msg
except (ImportError, AttributeError):
    pass

# --- Streamlit Page Configuration ---
st.set_page_config(page_title="AI SOC Analyst Agent", page_icon="🛡️", layout="centered")

st.title("🛡️ AI SOC Analyst SaaS Agent")
st.write("Scan suspicious IP addresses and generate automated threat intelligence reports using AI.")

# --- 1. Load API Keys ---
if "GROQ_API_KEY" in st.secrets and "VIRUSTOTAL_API_KEY" in st.secrets:
    GROQ_API_KEY = st.secrets["GROQ_API_KEY"]
    VIRUSTOTAL_API_KEY = st.secrets["VIRUSTOTAL_API_KEY"]

    os.environ["GROQ_API_KEY"] = GROQ_API_KEY
    os.environ["VIRUSTOTAL_API_KEY"] = VIRUSTOTAL_API_KEY
else:
    st.error("Error: API Keys not found in Streamlit Secrets.")
    st.stop()

# --- 2. Initialize LLM ---
# llama3-70b-8192 was decommissioned by Groq in Aug 2025. Its announced
# replacement, llama-3.3-70b-versatile, was itself deprecated for free/
# developer-tier usage on Aug 16, 2026 (console.groq.com/docs/deprecations).
# Current production, tool-calling-capable models on Groq: openai/gpt-oss-120b
# (higher quality) or openai/gpt-oss-20b (cheaper/faster). Verify against
# console.groq.com/docs/models before relying on this in production, since
# Groq's catalog changes on short notice.
my_llm = LLM(
    model="groq/openai/gpt-oss-120b",
    api_key=GROQ_API_KEY,
)

# --- 3. Define the VirusTotal Scanning Tool ---
@tool("VirusTotal IP Scanner")
def scan_ip_tool(ip_address: str) -> str:
    """
    Scans a suspicious IP address using the VirusTotal API v3.
    Returns a summary of harmless, malicious, and suspicious votes.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    ip_address = ip_address.strip()

    # Correct VirusTotal v3 endpoint: the original code built a malformed
    # URL ("https://virustotal.com{ip}") that never hit a real path.
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {
        "accept": "application/json",
        # VirusTotal v3 auth header is "x-apikey", not "x-key".
        "x-apikey": api_key,
    }
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return (
                f"VirusTotal Scan Results for {ip_address} -> "
                f"Malicious: {stats['malicious']}, "
                f"Suspicious: {stats['suspicious']}, "
                f"Harmless: {stats['harmless']}"
            )
        elif response.status_code == 404:
            return f"No VirusTotal record found for {ip_address}."
        elif response.status_code == 401:
            return "Error: VirusTotal API key was rejected (401 Unauthorized)."
        else:
            return f"Error: Could not fetch data. Status Code: {response.status_code} - {response.text[:200]}"
    except requests.exceptions.RequestException as e:
        return f"Exception during scan: {str(e)}"


def _looks_like_ip(value: str) -> bool:
    """Lightweight IPv4/IPv6 sanity check before spending an LLM call on bad input."""
    ipv4 = r"^(\d{1,3}\.){3}\d{1,3}$"
    ipv6 = r"^[0-9a-fA-F:]+$"
    return bool(re.match(ipv4, value)) or (":" in value and bool(re.match(ipv6, value)))


# --- 4. User Interface ---
target_ip = st.text_input("Enter Suspicious IP Address:", placeholder="e.g., 185.220.101.5")

if st.button("Analyze with AI Agent"):
    target_ip = target_ip.strip()
    if not target_ip:
        st.warning("Please enter a valid IP address.")
    elif not _looks_like_ip(target_ip):
        st.warning("That doesn't look like a valid IP address. Please check the format.")
    else:
        with st.spinner("AI Agent is investigating..."):
            try:
                # --- 5. Define Agent ---
                soc_analyst = Agent(
                    role="Senior SOC Threat Analyst",
                    goal="Analyze network threats and generate a comprehensive security report.",
                    backstory=(
                        "You are an expert Security Operations Center (SOC) analyst. "
                        "Your job is to investigate suspicious IPs using available tools "
                        "and provide a detailed incident response report."
                    ),
                    llm=my_llm,
                    tools=[scan_ip_tool],
                    verbose=True,
                    allow_delegation=False,
                    # Threat intel changes over time; always re-fetch a fresh
                    # scan rather than reusing a cached tool result.
                    cache=False,
                )

                # --- 6. Define Task ---
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
                    agent=soc_analyst,
                )

                # --- 7. Execute Crew ---
                crew = Crew(agents=[soc_analyst], tasks=[analysis_task])
                result = crew.kickoff()

                # --- 8. Display Results ---
                st.success("Analysis Completed!")
                st.markdown("### Security Incident Report")
                st.markdown(str(result))

            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
