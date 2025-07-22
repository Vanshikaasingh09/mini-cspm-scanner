import streamlit as st
import json
import csv
import io
from datetime import datetime
from scanner import run_all_checks
from credentials import create_session

st.set_page_config(page_title="Mini CSPM Tool", layout="wide")
st.title("🔐 Mini AWS CSPM Scanner")

st.write("Enter your AWS credentials to begin scanning.")
aws_access_key = st.text_input("AWS Access Key", type="password")
aws_secret_key = st.text_input("AWS Secret Key", type="password")
aws_region = st.text_input("AWS Region", value="ap-south-1")

def convert_report_to_csv(report):
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Check Type", "Resource / Detail"])
    for section, findings in report.items():
        if findings:
            for item in findings:
                if isinstance(item, dict):
                    writer.writerow([section, json.dumps(item)])
                else:
                    writer.writerow([section, item])
        else:
            writer.writerow([section, "No issues found"])
    return output.getvalue()

if st.button("▶️ Run Security Scan"):
    if not all([aws_access_key, aws_secret_key, aws_region]):
        st.error("❌ Please provide all AWS credentials.")
    else:
        with st.spinner("Scanning..."):
            try:
                session = create_session(aws_access_key, aws_secret_key, aws_region)
                st.write(f"📍 Using region: `{session.region_name}`")
                results = run_all_checks(session)

                if not results:
                    st.error("❌ Scan failed or returned no results.")
                else:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    # HTML Report
                    with open("report.html", "w", encoding="utf-8") as f:
                        f.write(f"<html><head><title>CSPM Report</title></head><body>")
                        f.write(f"<h1>Mini CSPM Report – {timestamp}</h1>")
                        for section, findings in results.items():
                            f.write(f"<h2>{section}</h2><ul>")
                            for item in findings:
                                color = "red" if "❗" in str(item) or "⚠️" in str(item) else "green"
                                if isinstance(item, dict):
                                    formatted = "<br>".join(f"{k}: {v}" for k, v in item.items())
                                    f.write(f"<li style='color:{color}'>{formatted}</li>")
                                else:
                                    f.write(f"<li style='color:{color}'>{item}</li>")
                            f.write("</ul>")
                        f.write("</body></html>")

                    # CSV Report
                    csv_data = convert_report_to_csv(results)
                    with open("report.csv", "w", encoding="utf-8", newline='') as f:
                        f.write(csv_data)

                    # Show results in UI
                    st.success("✅ Scan complete!")
                    st.caption(f"Scan time: {timestamp}")
                    for section, findings in results.items():
                        st.subheader(section)

                        if section == "s3_bucket_audit" and findings:
                            st.markdown("📦 **All S3 Buckets with Access Info:**")
                            table_data = []
                            for item in findings:
                                if isinstance(item, dict):
                                    table_data.append({
                                        "Bucket": item.get("Bucket", "N/A"),
                                        "Public": item.get("Public", "Unknown"),
                                        "ACL": item.get("ACL", "None"),
                                        "Policy": item.get("Policy", "None")
                                    })
                            st.dataframe(table_data, use_container_width=True)
                        elif findings:
                            for f_item in findings:
                                if isinstance(f_item, dict):
                                    st.markdown("🔸 **Resource Details:**")
                                    for key, val in f_item.items():
                                        st.markdown(f"- **{key}**: `{val}`")
                                else:
                                    icon = "⚠️" if "⚠️" in f_item or "❗" in f_item else "✅"
                                    st.markdown(f"{icon} {f_item}")
                        else:
                            st.success(f"✅ No issues found in {section}")

                    # Downloads
                    st.download_button("⬇️ Download JSON Report", data=json.dumps(results, indent=2), file_name="report.json")
                    with open("report.html", "rb") as f:
                        st.download_button("⬇️ Download HTML Report", data=f, file_name="report.html", mime="text/html")
                    st.download_button("⬇️ Download CSV Report", data=csv_data, file_name="report.csv", mime="text/csv")

            except Exception as e:
                st.error(f"❌ Error during scan: {e}")
