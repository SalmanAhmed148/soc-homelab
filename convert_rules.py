import os
import glob
import re

# Simple architecture bridge to turn Sigma YAML keys into Wazuh XML fields
def yml_to_xml(file_path):
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Extract structural metadata fields from the Sigma YAML rule
    title_match = re.search(r'^title:\s*(.*)$', content, re.M)
    desc_match = re.search(r'^description:\s*(.*)$', content, re.M)
    id_match = re.search(r'^id:\s*(.*)$', content, re.M)
    
    title = title_match.group(1).strip().strip('"\'') if title_match else "Custom Sigma Rule"
    description = desc_match.group(1).strip().strip('"\'') if desc_match else "Converted from Sigma layout"
    rule_id = "100200" # Base fallback custom rule ID for local configurations
    
    # Simple extraction block for standard key-value process fields
    xml_fields = []
    lines = content.split('\n')
    for line in lines:
        if ':' in line and not line.strip().startswith(('#', 'title', 'description', 'id', 'status', 'level', 'author', 'logsource')):
            parts = line.split(':', 1)
            key = parts[0].strip().replace('-', '').strip()
            val = parts[1].strip().strip('"\'[]')
            if val and not val.startswith(('selection', 'condition')):
                # Normalize common Windows/Linux system tracking variables to generic targets
                if "image" in key.lower():
                    xml_fields.append(f'<field name="win.eventdata.Image">.*{val}</field>')
                elif "commandline" in key.lower():
                    xml_fields.append(f'<field name="win.eventdata.CommandLine">.*{val}</field>')
                else:
                    xml_fields.append(f'<field name="full_log">.*{val}</field>')

    fields_block = "\n        ".join(xml_fields) if xml_fields else '<field name="full_log">.*</field>'
    
    # Construct a valid, production-ready Wazuh rule block structure
    wazuh_xml = f"""<group name="sigma_converted,custom">
    <rule id="{rule_id}" level="7">
        <description>{title} - {description}</description>
        {fields_block}
    </rule>
</group>
"""
    return wazuh_xml

# Batch sweep through your local directories
output_dir = "wazuh/custom-rules/"
os.makedirs(output_dir, exist_ok=True)

rule_files = glob.glob("sigma/windows/*.yml") + glob.glob("sigma/linux/*.yml")
print(f"Discovered {len(rule_files)} rules to convert across subdirectories.")

for f_path in rule_files:
    try:
        xml_data = yml_to_xml(f_path)
        base_name = os.path.splitext(os.path.basename(f_path))[0]
        out_path = os.path.join(output_dir, f"{base_name}.xml")
        with open(out_path, 'w') as out_f:
            out_f.write(xml_data)
        print(f"Successfully processed and output: {base_name}.xml")
    except Exception as e:
        print(f"Skipping rule file {f_path} due to parsing error: {e}")