import json
import re

# Load the raw dataset
with open(r'c:\Users\ADMIN\Downloads\convertcsv.json', 'r', encoding='utf-8') as f:
    raw_data = json.load(f)

# Extract triggers
urgency_triggers = set()
financial_triggers = set()
suspicious_tlds = set()

# Process each row
for row in raw_data:
    # Skip the header row if present
    if row.get('B') == 'message_text':
        continue
        
    text = str(row.get('B', '')).lower()
    
    # Financial triggers (D = blackmail, or explicit mention of money)
    if row.get('D') == '1' or any(word in text for word in ['pay', 'money', 'transfer', 'amount', '₹', '$']):
        financial_triggers.add(text)
        
    # Urgency triggers (G = High risk or explicit urgency)
    if row.get('G') == 'High' or row.get('C') == '1' or 'urgent' in text or 'immediately' in text or 'now' in text:
        # Don't add simple greetings that were mistakenly flagged
        if len(text) > 15 and not text.startswith('hello'):
            urgency_triggers.add(text)
            
    # Phishing indicators (F = 1)
    if row.get('F') == '1':
        # Find URLs and extract TLDs or add the whole text as an urgency trigger
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        for url in urls:
            try:
                tld = "." + url.split('.')[-1].split('/')[0]
                if len(tld) > 2 and len(tld) < 6:
                    suspicious_tlds.add(tld)
            except:
                pass
        
        # Also add the text itself as an urgency trigger if it's a phishing message
        if len(text) > 10:
            urgency_triggers.add(text)

# Convert sets to lists
formatted_dataset = {
    "FINANCIAL_TRIGGERS": list(financial_triggers)[:100],  # Cap at 100 to avoid huge payloads
    "URGENCY_TRIGGERS": list(urgency_triggers)[:100],
    "SUSPICIOUS_TLDS": list(suspicious_tlds)
}

# Save the formatted dataset
output_path = r'c:\Users\ADMIN\Desktop\threatdectai\custom-training-dataset.json'
with open(output_path, 'w', encoding='utf-8') as f:
    json.dump(formatted_dataset, f, indent=2)

print(f"Dataset converted successfully! Found {len(formatted_dataset['FINANCIAL_TRIGGERS'])} financial triggers and {len(formatted_dataset['URGENCY_TRIGGERS'])} urgency triggers.")
print(f"Saved to: {output_path}")
