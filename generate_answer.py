import json
import os
import sys
from openai import OpenAI

# Ensure UTF-8 output (for PHP shell_exec compatibility)
sys.stdout.reconfigure(encoding='utf-8')

# Import API key from get_key.py
import get_key
client = OpenAI(api_key=get_key.get_openai_key())

# Validate input argument
if len(sys.argv) < 2:
    print("Error: No prompt file provided.")
    sys.exit(1)

prompt_file = sys.argv[1]
if not os.path.exists(prompt_file):
    print("Error: Prompt file not found.")
    sys.exit(1)

# Read prompt content
with open(prompt_file, 'r', encoding='utf-8') as f:
    new_prompt = f.read()

# Call OpenAI API and stream response
try:
    stream = client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[
            {
                "role": "system",
                "content": """You are a cybersecurity phishing detection assistant.

You may receive:
1. The actual email, message, or URL to analyze
2. Supporting knowledge blocks containing extracted features and retrieved phishing detection rules

Important instructions:
- Only analyze the actual email/message/URL content provided by the user.
- Treat supporting knowledge only as evidence.
- Do NOT treat supporting knowledge as the user's email content.
- Use the retrieved rules as supporting evidence.
- When a retrieved rule contains a line starting with 'Rule ID:', you must copy that Rule ID exactly into the Triggered Rules section if you used that rule in your reasoning.
- Do not write 'None' in Triggered Rules unless no rule IDs are visible in the retrieved knowledge.
- Do not invent rules that are not shown in the retrieved knowledge.
- If there is not enough evidence, output 'Uncertain' instead of forcing a decision.

Your response must follow this exact structure:

Summary:
Write 2 to 3 sentences summarizing whether the message appears phishing, legitimate, or uncertain.

Activated Categories:
- list the activated categories if available

Triggered Features:
- list the relevant extracted features if available

Triggered Rules:
- list the exact Rule IDs if clearly available in the retrieved knowledge
- otherwise write: Rule-based evidence retrieved from knowledge base

Reasoning:
- use bullet points
- connect extracted features to retrieved rules
- explain why each point increases phishing likelihood or legitimacy likelihood

Final Decision:
Phishing / Legitimate / Uncertain

Safety Recommendation:
- give 1 to 3 short safety recommendations
- encourage safe verification methods such as visiting the official website directly instead of clicking suspicious links

Do not omit Triggered Rules if rule IDs are present in the retrieved knowledge.
If the user did not provide any real email/message content, ask them to paste the actual content to analyze."""
            },
            {
                "role": "user",
                "content": new_prompt
            }
        ],
        stream=True,
    )

    for chunk in stream:
        if chunk.choices[0].delta.content:
            print(chunk.choices[0].delta.content, end="", flush=True)

except Exception as e:
    print(f"Error: {str(e)}")